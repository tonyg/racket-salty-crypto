#lang racket
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(module+ test
  (require file/sha1)
  (require json)
  (require noise-protocol)
  (require racket/exn)
  (require racket/runtime-path)
  (require rackunit)
  (require libsodium)

  (file-stream-buffer-mode (current-output-port) 'none)

  (define-runtime-path noise-c-basic-path "noise-c-basic.txt")
  (define-runtime-path snow-path "snow.txt")

  (define all-test-cases
    (append
     (hash-ref (with-input-from-file noise-c-basic-path read-json) 'vectors)
     (hash-ref (with-input-from-file snow-path read-json) 'vectors)))

  (for [(test-case all-test-cases)]
    (define protocol_name (hash-ref test-case 'protocol_name (lambda () (hash-ref test-case 'name))))
    (define pattern
      (match protocol_name
        [(pregexp #px"^Noise_([^_]+)_25519_ChaChaPoly_BLAKE2s$" (list _ pattern-name-str))
         ;; In old-style tests, protocol_name is missing, but name is present; and name
         ;; sometimes starts with NoisePSK_ in which case it is an old-style PSK test. We skip
         ;; these.
         ;; (define is-old-style-psk? (string-prefix? protocol_name "NoisePSK_"))
         (lookup-handshake-pattern pattern-name-str)]
        [_ #f]))
    (if (or (hash-ref test-case 'fallback #f)
            (hash-has-key? test-case 'hybrid)
            (not pattern))
        (let ()
          ;; (printf "Skipping ~a\n" protocol_name)
          (void))
        (let ()
          (define oneway? (handshake-pattern-one-way? pattern))
          (define (! f a . args) (and a (apply f a args)))
          (define (get c k) (! hex-string->bytes (! hash-ref c k #f)))
          (define (many-psks c k) (match (hash-ref c k '()) ['() #f] [hs (map hex-string->bytes hs)]))
          (printf "Running ~a ~v\n" protocol_name pattern)
          (define (run-test)
            (define init-prologue (get test-case 'init_prologue))
            (define resp-prologue (get test-case 'resp_prologue))
            (define init-ephemeral (! sk->crypto-box-keypair (get test-case 'init_ephemeral)))
            (define resp-ephemeral (! sk->crypto-box-keypair (get test-case 'resp_ephemeral)))
            (define init-static (! sk->crypto-box-keypair (get test-case 'init_static)))
            (define resp-static (! sk->crypto-box-keypair (get test-case 'resp_static)))
            (define init-remote-static-pk (get test-case 'init_remote_static))
            (define resp-remote-static-pk (get test-case 'resp_remote_static))
            (define init-psks (or (! list (get test-case 'init_psk)) (many-psks test-case 'init_psks)))
            (define resp-psks (or (! list (get test-case 'resp_psk)) (many-psks test-case 'resp_psks)))
            (define I (make-noise-protocol pattern
                                           #:role 'initiator
                                           #:prologue (or init-prologue #"")
                                           #:static-keypair init-static
                                           #:remote-static-pk init-remote-static-pk
                                           #:pregenerated-ephemeral-keypair init-ephemeral
                                           #:preshared-keys init-psks))
            (define R (make-noise-protocol pattern
                                           #:role 'responder
                                           #:prologue (or resp-prologue #"")
                                           #:static-keypair resp-static
                                           #:remote-static-pk resp-remote-static-pk
                                           #:pregenerated-ephemeral-keypair resp-ephemeral
                                           #:preshared-keys resp-psks))
            (let loop ((messages (hash-ref test-case 'messages))
                       (sender I)
                       (receiver R))
              (match messages
                ['() 'done]
                [(cons m more-messages)
                 (define payload (get m 'payload))
                 (define expected-ciphertext (get m 'ciphertext))
                 (printf " - ~v\n" payload)
                 (define-values (actual-ciphertext sender-css) (sender 'write-message payload))
                 (check-equal? (bytes->hex-string actual-ciphertext)
                               (bytes->hex-string expected-ciphertext))
                 (define-values (remote-payload receiver-css) (receiver 'read-message expected-ciphertext))
                 (check-equal? remote-payload payload)
                 (if (eq? sender-css #f)
                     (check-false receiver-css)
                     (let ((expose (lambda (cs) (list (cs 'key) (cs 'nonce)))))
                       (check-equal? (map expose sender-css) (map expose (reverse receiver-css)))))
                 (cond
                   [(not sender-css)
                    (loop more-messages receiver sender)]
                   [else
                    (let loop ((messages more-messages)
                               (sender-css (if oneway? sender-css receiver-css))
                               (receiver-css (if oneway? receiver-css sender-css)))
                      (match messages
                        ['() 'done]
                        [(cons m more-messages)
                         (define payload (get m 'payload))
                         (define expected-ciphertext (get m 'ciphertext))
                         (printf " = ~v\n" payload)
                         (define actual-ciphertext ((car sender-css) 'encrypt #"" payload))
                         (check-equal? actual-ciphertext expected-ciphertext)
                         (define remote-payload ((cadr receiver-css) 'decrypt #"" expected-ciphertext))
                         (check-equal? remote-payload payload)
                         (if oneway?
                             (loop more-messages sender-css receiver-css)
                             (loop more-messages receiver-css sender-css))]))])])))
          (if (hash-ref test-case 'fail #f)
              (check-equal? (list protocol_name 'expected-failure)
                            (list protocol_name
                                  (with-handlers [((lambda (e) #t)
                                                   (lambda (e)
                                                     (printf "Error, as expected: ~a\n" (exn->string e))
                                                     'expected-failure))]
                                    (run-test)
                                    'unexpected-success)))
              (run-test)))))
  )
