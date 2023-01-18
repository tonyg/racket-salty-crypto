#lang racket
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(module+ test
  (require file/sha1)
  (require json)
  (require noise)
  (require racket/exn)
  (require racket/runtime-path)
  (require rackunit)
  (require libsodium)

  (file-stream-buffer-mode (current-output-port) 'none) ;; TEMPORARY

  (define-runtime-path noise-c-basic-path "noise-c-basic.txt")

  (define noise-c-basic
    (hash-ref (with-input-from-file noise-c-basic-path read-json) 'vectors))

  (for [(test-case noise-c-basic)]
    (define protocol_name (hash-ref test-case 'protocol_name (lambda () (hash-ref test-case 'name))))
    (define pattern-name (string->symbol (hash-ref test-case 'pattern)))
    (define pattern (match pattern-name
                      ['NN NN]
                      ['NK NK]
                      ['IK IK]
                      ['XK XK]
                      ['XX XX]
                      ['IX IX]
                      [_ #f]))
    (if (or (hash-ref test-case 'fallback #f)
            (hash-has-key? test-case 'hybrid)
            (not (equal? (hash-ref test-case 'dh) "25519"))
            (not (equal? (hash-ref test-case 'cipher) "ChaChaPoly"))
            (not (equal? (hash-ref test-case 'hash) "BLAKE2s"))
            (not pattern)
            (string-prefix? protocol_name "NoisePSK_")
            )
        (let ()
          ;; (printf "Skipping ~a\n" protocol_name)
          (void))
        (let ()
          (define (! f a . args) (and a (apply f a args)))
          (define (get c k) (! hex-string->bytes (! hash-ref c k #f)))
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
            (define init-psk (get test-case 'init_psk))
            (define resp-psk (get test-case 'resp_psk))
            (define I (make-initiator pattern
                                      #:prologue (or init-prologue #"")
                                      #:static-keypair init-static
                                      #:remote-static-pk init-remote-static-pk
                                      #:pregenerated-ephemeral-keypair init-ephemeral
                                      #:preshared-keys (and init-psk (list init-psk))))
            (define R (make-responder pattern
                                      #:prologue (or resp-prologue #"")
                                      #:static-keypair resp-static
                                      #:remote-static-pk resp-remote-static-pk
                                      #:pregenerated-ephemeral-keypair resp-ephemeral
                                      #:preshared-keys (and resp-psk (list resp-psk))))
            (let loop ((messages (hash-ref test-case 'messages))
                       (sender I)
                       (receiver R)
                       (sender-is-initiator? #t))
              (match messages
                ['() 'done]
                [(cons m more-messages)
                 (define payload (get m 'payload))
                 (define expected-ciphertext (get m 'ciphertext))
                 (printf " - ~v\n" payload)
                 (define-values (actual-ciphertext sender-css) (WriteMessage sender payload))
                 (check-equal? (bytes->hex-string actual-ciphertext)
                               (bytes->hex-string expected-ciphertext))
                 (define-values (remote-payload receiver-css) (ReadMessage receiver expected-ciphertext))
                 (check-equal? remote-payload payload)
                 (check-equal? sender-css receiver-css)
                 (cond
                   [(not sender-css)
                    (loop more-messages receiver sender (not sender-is-initiator?))]
                   [else
                    (let loop ((messages more-messages)
                               (sender-css (if sender-is-initiator? (reverse sender-css) sender-css))
                               (receiver-css (if sender-is-initiator? receiver-css (reverse receiver-css))))
                      (match messages
                        ['() 'done]
                        [(cons m more-messages)
                         (define payload (get m 'payload))
                         (define expected-ciphertext (get m 'ciphertext))
                         (printf " = ~v\n" payload)
                         (define actual-ciphertext (EncryptWithAd (car sender-css) #"" payload))
                         (check-equal? actual-ciphertext expected-ciphertext)
                         (define remote-payload (DecryptWithAd (cadr receiver-css) #"" expected-ciphertext))
                         (check-equal? remote-payload payload)
                         (loop more-messages receiver-css sender-css)]))])])))
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
