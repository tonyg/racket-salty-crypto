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
          (printf "Running ~a\n" protocol_name)
          (define (run-test)
            (define init-prologue (hex-string->bytes (hash-ref test-case 'init_prologue)))
            (define resp-prologue (hex-string->bytes (hash-ref test-case 'resp_prologue)))
            #t)
          (if (hash-ref test-case 'fail #f)
              (check-equal? (list protocol_name 'expected-failure)
                            (list protocol_name
                                  (with-handlers [((lambda (e) #t)
                                                   (lambda (e)
                                                     (printf "Error, as expected: ~a" (exn->string e))
                                                     'expected-failure))]
                                    (run-test)
                                    'unexpected-success)))
              (run-test)))))
  )
