#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide make-hkdf)

(require racket/match)

(define (make-hkdf HMAC-HASH)
  (lambda (chaining-key input-key-material num-outputs)
    (define temp-key (HMAC-HASH chaining-key input-key-material))
    (define output1 (HMAC-HASH temp-key (bytes 1)))
    (define output2 (HMAC-HASH temp-key (bytes-append output1 (bytes 2))))
    (match num-outputs
      [2 (list output1 output2)]
      [3 (list output1 output2 (HMAC-HASH temp-key (bytes-append output2 (bytes 3))))])))
