#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2012-2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require ffi/unsafe)
(require "ffi-lib.rkt")

(provide crypto_scalarmult_BYTES
         crypto_scalarmult_SCALARBYTES
         crypto_scalarmult_PRIMITIVE

         crypto-scalarmult-base
         crypto-scalarmult
         )

(define-libsodium crypto_scalarmult_bytes (_fun -> _size))
(define crypto_scalarmult_BYTES (crypto_scalarmult_bytes))

(define-libsodium crypto_scalarmult_scalarbytes (_fun -> _size))
(define crypto_scalarmult_SCALARBYTES (crypto_scalarmult_scalarbytes))

(define-libsodium crypto_scalarmult_primitive (_fun -> _string))
(define crypto_scalarmult_PRIMITIVE (crypto_scalarmult_primitive))

(define-libsodium crypto_scalarmult_base (_fun _bytes _bytes -> _int))

;; n is sk; crypto_scalarmult_SCALARBYTES == crypto_box_SECRETKEYBYTES.
(define (crypto-scalarmult-base n)
  (check-length 'crypto-scalarmult-base "n" n crypto_scalarmult_SCALARBYTES)
  (define q (make-bytes crypto_scalarmult_BYTES))
  (check-result (crypto_scalarmult_base q n))
  q)

(define-libsodium crypto_scalarmult (_fun _bytes _bytes _bytes -> _int))

(define (crypto-scalarmult n p)
  (check-length 'crypto-scalarmult "n" n crypto_scalarmult_SCALARBYTES)
  (check-length 'crypto-scalarmult "p" p crypto_scalarmult_BYTES)
  (define q (make-bytes crypto_scalarmult_BYTES))
  (check-result (crypto_scalarmult q n p))
  q)
