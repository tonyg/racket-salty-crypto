#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2012-2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require ffi/unsafe)
(require "ffi-lib.rkt")

(provide crypto_onetimeauth_BYTES
         crypto_onetimeauth_KEYBYTES
         crypto_onetimeauth_PRIMITIVE

	 crypto-onetimeauth
	 crypto-onetimeauth-verify
         )

(define-libsodium crypto_onetimeauth_bytes (_fun -> _size))
(define crypto_onetimeauth_BYTES (crypto_onetimeauth_bytes))

(define-libsodium crypto_onetimeauth_keybytes (_fun -> _size))
(define crypto_onetimeauth_KEYBYTES (crypto_onetimeauth_keybytes))

(define-libsodium crypto_onetimeauth_primitive (_fun -> _string))
(define crypto_onetimeauth_PRIMITIVE (crypto_onetimeauth_primitive))

(define-libsodium crypto_onetimeauth (_fun _bytes _bytes _ullong _bytes -> _int))

(define (crypto-onetimeauth msg key)
  (define a (make-bytes crypto_onetimeauth_BYTES))
  (check-length 'crypto-onetimeauth "key" key crypto_onetimeauth_KEYBYTES)
  (check-result (crypto_onetimeauth a msg (bytes-length msg) key))
  a)

(define-libsodium crypto_onetimeauth_verify (_fun _bytes _bytes _ullong _bytes -> _int))

(define (crypto-onetimeauth-verify authenticator msg key)
  (check-length 'crypto-onetimeauth-verify "key" key crypto_onetimeauth_KEYBYTES)
  (and (= (bytes-length authenticator) crypto_onetimeauth_BYTES)
       (zero? (crypto_onetimeauth_verify authenticator msg (bytes-length msg) key))))
