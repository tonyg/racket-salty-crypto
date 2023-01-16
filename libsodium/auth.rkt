#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2012-2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require ffi/unsafe)
(require "ffi-lib.rkt")

(provide crypto_auth_BYTES
         crypto_auth_KEYBYTES
         crypto_auth_PRIMITIVE

	 crypto-auth
	 crypto-auth-verify
         )

(define-libsodium crypto_auth_bytes (_fun -> _size))
(define crypto_auth_BYTES (crypto_auth_bytes))

(define-libsodium crypto_auth_keybytes (_fun -> _size))
(define crypto_auth_KEYBYTES (crypto_auth_keybytes))

(define-libsodium crypto_auth_primitive (_fun -> _string))
(define crypto_auth_PRIMITIVE (crypto_auth_primitive))

(define-libsodium crypto_auth (_fun _bytes _bytes _ullong _bytes -> _int))

(define (crypto-auth msg key)
  (define a (make-bytes crypto_auth_BYTES))
  (check-length 'crypto-auth "key" key crypto_auth_KEYBYTES)
  (check-result (crypto_auth a msg (bytes-length msg) key))
  a)

(define-libsodium crypto_auth_verify (_fun _bytes _bytes _ullong _bytes -> _int))

(define (crypto-auth-verify authenticator msg key)
  (check-length 'crypto-auth-verify "key" key crypto_auth_KEYBYTES)
  (and (= (bytes-length authenticator) crypto_auth_BYTES)
       (zero? (crypto_auth_verify authenticator msg (bytes-length msg) key))))
