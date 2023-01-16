#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2012-2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require ffi/unsafe)
(require "ffi-lib.rkt")
(require "hash.rkt")

(provide crypto_sign_BYTES
         crypto_sign_SEEDBYTES
         crypto_sign_PUBLICKEYBYTES
         crypto_sign_SECRETKEYBYTES
         crypto_sign_MESSAGEBYTES_MAX
         crypto_sign_PRIMITIVE

	 (struct-out crypto-sign-keypair)
	 make-crypto-sign-keypair
         seed->crypto-sign-keypair
         bytes->crypto-sign-keypair
	 crypto-sign
	 crypto-sign-open
         )

(define-libsodium crypto_sign_bytes (_fun -> _size))
(define crypto_sign_BYTES (crypto_sign_bytes))

(define-libsodium crypto_sign_seedbytes (_fun -> _size))
(define crypto_sign_SEEDBYTES (crypto_sign_seedbytes))

(define-libsodium crypto_sign_publickeybytes (_fun -> _size))
(define crypto_sign_PUBLICKEYBYTES (crypto_sign_publickeybytes))

(define-libsodium crypto_sign_secretkeybytes (_fun -> _size))
(define crypto_sign_SECRETKEYBYTES (crypto_sign_secretkeybytes))

(define-libsodium crypto_sign_messagebytes_max (_fun -> _size))
(define crypto_sign_MESSAGEBYTES_MAX (crypto_sign_messagebytes_max))

(define-libsodium crypto_sign_primitive (_fun -> _string))
(define crypto_sign_PRIMITIVE (crypto_sign_primitive))

(struct crypto-sign-keypair (pk sk) #:prefab)

(define-libsodium crypto_sign_keypair (_fun _bytes _bytes -> _int))

(define (make-crypto-sign-keypair)
  (define pk (make-bytes crypto_sign_PUBLICKEYBYTES))
  (define sk (make-bytes crypto_sign_SECRETKEYBYTES))
  (check-result (crypto_sign_keypair pk sk))
  (crypto-sign-keypair pk sk))

(define-libsodium crypto_sign_seed_keypair (_fun _bytes _bytes _bytes -> _int))

(define (seed->crypto-sign-keypair seed)
  (define pk (make-bytes crypto_sign_PUBLICKEYBYTES))
  (define sk (make-bytes crypto_sign_SECRETKEYBYTES))
  (check-length 'seed->crypto-sign-keypair "seed" seed crypto_sign_SEEDBYTES)
  (check-result (crypto_sign_seed_keypair pk sk seed))
  (crypto-sign-keypair pk sk))

(define (bytes->crypto-sign-keypair bs)
  (define seed (subbytes (crypto-hash bs) 0 crypto_sign_SEEDBYTES))
  (seed->crypto-sign-keypair seed))

(define-libsodium crypto_sign
  (_fun _bytes (smlen : (_ptr o _ullong)) _bytes _ullong _bytes -> (status : _int)
	-> (values status smlen)))

(define (crypto-sign msg sk)
  (define sm (make-bytes (+ (bytes-length msg) crypto_sign_BYTES)))
  (check-length 'crypto-sign "sk" sk crypto_sign_SECRETKEYBYTES)
  (define-values (status smlen) (crypto_sign sm msg (bytes-length msg) sk))
  (when (not (zero? status)) (raise (exn:fail:contract:libsodium
				     "crypto-sign: error from libsodium primitive"
				     (current-continuation-marks))))
  (subbytes sm 0 smlen))

(define-libsodium crypto_sign_open
  (_fun _bytes (mlen : (_ptr o _ullong)) _bytes _ullong _bytes -> (status : _int)
	-> (values status mlen)))

(define (crypto-sign-open signed-msg pk)
  (define m (make-bytes (bytes-length signed-msg)))
  (check-length 'crypto-sign "pk" pk crypto_sign_PUBLICKEYBYTES)
  (define-values (status mlen) (crypto_sign_open m signed-msg (bytes-length signed-msg) pk))
  (when (not (zero? status)) (raise (exn:fail:contract:libsodium
				     "crypto-sign-open: error from libsodium primitive"
				     (current-continuation-marks))))
  (subbytes m 0 mlen))
