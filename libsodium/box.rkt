#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2012-2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require ffi/unsafe)
(require "ffi-lib.rkt")
(require "random.rkt")
(require "hash.rkt")

(provide crypto_box_SEEDBYTES
         crypto_box_PUBLICKEYBYTES
         crypto_box_SECRETKEYBYTES
         crypto_box_NONCEBYTES
         crypto_box_MACBYTES
         crypto_box_MESSAGEBYTES_MAX
         crypto_box_PRIMITIVE
         crypto_box_BEFORENMBYTES

         (struct-out crypto-box-keypair)
	 make-crypto-box-keypair
         seed->crypto-box-keypair
         bytes->crypto-box-keypair
         crypto-scalarmult-base
	 crypto-box-random-nonce
	 crypto-box
	 crypto-box-open

	 (struct-out crypto-box-state)
	 crypto-box-precompute
	 crypto-box*
	 crypto-box-open*
         )

(struct crypto-box-keypair (pk sk) #:prefab)
(struct crypto-box-state (k) #:prefab)

(struct crypto-sign-keypair (pk sk) #:prefab)

(define-libsodium crypto_box_seedbytes (_fun -> _size))
(define crypto_box_SEEDBYTES (crypto_box_seedbytes))

(define-libsodium crypto_box_publickeybytes (_fun -> _size))
(define crypto_box_PUBLICKEYBYTES (crypto_box_publickeybytes))

(define-libsodium crypto_box_secretkeybytes (_fun -> _size))
(define crypto_box_SECRETKEYBYTES (crypto_box_secretkeybytes))

(define-libsodium crypto_box_noncebytes (_fun -> _size))
(define crypto_box_NONCEBYTES (crypto_box_noncebytes))

(define-libsodium crypto_box_macbytes (_fun -> _size))
(define crypto_box_MACBYTES (crypto_box_macbytes))

(define-libsodium crypto_box_messagebytes_max (_fun -> _size))
(define crypto_box_MESSAGEBYTES_MAX (crypto_box_messagebytes_max))

(define-libsodium crypto_box_primitive (_fun -> _string))
(define crypto_box_PRIMITIVE (crypto_box_primitive))

(define-libsodium crypto_box_beforenmbytes (_fun -> _size))
(define crypto_box_BEFORENMBYTES (crypto_box_beforenmbytes))

(define-libsodium crypto_box_keypair (_fun _bytes _bytes -> _int))

(define (make-crypto-box-keypair)
  (define pk (make-bytes crypto_box_PUBLICKEYBYTES))
  (define sk (make-bytes crypto_box_SECRETKEYBYTES))
  (check-result (crypto_box_keypair pk sk))
  (crypto-box-keypair pk sk))

(define-libsodium crypto_box_seed_keypair (_fun _bytes _bytes _bytes -> _int))

(define (seed->crypto-box-keypair seed)
  (define pk (make-bytes crypto_box_PUBLICKEYBYTES))
  (define sk (make-bytes crypto_box_SECRETKEYBYTES))
  (check-length 'seed->crypto-box-keypair "seed" seed crypto_box_SEEDBYTES)
  (check-result (crypto_box_seed_keypair pk sk seed))
  (crypto-box-keypair pk sk))

(define (bytes->crypto-box-keypair bs)
  (define seed (subbytes (crypto-hash bs) 0 crypto_box_SEEDBYTES))
  (seed->crypto-box-keypair seed))

(define-libsodium crypto_scalarmult_base (_fun _bytes _bytes -> _int))

(define (crypto-scalarmult-base sk)
  (check-length 'crypto-scalarmult-base "sk" sk crypto_box_SECRETKEYBYTES)
  (define pk (make-bytes crypto_box_PUBLICKEYBYTES))
  (check-result (crypto_scalarmult_base pk sk))
  pk)

(define (crypto-box-random-nonce)
  (random-bytes crypto_box_NONCEBYTES))

(define-libsodium crypto_box_easy (_fun _bytes _bytes _ullong _bytes _bytes _bytes -> _int))

(define (crypto-box msg nonce pk sk)
  (define c (make-bytes (+ crypto_box_MACBYTES (bytes-length msg))))
  (check-length 'crypto-box "nonce" nonce crypto_box_NONCEBYTES)
  (check-length 'crypto-box "pk" pk crypto_box_PUBLICKEYBYTES)
  (check-length 'crypto-box "sk" sk crypto_box_SECRETKEYBYTES)
  (check-result (crypto_box_easy c msg (bytes-length msg) nonce pk sk))
  c)

(define-libsodium crypto_box_open_easy (_fun _bytes _bytes _ullong _bytes _bytes _bytes -> _int))

(define (crypto-box-open c nonce pk sk)
  (define msg (make-bytes (- (bytes-length c) crypto_box_MACBYTES)))
  (check-length 'crypto-box-open "nonce" nonce crypto_box_NONCEBYTES)
  (check-length 'crypto-box-open "pk" pk crypto_box_PUBLICKEYBYTES)
  (check-length 'crypto-box-open "sk" sk crypto_box_SECRETKEYBYTES)
  (check-result (crypto_box_open_easy msg c (bytes-length c) nonce pk sk))
  msg)

(define-libsodium crypto_box_beforenm (_fun _bytes _bytes _bytes -> _int))

(define (crypto-box-precompute pk sk)
  (define k (make-bytes crypto_box_BEFORENMBYTES))
  (check-length 'crypto-box-precompute "pk" pk crypto_box_PUBLICKEYBYTES)
  (check-length 'crypto-box-precompute "sk" sk crypto_box_SECRETKEYBYTES)
  (check-result (crypto_box_beforenm k pk sk))
  (crypto-box-state k))

(define-libsodium crypto_box_easy_afternm (_fun _bytes _bytes _ullong _bytes _bytes -> _int))

(define (crypto-box* msg nonce state)
  (define k (crypto-box-state-k state))
  (define c (make-bytes (+ crypto_box_MACBYTES (bytes-length msg))))
  (check-length 'crypto-box* "nonce" nonce crypto_box_NONCEBYTES)
  (check-length 'crypto-box* "k" k crypto_box_BEFORENMBYTES)
  (check-result (crypto_box_easy_afternm c msg (bytes-length msg) nonce k))
  c)

(define-libsodium crypto_box_open_easy_afternm (_fun _bytes _bytes _ullong _bytes _bytes -> _int))

(define (crypto-box-open* c nonce state)
  (define k (crypto-box-state-k state))
  (define msg (make-bytes (- (bytes-length c) crypto_box_MACBYTES)))
  (check-length 'crypto-box-open* "nonce" nonce crypto_box_NONCEBYTES)
  (check-length 'crypto-box-open* "k" k crypto_box_BEFORENMBYTES)
  (check-result (crypto_box_open_easy_afternm msg c (bytes-length c) nonce k))
  msg)
