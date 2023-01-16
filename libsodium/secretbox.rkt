#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2012-2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require ffi/unsafe)
(require "ffi-lib.rkt")
(require "random.rkt")

(provide crypto_secretbox_KEYBYTES
         crypto_secretbox_NONCEBYTES
         crypto_secretbox_MACBYTES
         crypto_secretbox_MESSAGEBYTES_MAX
         crypto_secretbox_PRIMITIVE

	 crypto-secretbox-random-nonce
         crypto-secretbox-keygen
	 crypto-secretbox
	 crypto-secretbox-open
         )

(define-libsodium crypto_secretbox_keybytes (_fun -> _size))
(define crypto_secretbox_KEYBYTES (crypto_secretbox_keybytes))

(define-libsodium crypto_secretbox_noncebytes (_fun -> _size))
(define crypto_secretbox_NONCEBYTES (crypto_secretbox_noncebytes))

(define-libsodium crypto_secretbox_macbytes (_fun -> _size))
(define crypto_secretbox_MACBYTES (crypto_secretbox_macbytes))

(define-libsodium crypto_secretbox_messagebytes_max (_fun -> _size))
(define crypto_secretbox_MESSAGEBYTES_MAX (crypto_secretbox_messagebytes_max))

(define-libsodium crypto_secretbox_primitive (_fun -> _string))
(define crypto_secretbox_PRIMITIVE (crypto_secretbox_primitive))

(define (crypto-secretbox-random-nonce)
  (random-bytes crypto_secretbox_NONCEBYTES))

(define (crypto-secretbox-keygen)
  (random-bytes crypto_secretbox_KEYBYTES))

(define-libsodium crypto_secretbox_easy (_fun _bytes _bytes _ullong _bytes _bytes -> _int))
(define-libsodium crypto_secretbox_open_easy (_fun _bytes _bytes _ullong _bytes _bytes -> _int))

(define (crypto-secretbox msg nonce key)
  (define c (make-bytes (+ crypto_secretbox_MACBYTES (bytes-length msg))))
  (check-length 'crypto-secretbox "nonce" nonce crypto_secretbox_NONCEBYTES)
  (check-length 'crypto-secretbox "key" key crypto_secretbox_KEYBYTES)
  (check-result (crypto_secretbox_easy c msg (bytes-length msg) nonce key))
  c)

(define (crypto-secretbox-open c nonce key)
  (define msg (make-bytes (- (bytes-length c) crypto_secretbox_MACBYTES)))
  (check-length 'crypto-secretbox-open "nonce" nonce crypto_secretbox_NONCEBYTES)
  (check-length 'crypto-secretbox-open "key" key crypto_secretbox_KEYBYTES)
  (check-result (crypto_secretbox_open_easy msg c (bytes-length c) nonce key))
  msg)
