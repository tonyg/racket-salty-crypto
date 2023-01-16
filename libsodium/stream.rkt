#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2012-2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require ffi/unsafe)
(require "ffi-lib.rkt")
(require "random.rkt")

(provide crypto_stream_NONCEBYTES
         crypto_stream_KEYBYTES
         crypto_stream_PRIMITIVE

         crypto-stream-random-nonce
         crypto-stream-keygen
	 crypto-stream!
	 crypto-stream
	 crypto-stream-xor!
	 crypto-stream-xor
         )

(define-libsodium crypto_stream_noncebytes (_fun -> _size))
(define crypto_stream_NONCEBYTES (crypto_stream_noncebytes))

(define-libsodium crypto_stream_keybytes (_fun -> _size))
(define crypto_stream_KEYBYTES (crypto_stream_keybytes))

(define-libsodium crypto_stream_primitive (_fun -> _string))
(define crypto_stream_PRIMITIVE (crypto_stream_primitive))

(define (crypto-stream-random-nonce)
  (random-bytes crypto_stream_NONCEBYTES))

(define (crypto-stream-keygen)
  (random-bytes crypto_stream_KEYBYTES))

(define-libsodium crypto_stream (_fun _bytes _ullong _bytes _bytes -> _int))

(define (crypto-stream! out nonce key)
  (check-length 'crypto-stream! "nonce" nonce crypto_stream_NONCEBYTES)
  (check-length 'crypto-stream! "key" key crypto_stream_KEYBYTES)
  (check-result (crypto_stream out (bytes-length out) nonce key))
  out)

(define (crypto-stream clen nonce key)
  (define out (make-bytes clen))
  (crypto-stream! out nonce key))

(define-libsodium crypto_stream_xor (_fun _bytes _bytes _ullong _bytes _bytes -> _int))

(define (internal-crypto-stream-xor out msg nonce key)
  ;; Check that (bytes-length out) == (bytes-length msg) must be done by caller
  (check-length 'internal-crypto-stream-xor "nonce" nonce crypto_stream_NONCEBYTES)
  (check-length 'internal-crypto-stream-xor "key" key crypto_stream_KEYBYTES)
  (check-result (crypto_stream_xor out msg (bytes-length msg) nonce key))
  out)

(define (crypto-stream-xor! out msg nonce key)
  (check-length 'crypto-stream-xor! "output buffer" out (bytes-length msg))
  (internal-crypto-stream-xor out msg nonce key))

(define (crypto-stream-xor msg nonce key)
  (define out (make-bytes (bytes-length msg)))
  (internal-crypto-stream-xor out msg nonce key))
