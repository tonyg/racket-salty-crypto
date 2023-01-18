#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require ffi/unsafe)
(require "ffi-lib.rkt")

(provide BLAKE2S_OUTBYTES
         BLAKE2B_OUTBYTES
         BLAKE2S_KEYBYTES
         BLAKE2B_KEYBYTES
         BLAKE2S_BLOCKLEN
         BLAKE2B_BLOCKLEN

         blake2s
         blake2b
         blake2sp
         blake2bp
         )

(define BLAKE2S_OUTBYTES 32)
(define BLAKE2B_OUTBYTES 64)
(define BLAKE2S_KEYBYTES 32)
(define BLAKE2B_KEYBYTES 64)
(define BLAKE2S_BLOCKLEN 64)
(define BLAKE2B_BLOCKLEN 128)

(define-libb2 _blake2s (_fun _bytes _bytes _bytes _size _size _size -> _int) #:c-id blake2s)
(define-libb2 _blake2b (_fun _bytes _bytes _bytes _size _size _size -> _int) #:c-id blake2b)
(define-libb2 _blake2sp (_fun _bytes _bytes _bytes _size _size _size -> _int) #:c-id blake2sp)
(define-libb2 _blake2bp (_fun _bytes _bytes _bytes _size _size _size -> _int) #:c-id blake2bp)

(define (blake* fname _f OUTBYTES KEYBYTES)
  (lambda (in [key #""] #:length [outbytes (* OUTBYTES 8)])
    (define out (make-bytes (/ outbytes 8)))
    (check-length-<= fname "key" key KEYBYTES)
    (check-result fname (_f out in key (bytes-length out) (bytes-length in) (bytes-length key)))
    out))

(define blake2s (blake* 'blake2s _blake2s BLAKE2S_OUTBYTES BLAKE2S_KEYBYTES))
(define blake2b (blake* 'blake2b _blake2b BLAKE2B_OUTBYTES BLAKE2B_KEYBYTES))
(define blake2sp (blake* 'blake2sp _blake2sp BLAKE2S_OUTBYTES BLAKE2S_KEYBYTES))
(define blake2bp (blake* 'blake2bp _blake2bp BLAKE2B_OUTBYTES BLAKE2B_KEYBYTES))

(module+ test
  (require rackunit)
  (require (only-in file/sha1 hex-string->bytes))

  (define-syntax-rule (C (f arg ...) in hex ...)
    (check-equal? (f in arg ...) (hex-string->bytes (string-append hex ...))))

  (C (blake2s #:length 224) #"" "1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4")
  (C (blake2s) #"" "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
  (C (blake2b #:length 384) #""
     "b32811423377f52d7862286ee1a72ee540524380fda1724a"
     "6f25d7978c6fd3244a6caf0498812673c5e05ef583825100")
  (C (blake2b) #""
     "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
     "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")

  (C (blake2b) #"The quick brown fox jumps over the lazy dog"
     "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673"
     "f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918")
  (C (blake2b) #"The quick brown fox jumps over the lazy dof"
     "ab6b007747d8068c02e25a6008db8a77c218d94f3b40d2291a7dc8a62090a744"
     "c082ea27af01521a102e42f480a31e9844053f456b4b41e8aa78bbe5c12957bb")
  )
