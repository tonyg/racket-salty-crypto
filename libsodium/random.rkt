#lang racket/base

(provide random-bytes)

(require ffi/unsafe)
(require "ffi-lib.rkt")

(define-libsodium randombytes_buf (_fun _bytes _uint64 -> _void))
(define (random-bytes count)
  (define bs (make-bytes count))
  (randombytes_buf bs (bytes-length bs))
  bs)
