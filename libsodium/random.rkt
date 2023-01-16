#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2012-2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide random-bytes)

(require ffi/unsafe)
(require "ffi-lib.rkt")

(define-libsodium randombytes_buf (_fun _bytes _uint64 -> _void))
(define (random-bytes count)
  (define bs (make-bytes count))
  (randombytes_buf bs (bytes-length bs))
  bs)
