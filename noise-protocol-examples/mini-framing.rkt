#lang racket
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide framed)

(define (framed thunk)
  (define-values (in out) (thunk))
  (values (lambda () (read-bytes (integer-bytes->integer (read-bytes 2 in) #f #t) in))
          (lambda (bs)
            (write-bytes (integer->integer-bytes (bytes-length bs) 2 #f #t) out)
            (write-bytes bs out)
            (flush-output out))))
