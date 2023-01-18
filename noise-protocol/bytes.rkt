#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide bytes-xor
         bytes-pad-or-reduce)

(define (bytes-xor bs1 bs2)
  (define r (make-bytes (max (bytes-length bs1) (bytes-length bs2))))
  (for [(i (in-range (bytes-length r)))
        (j1 (in-cycle (in-range (bytes-length bs1))))
        (j2 (in-cycle (in-range (bytes-length bs2))))]
    (bytes-set! r i (bitwise-xor (bytes-ref bs1 j1) (bytes-ref bs2 j2))))
  r)

(define (bytes-pad-or-reduce bs target-size chop)
  (let* ((bs (if (> (bytes-length bs) target-size) (chop bs) bs)))
    (bytes-append bs (make-bytes (- target-size (bytes-length bs))))))

(module+ test
  (require rackunit)
  (check-equal? (bytes-xor (make-bytes 3 #x5a) (make-bytes 3 #xa5))
                (make-bytes 3 #xff))
  (check-equal? (bytes-xor (make-bytes 3 #x5a) (make-bytes 1 #xa5))
                (make-bytes 3 #xff))
  (check-equal? (bytes-xor (make-bytes 1 #x5a) (make-bytes 3 #xa5))
                (make-bytes 3 #xff)))
