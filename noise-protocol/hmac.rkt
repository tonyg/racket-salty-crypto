#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide make-hmac)

(require "bytes.rkt")

(define (make-hmac HASH BLOCKLEN)
  (let ((ipad (make-bytes BLOCKLEN #x36))
        (opad (make-bytes BLOCKLEN #x5c)))
    (lambda (key data)
      (let* ((key (if (> (bytes-length key) BLOCKLEN) (HASH key) key))
             (key (bytes-append key (make-bytes (- BLOCKLEN (bytes-length key))))))
        (HASH (bytes-append (bytes-xor key opad)
                            (HASH (bytes-append (bytes-xor key ipad)
                                                data))))))))

(module+ test
  (require rackunit)
  (require file/sha1)
  (require file/md5)
  (check-equal? ((make-hmac (lambda (i) (md5 i #f)) 64) (make-bytes 16 11) #"Hi There")
                (hex-string->bytes "9294727a3638bb1c13f48ef8158bfc9d")))
