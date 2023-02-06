#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide make-hmac)

(require "bytes.rkt")

(define (make-hmac HASH BLOCKLEN)
  (let ((ipad (make-bytes BLOCKLEN #x36))
        (opad (make-bytes BLOCKLEN #x5c)))
    (lambda (key data)
      (let ((key (bytes-pad-or-reduce key BLOCKLEN HASH)))
        (HASH (bytes-append (bytes-xor key opad)
                            (HASH (bytes-append (bytes-xor key ipad) data))))))))

(module+ test
  (require (only-in file/sha1 hex-string->bytes))
  (require rackunit)
  (require file/md5)
  (require libb2)
  (check-equal? (subbytes ((make-hmac blake2s BLAKE2S_BLOCKLEN) #"" #"\261\tsyndicate") 0 16)
                (hex-string->bytes "69ca300c1dbfa08fba692102dd82311a"))
  (check-equal? ((make-hmac (lambda (i) (md5 i #f)) 64) (make-bytes 16 11) #"Hi There")
                (hex-string->bytes "9294727a3638bb1c13f48ef8158bfc9d")))
