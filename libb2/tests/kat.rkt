#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(module+ test
  (require rackunit)
  (require libb2)
  (require racket/match)
  (require (only-in file/sha1 hex-string->bytes))
  (require (only-in racket/string string-split))

  (define (line->bytes line)
    (match (string-split line)
      [(list _key) #""]
      [(list _key hex) (hex-string->bytes hex)]))

  (define (run-kat f filename)
    (with-input-from-file filename
      (lambda ()
        (let loop ()
          (define line (read-line))
          (cond [(eof-object? line) (void)]
                [(equal? line "") (loop)]
                [else (define in-bytes (line->bytes line))
                      (define key-bytes (line->bytes (read-line)))
                      (define hash-bytes (line->bytes (read-line)))
                      (check-equal? (f in-bytes key-bytes #:length (* (bytes-length hash-bytes) 8))
                                    hash-bytes)
                      (loop)])))))

  (run-kat blake2s "blake2s-kat.txt")
  (run-kat blake2b "blake2b-kat.txt")
  (run-kat blake2sp "blake2sp-kat.txt")
  (run-kat blake2bp "blake2bp-kat.txt"))
