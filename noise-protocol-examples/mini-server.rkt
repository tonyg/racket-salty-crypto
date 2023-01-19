#lang racket
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require noise-protocol)
(require racket/tcp)
(require "mini-framing.rkt")

(module+ main
  (define listener (tcp-listen 9000 512 #t "localhost"))
  (let loop ()
    (define-values (read-packet write-packet) (framed (lambda () (tcp-accept listener))))
    (thread
     (lambda ()
       (define H (Noise-*-25519_ChaChaPoly_BLAKE2s "XX" #:role 'responder))
       (define-values (send recv) (complete-handshake H write-packet read-packet))
       (define message (recv 'decrypt #"" (read-packet)))
       (printf "Client said: ~a\n" message)
       (write-packet (send 'encrypt #"" (string->bytes/utf-8 (~a "You said: " message))))))
    (loop))
  )
