#lang racket
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require noise-protocol)
(require racket/tcp)
(require "mini-framing.rkt")

(module+ main
  (define-values (read-packet write-packet) (framed (lambda () (tcp-connect "localhost" 9000))))
  (define H (Noise-*-25519_ChaChaPoly_BLAKE2s "XX" #:role 'initiator))
  (define-values (send recv) (complete-handshake H write-packet read-packet))
  (write-packet (send 'encrypt #"" #"Hello world!"))
  (printf "Server said: ~a\n" (recv 'decrypt #"" (read-packet)))
  )
