#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide Noise-*-25519_ChaChaPoly_BLAKE2s
         instantiate-noise-protocol
         complete-handshake
         (all-from-out "patterns.rkt"))

(require "patterns.rkt")
(require "protocol.rkt")

(define Noise-*-25519_ChaChaPoly_BLAKE2s
  (let ()
    (local-require libsodium)
    (local-require libb2)

    (define (nonce->bytes n)
      (bytes-append (make-bytes 4) (integer->integer-bytes n 8 #f #f)))

    (instantiate-noise-protocol

     #:dh-name "25519"
     #:generate-keypair make-crypto-box-keypair
     #:keypair-pk crypto-box-keypair-pk
     #:dh (lambda (kp pk) (crypto-scalarmult (crypto-box-keypair-sk kp) pk))
     #:dhlen crypto_scalarmult_BYTES

     #:cipher-name "ChaChaPoly"
     #:encrypt (lambda (k n ad plaintext)
                 (crypto-aead-chacha20poly1305-ietf-encrypt plaintext ad (nonce->bytes n) k))
     #:decrypt (lambda (k n ad ciphertext)
                 (crypto-aead-chacha20poly1305-ietf-decrypt ciphertext ad (nonce->bytes n) k))

     #:hash-name "BLAKE2s"
     #:hash blake2s
     #:blocklen BLAKE2S_BLOCKLEN
     #:hashlen BLAKE2S_OUTBYTES)))
