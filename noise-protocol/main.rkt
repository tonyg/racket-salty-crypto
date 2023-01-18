#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide make-noise-protocol
         (all-from-out "patterns.rkt"))

(require libsodium)
(require libb2)
(require racket/match)
(require racket/port)
(require "bytes.rkt")
(require "hmac.rkt")
(require "hkdf.rkt")
(require "patterns.rkt")

(define (GENERATE_KEYPAIR) (make-crypto-box-keypair))
(define DHLEN crypto_scalarmult_BYTES)
(define (DH kp pk) (crypto-scalarmult (crypto-box-keypair-sk kp) pk))
(define (KEYPAIR-PK kp) (crypto-box-keypair-pk kp))

(define (ENCRYPT k n ad plaintext)
  (crypto-aead-chacha20poly1305-ietf-encrypt plaintext ad (SERIALIZE-NONCE n) k))
(define (DECRYPT k n ad ciphertext)
  (crypto-aead-chacha20poly1305-ietf-decrypt ciphertext ad (SERIALIZE-NONCE n) k))
(define (SERIALIZE-NONCE n) (bytes-append (make-bytes 4) (integer->integer-bytes n 8 #f #f)))

(define (REKEY k) (ENCRYPT k (- (expt 2 64) 1) #"" (make-bytes 32)))

(define (HASH data) (blake2s data))
(define HASHLEN BLAKE2S_OUTBYTES)
(define BLOCKLEN BLAKE2S_BLOCKLEN)
(define HKDF (make-hkdf (make-hmac HASH BLOCKLEN)))

;;---------------------------------------------------------------------------

(define (CipherState k)
  (define (set-k! nk) (set! k (subbytes nk 0 32)))
  (when k (set-k! k))
  (define n 0)
  (define (++)
    (when (= n #xffffffffffffffff) (error 'CipherState "No more nonces available"))
    (begin0 n (set! n (+ n 1))))
  (match-lambda*
    [(list 'encrypt ad plaintext) (if k (ENCRYPT k (++) ad plaintext) plaintext)]
    [(list 'decrypt ad ciphertext) (if k (DECRYPT k (++) ad ciphertext) ciphertext)]
    [(list 'key) k]
    [(list 'nonce) n]
    [(list 'rekey) (set-k! (REKEY k))]))

(define (make-noise-protocol handshake_pattern
                             #:role role
                             #:prologue [prologue #""]
                             #:static-keypair [s #f]
                             #:remote-static-pk [rs #f]
                             #:pregenerated-ephemeral-keypair [e #f]
                             #:remote-pregenerated-ephemeral-pk [re #f]
                             #:preshared-keys [psks #f])
  (define protocol_name
    (string->bytes/utf-8 (format "Noise_~a_25519_ChaChaPoly_BLAKE2s"
                                 (handshake-pattern-name handshake_pattern))))

  (define cs (CipherState #f))
  (define ck (bytes-pad-or-reduce protocol_name HASHLEN HASH))
  (define h ck)
  (define message-patterns (handshake-pattern-message-patterns handshake_pattern))

  (define (MixHash data) (set! h (HASH (bytes-append h data))))

  (define (MixKey input)
    (match-define (list new-ck k) (HKDF ck input 2))
    (set! ck new-ck)
    (set! cs (CipherState k)))

  (define (MixKeyAndHash-next-psk)
    (match-define (list new-ck temp_h k) (HKDF ck (car psks) 3))
    (set! psks (cdr psks))
    (set! ck new-ck)
    (MixHash temp_h)
    (set! cs (CipherState k)))

  (define (EncryptAndHash p) (let ((c (cs 'encrypt h p))) (MixHash c) c))
  (define (DecryptAndHash c) (let ((p (cs 'decrypt h c))) (MixHash c) p))

  (define (next-message-pattern!)
    (begin0 (car message-patterns) (set! message-patterns (cdr message-patterns))))

  (define-syntax-rule (role-case i r) (match role ['initiator i] ['responder r]))

  (define (maybe-Split)
    (and (null? message-patterns)
         (let ((css (map CipherState (HKDF ck #"" 2))))
           (role-case css (reverse css)))))

  (when (not e) (set! e (GENERATE_KEYPAIR)))
  (when (not s) (set! s (GENERATE_KEYPAIR)))

  (MixHash prologue)
  (for [(token (handshake-pattern-initiator-pre-message handshake_pattern))]
    (MixHash (match token ['e (role-case (KEYPAIR-PK e) re)] ['s (role-case (KEYPAIR-PK s) rs)])))
  (for [(token (handshake-pattern-responder-pre-message handshake_pattern))]
    (MixHash (match token ['e (role-case re (KEYPAIR-PK e))] ['s (role-case rs (KEYPAIR-PK s))])))

  (match-lambda*

    [(list 'write-message payload)
     (define buffer
       (call-with-output-bytes
        (lambda (port)
          (for [(token (next-message-pattern!))]
            (match token
              ['e (write-bytes (KEYPAIR-PK e) port)
                  (MixHash (KEYPAIR-PK e))
                  (when psks (MixKey (KEYPAIR-PK e)))]
              ['s (write-bytes (EncryptAndHash (KEYPAIR-PK s)) port)]
              ['ee (MixKey (DH e re))]
              ['es (MixKey (role-case (DH e rs) (DH s re)))]
              ['se (MixKey (role-case (DH s re) (DH e rs)))]
              ['ss (MixKey (DH s rs))]
              ['psk (MixKeyAndHash-next-psk)]))
          (write-bytes (EncryptAndHash payload) port))))
     (values buffer (maybe-Split))]

    [(list 'read-message message)
     (define in (open-input-bytes message))
     (for [(token (next-message-pattern!))]
       (match token
         ['e (set! re (read-bytes DHLEN in))
             (MixHash re)
             (when psks (MixKey re))]
         ['s (set! rs (DecryptAndHash (read-bytes (+ DHLEN (if (cs 'key) 16 0)) in)))]
         ['ee (MixKey (DH e re))]
         ['es (MixKey (role-case (DH e rs) (DH s re)))]
         ['se (MixKey (role-case (DH s re) (DH e rs)))]
         ['ss (MixKey (DH s rs))]
         ['psk (MixKeyAndHash-next-psk)]))
     (values (DecryptAndHash (port->bytes in)) (maybe-Split))]

    [(list 'remote-static-key) rs]
    [(list 'handshake-hash) h]))
