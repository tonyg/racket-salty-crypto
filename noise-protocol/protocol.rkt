#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide MAX-NONCE
         instantiate-noise-protocol
         complete-handshake
         make-default-rekey)

(require racket/match)
(require racket/port)
(require "bytes.rkt")
(require "hmac.rkt")
(require "hkdf.rkt")
(require "patterns.rkt")

(define MAX-NONCE (- (expt 2 64) 1))

(define (instantiate-noise-protocol

         #:dh-name DH-NAME
         #:generate-keypair GENERATE_KEYPAIR
         #:keypair-pk KEYPAIR-PK
         #:dh DH
         #:dhlen [DHLEN (compute-dhlen GENERATE_KEYPAIR KEYPAIR-PK DH)]

         #:cipher-name AEAD-CIPHER-NAME
         #:encrypt ENCRYPT
         #:decrypt DECRYPT
         #:rekey [REKEY (make-default-rekey ENCRYPT)]

         #:hash-name HASH-NAME
         #:hash HASH
         #:blocklen BLOCKLEN
         #:hashlen [HASHLEN (bytes-length (HASH #""))]
         #:hmac [HMAC (make-hmac HASH BLOCKLEN)]
         #:hkdf [HKDF (make-hkdf HMAC)]
         )

  (lambda (handshake_pattern
           #:role role
           #:prologue [prologue #""]
           #:static-keypair [s #f]
           #:remote-static-pk [rs #f]
           #:pregenerated-ephemeral-keypair [e #f]
           #:remote-pregenerated-ephemeral-pk [re #f]
           #:preshared-keys [psks #f])

    (define protocol_name
      (string->bytes/utf-8
       (format "Noise_~a_~a_~a_~a"
               (handshake-pattern-name handshake_pattern)
               DH-NAME
               AEAD-CIPHER-NAME
               HASH-NAME)))

    (define (CipherState k)
      (define (set-k! nk) (set! k (subbytes nk 0 32)))
      (when k (set-k! k))
      (define n 0)
      (define (++)
        (when (= n MAX-NONCE) (error 'CipherState "No more nonces available"))
        (begin0 n (set! n (+ n 1))))
      (match-lambda*
        [(list 'encrypt ad plaintext) (if k (ENCRYPT k (++) ad plaintext) plaintext)]
        [(list 'decrypt ad ciphertext) (if k (DECRYPT k (++) ad ciphertext) ciphertext)]
        [(list 'key) k]
        [(list 'nonce) n]
        [(list 'rekey) (set-k! (REKEY k))]))

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

      [(list 'role) role]
      [(list 'remote-static-key) rs]
      [(list 'handshake-hash) h])))

(define (compute-dhlen GENERATE_KEYPAIR KEYPAIR-PK DH)
  (define kp (GENERATE_KEYPAIR))
  (bytes-length (DH kp (KEYPAIR-PK kp))))

(define (make-default-rekey ENCRYPT)
  (lambda (k) (ENCRYPT k MAX-NONCE #"" (make-bytes 32))))

(define (complete-handshake H write-packet read-packet [handle-message void])
  (define (W)
    (define-values (packet css) (H 'write-message #""))
    (write-packet packet)
    (if css (values (car css) (cadr css)) (R)))
  (define (R)
    (define-values (message css) (H 'read-message (read-packet)))
    (handle-message message)
    (if css (values (car css) (cadr css)) (W)))
  (match (H 'role) ['initiator (W)] ['responder (R)]))
