#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide (struct-out CipherState)
         EncryptWithAd
         DecryptWithAd
         Rekey

         make-initiator
         make-responder
         WriteMessage
         ReadMessage

         ;; plus uses of define/provide below
         )

(require libsodium)
(require libb2)
(require racket/match)
(require racket/port)

(module+ test (require rackunit))

(define (GENERATE_KEYPAIR) (make-crypto-box-keypair))
(define DHLEN crypto_box_BEFORENMBYTES)
(define (DH kp pk) (crypto-box-state-k (crypto-box-precompute pk (crypto-box-keypair-sk kp))))

(define (ENCRYPT k n ad plaintext) (crypto-aead-chacha20poly1305-encrypt plaintext ad n k))
(define (DECRYPT k n ad ciphertext) (crypto-aead-chacha20poly1305-decrypt ciphertext ad n k))
(define (REKEY k)
  (subbytes (ENCRYPT k
                     (make-bytes crypto_aead_chacha20poly1305_NPUBBYTES 255)
                     #""
                     (make-bytes crypto_aead_chacha20poly1305_KEYBYTES))
            0
            crypto_aead_chacha20poly1305_KEYBYTES))

(define (HASH data) (blake2s data))
(define HASHLEN BLAKE2S_OUTBYTES)
(define BLOCKLEN BLAKE2S_BLOCKLEN)

(define (bytes-xor bs1 bs2)
  (define r (make-bytes (max (bytes-length bs1) (bytes-length bs2))))
  (for [(i (in-range (bytes-length r)))
        (j1 (in-cycle (in-range (bytes-length bs1))))
        (j2 (in-cycle (in-range (bytes-length bs2))))]
    (bytes-set! r i (bitwise-xor (bytes-ref bs1 j1) (bytes-ref bs2 j2))))
  r)

(module+ test
  (check-equal? (bytes-xor (make-bytes 3 #x5a) (make-bytes 3 #xa5))
                (make-bytes 3 #xff))
  (check-equal? (bytes-xor (make-bytes 3 #x5a) (make-bytes 1 #xa5))
                (make-bytes 3 #xff))
  (check-equal? (bytes-xor (make-bytes 1 #x5a) (make-bytes 3 #xa5))
                (make-bytes 3 #xff)))

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
  (require file/sha1)
  (require file/md5)
  (check-equal? ((make-hmac (lambda (i) (md5 i #f)) 64) (make-bytes 16 11) #"Hi There")
                (hex-string->bytes "9294727a3638bb1c13f48ef8158bfc9d")))

(define HMAC-HASH (make-hmac HASH BLOCKLEN))

(define (HKDF chaining-key input-key-material num-outputs)
  (define temp-key (HMAC-HASH chaining-key input-key-material))
  (define output1 (HMAC-HASH temp-key (bytes 1)))
  (define output2 (HMAC-HASH temp-key (bytes-append output1 (bytes 2))))
  (match num-outputs
    [2 (list output1 output2)]
    [3 (list output1 output2 (HMAC-HASH temp-key (bytes-append output2 (bytes 3))))]))

;;---------------------------------------------------------------------------

(struct CipherState (k n) #:mutable)

(define (make-CipherState [k #f])
  (CipherState k 0))

(define (InitializeKey cs k)
  (set-CipherState-k! cs k)
  (set-CipherState-n! cs 0)
  cs)

(define (next-n! cs)
  (define n (CipherState-n cs))
  (set-CipherState-n! cs (+ n 1))
  (when (= n #xffffffffffffffff)
    (error 'next-nonce "No more nonces available"))
  (integer->integer-bytes n 8 #f #t))

(define (HasKey cs)
  (not (eq? #f (CipherState-k cs))))

(define (EncryptWithAd cs ad plaintext)
  (if (HasKey cs)
      (ENCRYPT (CipherState-k cs) (next-n! cs) ad plaintext)
      plaintext))

(define (DecryptWithAd cs ad ciphertext)
  (if (HasKey cs)
      (DECRYPT (CipherState-k cs) (next-n! cs) ad ciphertext)
      ciphertext))

(define (Rekey cs)
  (set-CipherState-k! cs (REKEY (CipherState-k cs))))

;;---------------------------------------------------------------------------

(struct SymmetricState (cs ck h) #:mutable)

(define (make-SymmetricState protocol_name)
  (define h (if (<= (bytes-length protocol_name) HASHLEN)
                (bytes-append protocol_name (make-bytes (- HASHLEN (bytes-length protocol_name))))
                (HASH protocol_name)))
  (SymmetricState (make-CipherState) h h))

(define (MixKey ss input_key_material)
  (match-define (list new-ck temp_k) (HKDF (SymmetricState-ck ss) input_key_material 2))
  (set-SymmetricState-ck! ss new-ck)
  (InitializeKey (SymmetricState-cs ss) (subbytes temp_k 0 32)))

(define (MixHash ss data)
  (set-SymmetricState-h! ss (HASH (bytes-append (SymmetricState-h ss) data))))

(define (MixKeyAndHash ss input_key_material)
  (match-define (list new-ck temp_h temp_k) (HKDF (SymmetricState-ck ss) input_key_material 3))
  (set-SymmetricState-ck! ss new-ck)
  (MixHash ss temp_h)
  (InitializeKey (SymmetricState-cs ss) (subbytes temp_k 0 32)))

(define (GetHandshakeHash ss)
  (SymmetricState-h ss))

(define (EncryptAndHash ss plaintext)
  (define ciphertext (EncryptWithAd (SymmetricState-cs ss) (SymmetricState-h ss) plaintext))
  (MixHash ss ciphertext)
  ciphertext)

(define (DecryptAndHash ss ciphertext)
  (define plaintext (DecryptWithAd (SymmetricState-cs ss) (SymmetricState-h ss) ciphertext))
  (MixHash ss ciphertext)
  plaintext)

(define (Split ss)
  (match-define (list temp_k1 temp_k2) (HKDF (SymmetricState-ck ss) #"" 2))
  (list (make-CipherState (subbytes temp_k1 0 32))
        (make-CipherState (subbytes temp_k2 0 32))))

;;---------------------------------------------------------------------------

(struct handshake-pattern (name initiator-pre-message responder-pre-message message-patterns) #:prefab)

(struct HandshakeState (ss s e rs re initiator message-patterns psks) #:mutable)

(define (make-HandshakeState handshake_pattern initiator prologue s e rs re [psks #f])
  (define protocol_name
    (string->bytes/utf-8 (format "Noise_~a_25519_ChaChaPoly_BLAKE2s"
                                 (handshake-pattern-name handshake_pattern))))
  (define ss (make-SymmetricState protocol_name))
  (MixHash ss prologue)
  (define hs (HandshakeState ss s e rs re initiator (handshake-pattern-message-patterns handshake_pattern) psks))
  (for [(token (handshake-pattern-initiator-pre-message handshake_pattern))]
    (MixHash (HandshakeState-ss hs)
             (match token
               ['e (crypto-box-keypair-pk e)]
               ['s (crypto-box-keypair-pk s)])))
  (for [(token (handshake-pattern-responder-pre-message handshake_pattern))]
    (MixHash (HandshakeState-ss hs)
             (match token
               ['e re]
               ['s rs])))
  hs)

(define (make-initiator handshake_pattern
                        #:prologue [prologue #""]
                        #:static-keypair [static #f]
                        #:remote-static-keypair [remote-static #f]
                        #:preshared-keys [psks #f])
  (make-HandshakeState handshake_pattern #t prologue static #f remote-static #f psks))

(define (make-responder handshake_pattern
                        #:prologue [prologue #""]
                        #:static-keypair [static #f]
                        #:remote-static-keypair [remote-static #f]
                        #:preshared-keys [psks #f])
  (make-HandshakeState handshake_pattern #f prologue static #f remote-static #f psks))

(define (next-message-pattern! hs)
  (match-define (cons mp more) (HandshakeState-message-patterns hs))
  (set-HandshakeState-message-patterns! hs more)
  mp)

(define (next-psk! hs)
  (match-define (cons psk more) (HandshakeState-psks hs))
  (set-HandshakeState-psks! hs more)
  psk)

(define (maybe-Split hs)
  (if (null? (HandshakeState-message-patterns hs))
      (Split (HandshakeState-ss hs))
      #f))

(define (WriteMessage hs payload)
  (define buffer
    (call-with-output-bytes
     (lambda (port)
       (for [(token (next-message-pattern! hs))]
         (match token
           ['e (set-HandshakeState-e! hs (GENERATE_KEYPAIR))
               (write-bytes (crypto-box-keypair-pk (HandshakeState-e hs)) port)
               (MixHash (HandshakeState-ss hs) (crypto-box-keypair-pk (HandshakeState-e hs)))
               (when (HandshakeState-psks hs)
                 (MixKey (HandshakeState-ss hs) (crypto-box-keypair-pk (HandshakeState-e hs))))]
           ['s (write-bytes (EncryptAndHash (HandshakeState-ss hs)
                                            (crypto-box-keypair-pk (HandshakeState-s hs)))
                            port)]
           ['ee (MixKey (HandshakeState-ss hs) (DH (HandshakeState-e hs) (HandshakeState-re hs)))]
           ['es (MixKey (HandshakeState-ss hs) (if (HandshakeState-initiator hs)
                                                   (DH (HandshakeState-e hs) (HandshakeState-rs hs))
                                                   (DH (HandshakeState-s hs) (HandshakeState-re hs))))]
           ['se (MixKey (HandshakeState-ss hs) (if (HandshakeState-initiator hs)
                                                   (DH (HandshakeState-s hs) (HandshakeState-re hs))
                                                   (DH (HandshakeState-e hs) (HandshakeState-rs hs))))]
           ['ss (MixKey (HandshakeState-ss hs) (DH (HandshakeState-s hs) (HandshakeState-rs hs)))]
           ['psk (MixKeyAndHash (HandshakeState-ss hs) (next-psk! hs))]))
       (write-bytes (EncryptAndHash (HandshakeState-ss hs) payload) port))))
  (values buffer (maybe-Split hs)))

(define (ReadMessage hs message)
  (define in (open-input-bytes message))
  (for [(token (next-message-pattern! hs))]
    (match token
      ['e (set-HandshakeState-re! hs (read-bytes DHLEN in))
          (MixKey (HandshakeState-ss hs) (HandshakeState-re hs))
          (when (HandshakeState-psks hs)
            (MixKey (HandshakeState-ss hs) (HandshakeState-re hs)))]
      ['s (let ((temp (if (HasKey (SymmetricState-cs (HandshakeState-ss hs)))
                          (read-bytes (+ DHLEN 16) in)
                          (read-bytes DHLEN in))))
            (set-HandshakeState-rs! hs (DecryptAndHash (HandshakeState-ss hs) temp)))]
      ['ee (MixKey (HandshakeState-ss hs) (DH (HandshakeState-e hs) (HandshakeState-re hs)))]
      ['es (MixKey (HandshakeState-ss hs) (if (HandshakeState-initiator hs)
                                              (DH (HandshakeState-e hs) (HandshakeState-rs hs))
                                              (DH (HandshakeState-s hs) (HandshakeState-re hs))))]
      ['se (MixKey (HandshakeState-ss hs) (if (HandshakeState-initiator hs)
                                              (DH (HandshakeState-s hs) (HandshakeState-re hs))
                                              (DH (HandshakeState-e hs) (HandshakeState-rs hs))))]
      ['ss (MixKey (HandshakeState-ss hs) (DH (HandshakeState-s hs) (HandshakeState-rs hs)))]
      ['psk (MixKeyAndHash (HandshakeState-ss hs) (next-psk! hs))]))
  (values (DecryptAndHash (HandshakeState-ss hs) (port->bytes in)) (maybe-Split hs)))

;;---------------------------------------------------------------------------

(define-syntax-rule (define/provide id expr) (begin (define id expr) (provide id)))

(define/provide NN (handshake-pattern "NN" '() '() '((e) (e ee))))
(define/provide NK (handshake-pattern "NK" '() '(s) '((e es) (e ee))))
(define/provide IK (handshake-pattern "IK" '() '(s) '((e es s ss) (e ee se))))
(define/provide XK (handshake-pattern "XK" '() '(s) '((e es) (e ee) (s se))))
(define/provide XX (handshake-pattern "XX" '() '() '((e) (e ee s es) (s se))))
(define/provide IX (handshake-pattern "IX" '() '() '((e s) (e ee se s es))))

(define/provide NNpsk0 (handshake-pattern "NNpsk0" '() '() '((psk e) (e ee))))

(define/provide NKpsk2 (handshake-pattern "NKpsk2" '() '(s) '((e es) (e ee psk))))
(define/provide IKpsk2 (handshake-pattern "IKpsk2" '() '(s) '((e es s ss) (e ee se psk))))
