#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide (struct-out CipherState)
         EncryptWithAd
         DecryptWithAd
         Rekey

         make-HandshakeState
         WriteMessage
         ReadMessage

         (struct-out handshake-pattern)
         lookup-handshake-pattern
         )

(require libsodium)
(require libb2)
(require racket/match)
(require racket/port)
(require (only-in racket/string string-split))
(require (only-in racket/list take drop))

(module+ test (require rackunit))

(define (GENERATE_KEYPAIR) (make-crypto-box-keypair))
(define DHLEN crypto_box_BEFORENMBYTES)
(define (DH kp pk) (crypto-scalarmult (crypto-box-keypair-sk kp) pk))

(define (ENCRYPT k n ad plaintext) (crypto-aead-chacha20poly1305-ietf-encrypt plaintext ad n k))
(define (DECRYPT k n ad ciphertext) (crypto-aead-chacha20poly1305-ietf-decrypt ciphertext ad n k))
(define (REKEY k)
  (subbytes (ENCRYPT k
                     (make-bytes crypto_aead_chacha20poly1305_ietf_NPUBBYTES 255)
                     #""
                     (make-bytes crypto_aead_chacha20poly1305_ietf_KEYBYTES))
            0
            crypto_aead_chacha20poly1305_ietf_KEYBYTES))

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

(struct CipherState (k n) #:mutable #:prefab)

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
  (bytes-append (make-bytes 4) ;; ChaChaPoly-IETF has a 96-bit nonce
                ;; v Little-endian for ChaChaPoly, but big-endian for AESGCM!
                (integer->integer-bytes n 8 #f #f)))

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

(struct SymmetricState (cs ck h) #:mutable #:prefab)

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

(struct HandshakeState (ss s e rs re role message-patterns psks) #:mutable)

(define (make-HandshakeState handshake_pattern
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
  (define ss (make-SymmetricState protocol_name))
  (MixHash ss prologue)
  (for [(token (handshake-pattern-initiator-pre-message handshake_pattern))]
    (MixHash ss
             (match token
               ['e (match role ['initiator (crypto-box-keypair-pk e)] ['responder re])]
               ['s (match role ['initiator (crypto-box-keypair-pk s)] ['responder rs])])))
  (for [(token (handshake-pattern-responder-pre-message handshake_pattern))]
    (MixHash ss
             (match token
               ['e (match role ['initiator re] ['responder (crypto-box-keypair-pk e)])]
               ['s (match role ['initiator rs] ['responder (crypto-box-keypair-pk s)])])))
  (HandshakeState ss s e rs re role (handshake-pattern-message-patterns handshake_pattern) psks))

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
           ['e (if (HandshakeState-e hs)
                   (void) ;; pregenerated ephemeral keypair (for testing), no action required
                   (set-HandshakeState-e! hs (GENERATE_KEYPAIR)))
               (write-bytes (crypto-box-keypair-pk (HandshakeState-e hs)) port)
               (MixHash (HandshakeState-ss hs) (crypto-box-keypair-pk (HandshakeState-e hs)))
               (when (HandshakeState-psks hs)
                 (MixKey (HandshakeState-ss hs) (crypto-box-keypair-pk (HandshakeState-e hs))))]
           ['s (write-bytes (EncryptAndHash (HandshakeState-ss hs)
                                            (crypto-box-keypair-pk (HandshakeState-s hs)))
                            port)]
           ['ee (MixKey (HandshakeState-ss hs) (DH (HandshakeState-e hs) (HandshakeState-re hs)))]
           ['es (MixKey (HandshakeState-ss hs)
                        (match (HandshakeState-role hs)
                          ['initiator (DH (HandshakeState-e hs) (HandshakeState-rs hs))]
                          ['responder (DH (HandshakeState-s hs) (HandshakeState-re hs))]))]
           ['se (MixKey (HandshakeState-ss hs)
                        (match (HandshakeState-role hs)
                          ['initiator (DH (HandshakeState-s hs) (HandshakeState-re hs))]
                          ['responder (DH (HandshakeState-e hs) (HandshakeState-rs hs))]))]
           ['ss (MixKey (HandshakeState-ss hs) (DH (HandshakeState-s hs) (HandshakeState-rs hs)))]
           ['psk (MixKeyAndHash (HandshakeState-ss hs) (next-psk! hs))]))
       (write-bytes (EncryptAndHash (HandshakeState-ss hs) payload) port))))
  (values buffer (maybe-Split hs)))

(define (ReadMessage hs message)
  (define in (open-input-bytes message))
  (for [(token (next-message-pattern! hs))]
    (match token
      ['e (set-HandshakeState-re! hs (read-bytes DHLEN in))
          (MixHash (HandshakeState-ss hs) (HandshakeState-re hs))
          (when (HandshakeState-psks hs)
            (MixKey (HandshakeState-ss hs) (HandshakeState-re hs)))]
      ['s (let ((temp (if (HasKey (SymmetricState-cs (HandshakeState-ss hs)))
                          (read-bytes (+ DHLEN 16) in)
                          (read-bytes DHLEN in))))
            (set-HandshakeState-rs! hs (DecryptAndHash (HandshakeState-ss hs) temp)))]
      ['ee (MixKey (HandshakeState-ss hs) (DH (HandshakeState-e hs) (HandshakeState-re hs)))]
      ['es (MixKey (HandshakeState-ss hs)
                   (match (HandshakeState-role hs)
                     ['initiator (DH (HandshakeState-e hs) (HandshakeState-rs hs))]
                     ['responder (DH (HandshakeState-s hs) (HandshakeState-re hs))]))]
      ['se (MixKey (HandshakeState-ss hs)
                   (match (HandshakeState-role hs)
                     ['initiator (DH (HandshakeState-s hs) (HandshakeState-re hs))]
                     ['responder (DH (HandshakeState-e hs) (HandshakeState-rs hs))]))]
      ['ss (MixKey (HandshakeState-ss hs) (DH (HandshakeState-s hs) (HandshakeState-rs hs)))]
      ['psk (MixKeyAndHash (HandshakeState-ss hs) (next-psk! hs))]))
  (values (DecryptAndHash (HandshakeState-ss hs) (port->bytes in)) (maybe-Split hs)))

;;---------------------------------------------------------------------------

(define (lookup-handshake-pattern pattern-name-str)
  (match pattern-name-str
    [(pregexp #px"^([NKX]|[NKXI]1?[NKX]1?)([a-z][a-z0-9]*(\\+[a-z][a-z0-9]*)*)?$"
              (list _ main modifiers0 _final-modifier))
     (define modifiers (string-split (or modifiers0 "") "+"))
     (define base
       (match main
         ["NN" (handshake-pattern "NN" '() '() '((e) (e ee)))]
         ["NK" (handshake-pattern "NK" '() '(s) '((e es) (e ee)))]
         ["IK" (handshake-pattern "IK" '() '(s) '((e es s ss) (e ee se)))]
         ["XK" (handshake-pattern "XK" '() '(s) '((e es) (e ee) (s se)))]
         ["XX" (handshake-pattern "XX" '() '() '((e) (e ee s es) (s se)))]
         ["IX" (handshake-pattern "IX" '() '() '((e s) (e ee se s es)))]
         [_ #f]))
     (define modified (for/fold [(p base)] [(mod modifiers)] (and p (apply-modifier p mod))))
     (and modified (struct-copy handshake-pattern modified [name pattern-name-str]))]
    [_ #f]))

(define (apply-modifier p mod)
  (match mod
    [(pregexp #px"^psk([0-9]+)$" (list _ nstr))
     (define old-message-patterns (handshake-pattern-message-patterns p))
     (struct-copy handshake-pattern p
       [message-patterns
        (match (string->number nstr)
          [0 (cons (cons 'psk (car old-message-patterns)) (cdr old-message-patterns))]
          [n-plus-one (let ((n (- n-plus-one 1)))
                        (append (take old-message-patterns n)
                                (let ((ps (drop old-message-patterns n)))
                                  (cons (append (car ps) '(psk))
                                        (cdr ps)))))])])]
    [_ #f]))

;; (define/provide NNpsk0 (handshake-pattern "NNpsk0" '() '() '((psk e) (e ee))))
;; (define/provide NKpsk0 (handshake-pattern "NKpsk0" '() '(s) '((psk e es) (e ee))))
;; (define/provide IKpsk0 (handshake-pattern "IKpsk0" '() '(s) '((psk e es s ss) (e ee se))))
;; (define/provide XKpsk0 (handshake-pattern "XKpsk0" '() '(s) '((psk e es) (e ee) (s se))))
;; (define/provide XXpsk0 (handshake-pattern "XXpsk0" '() '() '((psk e) (e ee s es) (s se))))
;; (define/provide IXpsk0 (handshake-pattern "IXpsk0" '() '() '((psk e s) (e ee se s es))))

;; (define/provide NKpsk2 (handshake-pattern "NKpsk2" '() '(s) '((e es) (e ee psk))))
;; (define/provide IKpsk2 (handshake-pattern "IKpsk2" '() '(s) '((e es s ss) (e ee se psk))))
