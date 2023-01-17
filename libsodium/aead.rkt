#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require ffi/unsafe)
(require "ffi-lib.rkt")
(require "random.rkt")

(provide crypto_aead_chacha20poly1305_KEYBYTES
         crypto_aead_chacha20poly1305_NPUBBYTES
         crypto_aead_chacha20poly1305_ABYTES
	 crypto-aead-chacha20poly1305-keygen
	 crypto-aead-chacha20poly1305-encrypt
         crypto-aead-chacha20poly1305-decrypt

         crypto_aead_chacha20poly1305_ietf_KEYBYTES
         crypto_aead_chacha20poly1305_ietf_NPUBBYTES
         crypto_aead_chacha20poly1305_ietf_ABYTES
	 crypto-aead-chacha20poly1305-ietf-keygen
	 crypto-aead-chacha20poly1305-ietf-encrypt
         crypto-aead-chacha20poly1305-ietf-decrypt

         crypto_aead_xchacha20poly1305_ietf_KEYBYTES
         crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
         crypto_aead_xchacha20poly1305_ietf_ABYTES
	 crypto-aead-xchacha20poly1305-ietf-keygen
	 crypto-aead-xchacha20poly1305-ietf-encrypt
         crypto-aead-xchacha20poly1305-ietf-decrypt
         )

(define-libsodium crypto_aead_chacha20poly1305_keybytes (_fun -> _size))
(define crypto_aead_chacha20poly1305_KEYBYTES (crypto_aead_chacha20poly1305_keybytes))

(define-libsodium crypto_aead_chacha20poly1305_npubbytes (_fun -> _size))
(define crypto_aead_chacha20poly1305_NPUBBYTES (crypto_aead_chacha20poly1305_npubbytes))

(define-libsodium crypto_aead_chacha20poly1305_abytes (_fun -> _size))
(define crypto_aead_chacha20poly1305_ABYTES (crypto_aead_chacha20poly1305_abytes))

(define-libsodium crypto_aead_chacha20poly1305_ietf_keybytes (_fun -> _size))
(define crypto_aead_chacha20poly1305_ietf_KEYBYTES (crypto_aead_chacha20poly1305_ietf_keybytes))

(define-libsodium crypto_aead_chacha20poly1305_ietf_npubbytes (_fun -> _size))
(define crypto_aead_chacha20poly1305_ietf_NPUBBYTES (crypto_aead_chacha20poly1305_ietf_npubbytes))

(define-libsodium crypto_aead_chacha20poly1305_ietf_abytes (_fun -> _size))
(define crypto_aead_chacha20poly1305_ietf_ABYTES (crypto_aead_chacha20poly1305_ietf_abytes))

(define-libsodium crypto_aead_xchacha20poly1305_ietf_keybytes (_fun -> _size))
(define crypto_aead_xchacha20poly1305_ietf_KEYBYTES (crypto_aead_xchacha20poly1305_ietf_keybytes))

(define-libsodium crypto_aead_xchacha20poly1305_ietf_npubbytes (_fun -> _size))
(define crypto_aead_xchacha20poly1305_ietf_NPUBBYTES (crypto_aead_xchacha20poly1305_ietf_npubbytes))

(define-libsodium crypto_aead_xchacha20poly1305_ietf_abytes (_fun -> _size))
(define crypto_aead_xchacha20poly1305_ietf_ABYTES (crypto_aead_xchacha20poly1305_ietf_abytes))

(define (crypto-aead-chacha20poly1305-keygen)
  (random-bytes crypto_aead_chacha20poly1305_KEYBYTES))
(define (crypto-aead-chacha20poly1305-ietf-keygen)
  (random-bytes crypto_aead_chacha20poly1305_ietf_KEYBYTES))
(define (crypto-aead-xchacha20poly1305-ietf-keygen)
  (random-bytes crypto_aead_xchacha20poly1305_ietf_KEYBYTES))

(define-libsodium crypto_aead_chacha20poly1305_encrypt
  (_fun _bytes (clen : (_ptr o _ullong)) _bytes _ullong _bytes _ullong _bytes _bytes _bytes
        -> (status : _int)
	-> (values status clen)))

(define-libsodium crypto_aead_chacha20poly1305_decrypt
  (_fun _bytes (mlen : (_ptr o _ullong)) _bytes _bytes _ullong _bytes _ullong _bytes _bytes
        -> (status : _int)
	-> (values status mlen)))

(define-libsodium crypto_aead_chacha20poly1305_ietf_encrypt
  (_fun _bytes (clen : (_ptr o _ullong)) _bytes _ullong _bytes _ullong _bytes _bytes _bytes
        -> (status : _int)
	-> (values status clen)))

(define-libsodium crypto_aead_chacha20poly1305_ietf_decrypt
  (_fun _bytes (mlen : (_ptr o _ullong)) _bytes _bytes _ullong _bytes _ullong _bytes _bytes
        -> (status : _int)
	-> (values status mlen)))

(define-libsodium crypto_aead_xchacha20poly1305_ietf_encrypt
  (_fun _bytes (clen : (_ptr o _ullong)) _bytes _ullong _bytes _ullong _bytes _bytes _bytes
        -> (status : _int)
	-> (values status clen)))

(define-libsodium crypto_aead_xchacha20poly1305_ietf_decrypt
  (_fun _bytes (mlen : (_ptr o _ullong)) _bytes _bytes _ullong _bytes _ullong _bytes _bytes
        -> (status : _int)
	-> (values status mlen)))

(define (encrypt* fname _f ABYTES NPUBBYTES KEYBYTES)
  (lambda (msg associated-data nonce key)
    (define c (make-bytes (+ (bytes-length msg) ABYTES)))
    (check-length fname "nonce" nonce NPUBBYTES)
    (check-length fname "key" key KEYBYTES)
    (define-values (status clen)
      (_f c msg (bytes-length msg) associated-data (bytes-length associated-data) #f nonce key))
    (when (not (zero? status))
      (raise (exn:fail:contract:libsodium
              (format "~a: error from libsodium primitive" fname)
              (current-continuation-marks))))
    (subbytes c 0 clen)))

(define crypto-aead-chacha20poly1305-encrypt
  (encrypt* 'crypto_aead_chacha20poly1305_encrypt
            crypto_aead_chacha20poly1305_encrypt
            crypto_aead_chacha20poly1305_ABYTES
            crypto_aead_chacha20poly1305_NPUBBYTES
            crypto_aead_chacha20poly1305_KEYBYTES))

(define crypto-aead-chacha20poly1305-ietf-encrypt
  (encrypt* 'crypto_aead_chacha20poly1305_ietf_encrypt
            crypto_aead_chacha20poly1305_ietf_encrypt
            crypto_aead_chacha20poly1305_ietf_ABYTES
            crypto_aead_chacha20poly1305_ietf_NPUBBYTES
            crypto_aead_chacha20poly1305_ietf_KEYBYTES))

(define crypto-aead-xchacha20poly1305-ietf-encrypt
  (encrypt* 'crypto_aead_xchacha20poly1305_ietf_encrypt
            crypto_aead_xchacha20poly1305_ietf_encrypt
            crypto_aead_xchacha20poly1305_ietf_ABYTES
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES))

(define (decrypt* fname _f ABYTES NPUBBYTES KEYBYTES)
  (lambda (c associated-data nonce key)
    (define m (make-bytes (- (bytes-length c) ABYTES)))
    (check-length fname "nonce" nonce NPUBBYTES)
    (check-length fname "key" key KEYBYTES)
    (define-values (status mlen)
      (_f m #f c (bytes-length c) associated-data (bytes-length associated-data) nonce key))
    (when (not (zero? status))
      (raise (exn:fail:contract:libsodium
              (format "~a: error from libsodium primitive" fname)
              (current-continuation-marks))))
    (subbytes m 0 mlen)))

(define crypto-aead-chacha20poly1305-decrypt
  (decrypt* 'crypto_aead_chacha20poly1305_decrypt
            crypto_aead_chacha20poly1305_decrypt
            crypto_aead_chacha20poly1305_ABYTES
            crypto_aead_chacha20poly1305_NPUBBYTES
            crypto_aead_chacha20poly1305_KEYBYTES))

(define crypto-aead-chacha20poly1305-ietf-decrypt
  (decrypt* 'crypto_aead_chacha20poly1305_ietf_decrypt
            crypto_aead_chacha20poly1305_ietf_decrypt
            crypto_aead_chacha20poly1305_ietf_ABYTES
            crypto_aead_chacha20poly1305_ietf_NPUBBYTES
            crypto_aead_chacha20poly1305_ietf_KEYBYTES))

(define crypto-aead-xchacha20poly1305-ietf-decrypt
  (decrypt* 'crypto_aead_xchacha20poly1305_ietf_decrypt
            crypto_aead_xchacha20poly1305_ietf_decrypt
            crypto_aead_xchacha20poly1305_ietf_ABYTES
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES))
