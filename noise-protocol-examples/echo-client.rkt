#lang racket
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(module+ main
  (require racket/tcp)
  (require noise-protocol)

  (match (current-command-line-arguments)
    [(vector (and pattern-name (app string->pattern-number (? number? pattern-number)))
             hostname
             (app string->number (? number? port)))
     (define pattern (lookup-handshake-pattern pattern-name))
     (define echo-protocol (bytes 0 ;; no old-style PSK
                                  pattern-number
                                  0 ;; ChaChaPoly
                                  0 ;; 25519, no hybrid
                                  2 ;; BLAKE2s
                                  ))
     (define-values (in out) (tcp-connect hostname port))
     (define H (Noise-*-25519_ChaChaPoly_BLAKE2s pattern
                                                 #:role 'initiator
                                                 #:prologue echo-protocol))
     (write-bytes echo-protocol out)
     (define (write-packet bs)
       (log-info "Sending ~v" bs)
       (write-bytes (integer->integer-bytes (bytes-length bs) 2 #f #t) out)
       (write-bytes bs out)
       (flush-output out))
     (define (read-packet)
       (define len (integer-bytes->integer (read-bytes 2 in) #f #t))
       (define packet (read-bytes len in))
       (log-info "Received ~v" packet)
       packet)
     (define-values (send-cs receive-cs)
       (let loop ()
         (define-values (packet css) (H 'write-message #""))
         (write-packet packet)
         (if css
             (values (car css) (cadr css))
             (let ((packet (read-packet)))
               (define-values (message css) (H 'read-message packet))
               (when (positive? (bytes-length message))
                 (log-info "Message received during handshake: ~v" message))
               (if css
                   (values (car css) (cadr css))
                   (loop))))))
     (log-info "Handshake complete, enter lines to echo")
     (log-info "Server's static public-key is ~v" (H 'remote-static-key))
     (let loop ()
       (match (read-line)
         [(? eof-object?) (void)]
         [line
          (write-packet (send-cs 'encrypt #"" (string->bytes/utf-8 line)))
          (println (receive-cs 'decrypt #"" (read-packet)))
          (loop)]))
     (close-input-port in)
     (close-output-port out)
     (void)]
    [_
     (eprintf "Usage: echo-client pattern-name hostname port\n")
     (exit 1)]))

(define (string->pattern-number s)
  (match s
    ["NN" #x00]
    ["KN" #x01]
    ["NK" #x02]
    ["KK" #x03]
    ["NX" #x04]
    ["KX" #x05]
    ["XN" #x06]
    ["IN" #x07]
    ["XK" #x08]
    ["IK" #x09]
    ["XX" #x0A]
    ["IX" #x0B]
    [_ #f]))
