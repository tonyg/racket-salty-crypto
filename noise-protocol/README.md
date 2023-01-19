# Noise Protocol Framework for Racket

This package implements the [Noise Protocol Framework](https://noiseprotocol.org/) for Racket.

It tracks the protocol specification [revision 34](https://noiseprotocol.org/noise_rev34.html).

## Installation

```shell
raco pkg install noise-protocol
```

## Example

First, some simple packet framing:

```racket
(define (framed thunk)
  (define-values (in out) (thunk))
  (values (lambda () (read-bytes (integer-bytes->integer (read-bytes 2 in) #f #t) in))
          (lambda (bs)
            (write-bytes (integer->integer-bytes (bytes-length bs) 2 #f #t) out)
            (write-bytes bs out)
            (flush-output out))))
```

Then, a client:

```racket
(define-values (read-packet write-packet) (framed (lambda () (tcp-connect "localhost" 9000))))
(define H (Noise-*-25519_ChaChaPoly_BLAKE2s "XX" #:role 'initiator))
(define-values (send recv) (complete-handshake H write-packet read-packet))
(write-packet (send 'encrypt #"" #"Hello world!"))
(printf "Server said: ~a\n" (recv 'decrypt #"" (read-packet)))
```

and a server:

```racket
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
```
