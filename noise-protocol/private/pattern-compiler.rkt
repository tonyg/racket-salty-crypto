#lang racket
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

;; Quick-and-dirty compiler for the handshake pattern notation used in the Noise Protocol
;; Framework spec.

(module+ main
  (require json)

  (define lines (filter non-empty-string? (map string-trim (port->lines))))

  (define stanzas (let loop ((lines lines)
                             (current-rev #f))
                    (match lines
                      [(cons (pregexp #px"^(.+):$" (list _ n)) more)
                       (define stanzas (loop more (list n)))
                       (if current-rev (cons (reverse current-rev) stanzas) stanzas)]
                      [(cons other more)
                       (loop more (cons other current-rev))]
                      ['()
                       (if current-rev (cons (reverse current-rev) '()) '())])))

  (define (parse-tokens tokens)
    (map (compose string->symbol string-trim) (string-split tokens ",")))

  (define (parse-message m)
    (match m
      [(pregexp #px"^<- *(.+)$" (list _ tokens)) (cons 'resp (parse-tokens tokens))]
      [(pregexp #px"^-> *(.+)$" (list _ tokens)) (cons 'init (parse-tokens tokens))]))

  (define patterns-rev '())

  (define (expect-just-one name vs)
    (match vs
      ['() '()]
      [(list v) v]
      [_ (error 'expect-just-one "~a: why more than one premessage? ~v" name vs)]))

  (define (compile-pattern name pre-messages messages)
    (define-values (init-pre resp-pre)
      (partition (lambda (p) (eq? (car p) 'init)) (map parse-message pre-messages)))
    (set! init-pre (expect-just-one name (map cdr init-pre)))
    (set! resp-pre (expect-just-one name (map cdr resp-pre)))
    (set! patterns-rev
          (cons (list name init-pre resp-pre (map cdr (map parse-message messages)))
                patterns-rev)))

  (for [(stanza (in-list stanzas))]
    (match-define (cons name pieces) stanza)
    (define-values (pre-messages messages) (splitf-at pieces (lambda (p) (not (equal? p "...")))))
    (if (null? messages)
        (compile-pattern name '() pre-messages)
        (compile-pattern name pre-messages (cdr messages))))

  (file-stream-buffer-mode (current-output-port) 'none)
  (match (getenv "OUTPUT")
    ["racket"
     (for [(p (reverse patterns-rev))]
       (match-define (list name init-pre resp-pre messages) p)
       (define placeholder (make-string (string-length name) #\-))
       (printf "[~s (handshake-pattern ~s ~s ~v ~v ~v)]\n" name placeholder placeholder init-pre resp-pre messages))]
    ["typescript"
     (for [(p (reverse patterns-rev))]
       (match-define (list name init-pre resp-pre messages) p)
       (printf "_p(~s, ~a, ~a, ~a);\n"
               name
               (jsexpr->string (map (lambda (m) (map symbol->string m)) messages))
               (jsexpr->string (map symbol->string init-pre))
               (jsexpr->string (map symbol->string resp-pre))))]
    [_
     (eprintf "Usage: set OUTPUT environment variable to racket or typescript\n")
     (exit 1)]))
