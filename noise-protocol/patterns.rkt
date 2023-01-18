#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide (struct-out handshake-pattern)
         lookup-handshake-pattern
         handshake-pattern-one-way?)

(require racket/match)
(require (only-in racket/string string-split))
(require (only-in racket/list take drop))

(struct handshake-pattern
  (name base-name initiator-pre-message responder-pre-message message-patterns)
  #:prefab)

(define (lookup-handshake-pattern pattern-name-str)
  (match pattern-name-str
    [(pregexp #px"^([NKX]|[NKXI]1?[NKX]1?)([a-z][a-z0-9]*(\\+[a-z][a-z0-9]*)*)?$"
              (list _ main modifiers0 _final-modifier))
     (define modifiers (string-split (or modifiers0 "") "+"))
     (define base
       (match main
         ["N" (handshake-pattern "-" "-" '() '(s) '((e es)))]
         ["K" (handshake-pattern "-" "-" '(s) '(s) '((e es ss)))]
         ["X" (handshake-pattern "-" "-" '() '(s) '((e es s ss)))]
         ["NN" (handshake-pattern "--" "--" '() '() '((e) (e ee)))]
         ["NK" (handshake-pattern "--" "--" '() '(s) '((e es) (e ee)))]
         ["NX" (handshake-pattern "--" "--" '() '() '((e) (e ee s es)))]
         ["KN" (handshake-pattern "--" "--" '(s) '() '((e) (e ee se)))]
         ["KK" (handshake-pattern "--" "--" '(s) '(s) '((e es ss) (e ee se)))]
         ["KX" (handshake-pattern "--" "--" '(s) '() '((e) (e ee se s es)))]
         ["XN" (handshake-pattern "--" "--" '() '() '((e) (e ee) (s se)))]
         ["XK" (handshake-pattern "--" "--" '() '(s) '((e es) (e ee) (s se)))]
         ["XX" (handshake-pattern "--" "--" '() '() '((e) (e ee s es) (s se)))]
         ["IN" (handshake-pattern "--" "--" '() '() '((e s) (e ee se)))]
         ["IK" (handshake-pattern "--" "--" '() '(s) '((e es s ss) (e ee se)))]
         ["IX" (handshake-pattern "--" "--" '() '() '((e s) (e ee se s es)))]
         [_ #f]))
     (define modified (for/fold [(p base)] [(mod modifiers)] (and p (apply-modifier p mod))))
     (and modified (struct-copy handshake-pattern modified
                     [name pattern-name-str]
                     [base-name main]))]
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

(define (handshake-pattern-one-way? p)
  (= 1 (string-length (handshake-pattern-base-name p))))
