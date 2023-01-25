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
         ["I1K1" (handshake-pattern "----" "----" '() '(s) '((e s) (e ee es) (se)))]
         ["I1K" (handshake-pattern "---" "---" '() '(s) '((e es s) (e ee) (se)))]
         ["I1N" (handshake-pattern "---" "---" '() '() '((e s) (e ee) (se)))]
         ["I1X1" (handshake-pattern "----" "----" '() '() '((e s) (e ee s) (se es)))]
         ["I1X" (handshake-pattern "---" "---" '() '() '((e s) (e ee s es) (se)))]
         ["IK1" (handshake-pattern "---" "---" '() '(s) '((e s) (e ee se es)))]
         ["IK" (handshake-pattern "--" "--" '() '(s) '((e es s ss) (e ee se)))]
         ["IN" (handshake-pattern "--" "--" '() '() '((e s) (e ee se)))]
         ["IX1" (handshake-pattern "---" "---" '() '() '((e s) (e ee se s) (es)))]
         ["IX" (handshake-pattern "--" "--" '() '() '((e s) (e ee se s es)))]
         ["K1K1" (handshake-pattern "----" "----" '(s) '(s) '((e) (e ee es) (se)))]
         ["K1K" (handshake-pattern "---" "---" '(s) '(s) '((e es) (e ee) (se)))]
         ["K1N" (handshake-pattern "---" "---" '(s) '() '((e) (e ee) (se)))]
         ["K1X1" (handshake-pattern "----" "----" '(s) '() '((e) (e ee s) (se es)))]
         ["K1X" (handshake-pattern "---" "---" '(s) '() '((e) (e ee s es) (se)))]
         ["K" (handshake-pattern "-" "-" '(s) '(s) '((e es ss)))]
         ["KK1" (handshake-pattern "---" "---" '(s) '(s) '((e) (e ee se es)))]
         ["KK" (handshake-pattern "--" "--" '(s) '(s) '((e es ss) (e ee se)))]
         ["KN" (handshake-pattern "--" "--" '(s) '() '((e) (e ee se)))]
         ["KX1" (handshake-pattern "---" "---" '(s) '() '((e) (e ee se s) (es)))]
         ["KX" (handshake-pattern "--" "--" '(s) '() '((e) (e ee se s es)))]
         ["N" (handshake-pattern "-" "-" '() '(s) '((e es)))]
         ["NK1" (handshake-pattern "---" "---" '() '(s) '((e) (e ee es)))]
         ["NK" (handshake-pattern "--" "--" '() '(s) '((e es) (e ee)))]
         ["NN" (handshake-pattern "--" "--" '() '() '((e) (e ee)))]
         ["NX1" (handshake-pattern "---" "---" '() '() '((e) (e ee s) (es)))]
         ["NX" (handshake-pattern "--" "--" '() '() '((e) (e ee s es)))]
         ["X1K1" (handshake-pattern "----" "----" '() '(s) '((e) (e ee es) (s) (se)))]
         ["X1K" (handshake-pattern "---" "---" '() '(s) '((e es) (e ee) (s) (se)))]
         ["X1N" (handshake-pattern "---" "---" '() '() '((e) (e ee) (s) (se)))]
         ["X1X1" (handshake-pattern "----" "----" '() '() '((e) (e ee s) (es s) (se)))]
         ["X1X" (handshake-pattern "---" "---" '() '() '((e) (e ee s es) (s) (se)))]
         ["X" (handshake-pattern "-" "-" '() '(s) '((e es s ss)))]
         ["XK1" (handshake-pattern "---" "---" '() '(s) '((e) (e ee es) (s se)))]
         ["XK" (handshake-pattern "--" "--" '() '(s) '((e es) (e ee) (s se)))]
         ["XN" (handshake-pattern "--" "--" '() '() '((e) (e ee) (s se)))]
         ["XX1" (handshake-pattern "---" "---" '() '() '((e) (e ee s) (es s se)))]
         ["XX" (handshake-pattern "--" "--" '() '() '((e) (e ee s es) (s se)))]
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
