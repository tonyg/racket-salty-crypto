#!/usr/bin/env racket
#lang racket
;;; SPDX-License-Identifier: LGPL-3.0-or-later
;;; SPDX-FileCopyrightText: Copyright © 2021-2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require file/glob)
(require racket/date)

(define ((re p) i) (regexp-match p i))
(define ((re? p) i) (regexp-match? p i))
(define ((s p ins) i) (regexp-replace p i ins))

(define this-year (number->string (date-year (current-date))))

(define (get-git-config key)
  (string-trim (with-output-to-string
                 (lambda () (system* "/usr/bin/env" "git" "config" "--get" key)))))

(define (is-tracked? f)
  (call-with-output-file "/dev/null" #:exists 'append
    (lambda (sink)
      (parameterize ((current-error-port sink)
                     (current-output-port sink))
        (system* "/usr/bin/env" "git" "ls-files" "--error-unmatch" f)))))

(define user-name (get-git-config "user.name"))
(define user-email (get-git-config "user.email"))

(define user (format "~a <~a>" user-name user-email))

(define (make-copyright who low [hi #f])
  (if (and hi (not (string=? low hi)))
      (format "Copyright © ~a-~a ~a" low hi who)
      (format "Copyright © ~a ~a" low who)))

(define total-file-count 0)
(define total-changed-files 0)
(define dry-run? #f)
(define modify-untracked? #f)

(define (fix-files #:file-type-name file-type-name
                   #:file-pattern file-pattern
                   #:front-matter-re [front-matter-re #f]
                   #:leading-comment-re leading-comment-re
                   #:comment-prefix comment-prefix
                   #:file-filter [file-filter (lambda (x) #t)])
  (define matched-files (filter file-filter (glob file-pattern)))
  (define file-count (length matched-files))
  (define changed-files 0)
  (for [(file-number (in-naturals))
        (f (in-list matched-files))]
    (printf "~a [~a/~a] ~a ..." file-type-name file-number file-count f)
    (flush-output)
    (define all-lines (file->lines f))
    (define-values (front-matter head tail)
      (let*-values (((lines) all-lines)
                    ((front-matter lines) (if front-matter-re
                                              (splitf-at lines (re? front-matter-re))
                                              (values '() lines)))
                    ((head tail) (splitf-at lines (re? leading-comment-re))))
        (values front-matter head tail)))
    (let* ((head (map (s leading-comment-re "") head))
           (head (map (lambda (l)
                        (match (regexp-match "^([^:]+): (.*)$" l)
                          [(list _ k v) (list k v)]
                          [#f (list #f l)]))
                      head))
           (head (if (assoc "SPDX-FileCopyrightText" head)
                     head
                     (cons (list "SPDX-FileCopyrightText" (make-copyright user this-year)) head)))
           (head (if (assoc "SPDX-License-Identifier" head)
                     head
                     (cons (list "SPDX-License-Identifier" "ISC") head)))
           (head (map (lambda (l)
                        (match l
                          [(list "SPDX-FileCopyrightText"
                                 (and (regexp (regexp-quote user-name))
                                      (regexp #px"(\\d{4})-\\d{4}" (list _ low))))
                           (list "SPDX-FileCopyrightText"
                                 (make-copyright user low this-year))]
                          [(list "SPDX-FileCopyrightText"
                                 (and (regexp (regexp-quote user-name))
                                      (regexp #px"\\d{4}" (list low))))
                           (list "SPDX-FileCopyrightText"
                                 (make-copyright user low this-year))]
                          [_ l]))
                      head))
           (head (map (lambda (l)
                        (if (string=? (cadr l) "")
                            (string-trim comment-prefix)
                            (string-append comment-prefix
                                           (match l
                                             [(list #f v) v]
                                             [(list k v) (format "~a: ~a" k v)]))))
                      head))
           (new-lines `(,@front-matter
                        ,@head
                        ""
                        ,@(dropf tail (lambda (l) (string=? (string-trim l) "")))))
           (would-change-if-written? (not (equal? all-lines new-lines)))
           (write-needed? (and would-change-if-written? (or modify-untracked? (is-tracked? f)))))
      (when (and write-needed? (not dry-run?))
        (call-with-atomic-output-file
         f
         (lambda (port _tmp-path)
           (for [(l front-matter)] (displayln l port))
           (for [(l head)] (displayln l port))
           (newline port)
           (for [(l (dropf tail (lambda (l) (string=? (string-trim l) ""))))] (displayln l port)))))
      (if write-needed?
          (begin (set! changed-files (+ changed-files 1))
                 (printf "\e[41mchanged\e[0m\n"))
          (printf "\r\e[K"))))
  (when (positive? changed-files)
    (printf "~a [~a total files, ~a changed]\n" file-type-name file-count changed-files))
  (set! total-file-count (+ total-file-count file-count))
  (set! total-changed-files (+ total-changed-files changed-files)))

(command-line #:once-each
              [("-n" "--dry-run") "Do not write back changes to files"
               (set! dry-run? #t)]
              [("--modify-untracked") "Modify files not tracked by git as well as those that are"
               (set! modify-untracked? #t)])

(void (fix-files #:file-type-name "Racket"
                 #:file-pattern "**.rkt"
                 #:front-matter-re #px"^#"
                 #:leading-comment-re #px"^;+ *"
                 #:comment-prefix ";;; "))

(printf "fixcopyright: ~a files examined, ~a ~a\n"
        total-file-count
        total-changed-files
        (if dry-run?
            (if (zero? total-changed-files)
                "changes are needed"
                "files need to be updated")
            (if (zero? total-changed-files)
                "changes were needed"
                "files were updated")))

(exit (if (positive? total-changed-files) 1 0))
