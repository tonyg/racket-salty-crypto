#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2012-2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require ffi/unsafe)
(require ffi/unsafe/define)

(provide libsodium-lib
	 define-libsodium

	 (struct-out exn:fail:contract:libsodium)
	 check-result
	 check-length)

(define libsodium-lib (ffi-lib "libsodium"))

(define-ffi-definer define-libsodium libsodium-lib
  #:default-make-fail make-not-available)

(struct exn:fail:contract:libsodium exn:fail:contract () #:transparent)

(define-syntax-rule (check-result (f arg ...))
  (when (not (zero? (f arg ...)))
    (raise (exn:fail:contract:libsodium (format "~a: error from libsodium primitive" 'f)
                                        (current-continuation-marks)))))

(define (check-length f what thing expected-length)
  (when (not (= (bytes-length thing) expected-length))
    (raise (exn:fail:contract:libsodium (format "~a: expected ~a of length ~v, got length ~v"
                                                f what expected-length (bytes-length thing))
                                        (current-continuation-marks)))))
