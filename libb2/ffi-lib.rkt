#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(require ffi/unsafe)
(require ffi/unsafe/define)

(provide libb2-lib
	 define-libb2

	 (struct-out exn:fail:contract:libb2)
	 check-result
	 check-length-<=)

(define libb2-lib (ffi-lib "libb2"))

(define-ffi-definer define-libb2 libb2-lib
  #:default-make-fail make-not-available)

(struct exn:fail:contract:libb2 exn:fail:contract () #:transparent)

(define (check-result fname result)
  (when (not (zero? result))
    (raise (exn:fail:contract:libb2 (format "~a: error from libb2 primitive" fname)
                                    (current-continuation-marks)))))

(define (check-length-<= f what thing expected-length)
  (when (not (<= (bytes-length thing) expected-length))
    (raise (exn:fail:contract:libb2 (format "~a: expected ~a of length ~v, got length ~v"
                                            f what expected-length (bytes-length thing))
                                    (current-continuation-marks)))))
