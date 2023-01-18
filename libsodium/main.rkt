#lang racket/base
;;; SPDX-License-Identifier: ISC
;;; SPDX-FileCopyrightText: Copyright © 2012-2023 Tony Garnock-Jones <tonyg@leastfixedpoint.com>

(provide *sodium-version*
         *sodium-version-info*)

(provide (all-from-out "random.rkt"))
(provide (all-from-out "hash.rkt"))
(provide (all-from-out "scalarmult.rkt"))
(provide (all-from-out "box.rkt"))
(provide (all-from-out "stream.rkt"))
(provide (all-from-out "onetimeauth.rkt"))
(provide (all-from-out "auth.rkt"))
(provide (all-from-out "secretbox.rkt"))
(provide (all-from-out "sign.rkt"))
(provide (all-from-out "aead.rkt"))

(require "random.rkt")
(require "hash.rkt")
(require "scalarmult.rkt")
(require "box.rkt")
(require "stream.rkt")
(require "onetimeauth.rkt")
(require "auth.rkt")
(require "secretbox.rkt")
(require "sign.rkt")
(require "aead.rkt")

;;---------------------------------------------------------------------------

(require ffi/unsafe)
(require "ffi-lib.rkt")

(define-libsodium sodium_version_string (_fun -> _string))
(define-libsodium sodium_library_version_major (_fun -> _int))
(define-libsodium sodium_library_version_minor (_fun -> _int))
(define-libsodium sodium_library_minimal (_fun -> _int))

(define *sodium-version* (sodium_version_string))
(define *sodium-version-info* (list (list 'major (sodium_library_version_major))
                                    (list 'minor (sodium_library_version_minor))
                                    (list 'minimal (sodium_library_minimal))))
