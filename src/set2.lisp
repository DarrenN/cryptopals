(defpackage cryptopals/set2
  (:use :cl)
  (:import-from :cl-base64)
  (:import-from :ironclad)
  (:import-from :babel
                #:octets-to-string)
  (:import-from :alexandria
                #:hash-table-values)
  (:import-from :str
                #:concat
                #:downcase
                #:join
                #:lines)
  (:import-from :serapeum
                #:dict
                #:href
                #:href-default)
  (:import-from :cryptopals/constants
                #:+english-occurance+
                #:+english-letters+
                #:+etaoin-shrdlu+)
  (:import-from :uiop
                #:read-file-lines)
  (:local-nicknames (:i :iterate))
  (:export #:pkcs7-pad))

(in-package :cryptopals/set2)

;;; Challenge 9
;;; https://www.cryptopals.com/sets/2/challenges/9
;;;
;;; Implement PKCS#7 padding
;;; https://en.wikipedia.org/wiki/PKCS_7

(defun pkcs7-pad (input pad-length)
  "Pad the input with additional bytes to get to pad length. The padding bytes
should be the count of additional bytes needed to get to pad-length."
  (let* ((len (length input))
         (dif (if (< len pad-length)
                  (- pad-length len)
                  0)))
    (join ""
          (cons input
                (make-list dif :initial-element
                           (format nil "~2,'0X" dif))))))
