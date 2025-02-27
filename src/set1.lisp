(defpackage cryptopals/set1
  (:use :cl)
  (:import-from :cl-base64)
  (:export :hex-string-to-bytes
           :hex-to-base64))

(in-package :cryptopals/set1)

;;; Cryptopals Challenge Set 1
;;; https://www.cryptopals.com/sets/1

;;; Challenge 1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun hex-string-to-bytes (hex-string)
  "Converts a hexadecimal string into a vector of (unsigned-byte 8) values.
Assumes HEX-STRING contains an even number of hex digits."
  (let* ((len (length hex-string))
         (num-bytes (/ len 2))
         (result (make-array num-bytes :element-type '(unsigned-byte 8))))
    (loop for i from 0 below num-bytes do
      (let ((hex-pair (subseq hex-string (* i 2) (+ (* i 2) 2))))
        (setf (aref result i)
              (parse-integer hex-pair :radix 16))))
    result))

(defun hex-to-base64 (hex-string)
  "Convert a hex-string into bytes and encode them with base64"
  (base64:usb8-array-to-base64-string
   (coerce (hex-string-to-bytes hex-string) '(vector (unsigned-byte 8)))))
