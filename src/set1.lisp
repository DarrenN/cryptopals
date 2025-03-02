(defpackage cryptopals/set1
  (:use :cl)
  (:import-from :cl-base64)
  (:import-from :str :concat :downcase)
  (:local-nicknames (:i :iterate))
  (:export :hex-string-to-bytes
   :hex-to-base64
           :fixed-xor))

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
    (coerce result '(vector (unsigned-byte 8)))))

(defun hex-to-base64 (hex-string)
  "Convert a hex-string into bytes and encode them with base64"
  (base64:usb8-array-to-base64-string (hex-string-to-bytes hex-string)))

;;; Challenge 2
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun fixed-xor (hex-string-a hex-string-b)
  "Decode hex-string-a and hex-string-b into bytes and XOR them"
  (let* ((bytes-a (hex-string-to-bytes hex-string-a))
         (bytes-b (hex-string-to-bytes hex-string-b))
         (xord (i:iter (i:for i below (length bytes-a))
                 (i:collect
                     (format nil "~X"
                             (logxor (aref bytes-a i) (aref bytes-b i)))))))
    (downcase (apply #'concat xord))))
