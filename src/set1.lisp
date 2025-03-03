(defpackage cryptopals/set1
  (:use :cl)
  (:import-from :cl-base64)
  (:import-from :babel
                #:octets-to-string)
  (:import-from :alexandria
                #:hash-table-values)
  (:import-from :str
                #:concat
                #:downcase)
  (:import-from :serapeum
                #:dict
                #:href
                #:href-default)
  (:import-from :cryptopals/constants
                #:+english-occurance+
                #:+english-letters+
                #:+etaoin-shrdlu+)
  (:local-nicknames (:i :iterate))
  (:export #:hex-string-to-bytes
           #:hex-to-base64
           #:fixed-xor
           #:single-byte-xor-cipher))

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

;;; Challenge 3
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun get-char-frequency (cs)
  "Count the frequency of each char in the sequence in a hash table"
  (i:iter
    (i:with counter = (dict))
    (i:for c in cs)
    (i:reducing c by (lambda (accum s)
                       (if (href accum s)
                           (setf (href accum s) (+ 1 (href accum s)))
                           (setf (href accum s) 1))
                       accum) initial-value counter)))

; (single-byte-xor-cipher "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

(defun get-fitting-quotient (decs freq)
  "Check letter occurances and create a fitting quotient of letters in the
decrypted text against letter frequencies in english"
  (let* ((len (length decs))
         (dist-text (i:iter (i:for (k v) in-hashtable +english-occurance+)
                      (i:collect
                          `(,v ,(float (/ (* (href-default 0 freq k) 100) len)) ,k))))
         (len-dist (length dist-text)))
    (/ (i:iter (i:for z in dist-text)
         (i:sum (abs (- (car z) (cadr z)))))
       len-dist)))

(defun score (decs)
  "Count ETAOIN SHRDLU + Spaces to score a decrypted list of chars"
  (i:iter (i:for d in decs)
    (i:sum (if (href +etaoin-shrdlu+ d) 1 0))))

(defun decrypt-single-byte-xor (bs x)
  "loop over the bytes and xor them against x. We return a list of
(fitting-quotient x string) which we can use to try and find the
best solution."
  (let* ((decs (i:iter (i:for b in-vector bs)
                 (i:collect
                     (downcase (format nil "~C" (code-char (logxor b x)))))))
         ;(freq (get-char-frequency decs))
         (sc (score decs))
         ;(quot (get-fitting-quotient decs freq))
         )
    `(,sc ,x ,(apply #'concat decs))))

(defun single-byte-xor-cipher (hex-string)
  "Try to find the best decrypted text. Convert the hex-string to bytes and loop
over it with a single byte key in the range of 0,255, which is xor'd against
each byte in the list. We sort by fitting quotient which is generated for each
entry, and take the top 5 candidates."
  (let* ((bytes (hex-string-to-bytes hex-string))
         (decs (i:iter (i:for i from 0 below 256)
                 (i:collect (decrypt-single-byte-xor bytes i)))))
    (car
     (sort (copy-seq decs) #'> :key #'car))))
