(defpackage cryptopals/set1
  (:use :cl)
  (:import-from :cl-base64)
  (:import-from :babel
                #:octets-to-string)
  (:import-from :alexandria
                #:hash-table-values)
  (:import-from :str
                #:concat
                #:downcase
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
  (:export #:hex-string-to-bytes
           #:hex-to-base64
           #:fixed-xor
           #:single-byte-xor-cipher
           #:xor-cipher-file
           #:repeating-key-xor
           #:hamming-distance))

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
         (sc (score decs))
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

;;; Challenge 4
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun xor-cipher-file (f)
  "Try to find the line that has been encrypted with a single byte XOR cipher.
We do this by looping over the lines and pulling out the top scored candidate.
We then sort by score in descending order and return the top candidate."
  (let* ((ls (read-file-lines f))
         (cs (mapcar #'single-byte-xor-cipher ls)))
    (car (sort (copy-seq cs) #'> :key #'car))))


;;; Challenge 5
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Create circular lists which we use to conveniently rotate the key
;; https://stackoverflow.com/questions/16678371/circular-list-in-common-lisp

(defun circular (items)
  (setf (cdr (last items)) items))

(defclass circular ()
  ((items :initarg :items)))

(defmethod initialize-instance :after ((c circular) &rest initargs)
  (declare (ignorable initargs))
  (setf (slot-value c 'items) (circular (slot-value c 'items))))

(defmethod next-item ((c circular))
  (prog1 (first (slot-value c 'items))
    (setf (slot-value c 'items)
          (rest (slot-value c 'items)))))

(defun string-to-xord-hex (str rk)
  (i:iter (i:for s in-string str)
    (i:collect (format nil "~2,'0X" (logxor (char-int s) (next-item rk))))))

(defun repeating-key-xor (text &key key)
  "In repeating-key XOR, you'll sequentially apply each byte of the key (ex:
'ICE'); the first byte of plaintext will be XOR'd against I, the next C, the
next E, then I again for the 4th byte, and so on."
  (let* ((kb (i:iter (i:for s in-string key)
               (i:collect (char-int s))))
         (rk (make-instance 'circular :items kb)))
    (downcase (apply #'concat (string-to-xord-hex text rk)))))

;;; Challenge 6
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun string->binary (str)
  "Convert string into a list of bits. Since we're using ASCII we pad the bits
for each character to 7."
  (i:iter outer (i:for s in-string str)
    (i:iter (i:for c in-string (format nil "~7,'0B" (char-int s)))
      (i:in outer (i:collect (if (equal c #\1) 1 0))))))

(defun hamming-distance (a b)
  "Compute the difference between the bits of strings a and b."
  (count 1 (mapcar #'logxor
                   (string->binary a)
                   (string->binary b))))
