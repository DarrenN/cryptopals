(defpackage cryptopals/set1
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
           #:hamming-distance
           #:challenge-6
           #:challenge-7
           #:challenge-8))

(in-package :cryptopals/set1)

;;; Run the tests: (asdf:test-system :cryptopals)

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
         (sc (score decs)))
    `(,sc ,x ,(apply #'concat decs))))

(defun single-byte-xor-cipher (input)
  "Try to find the best decrypted text. Convert the hex-string to bytes and loop
over it with a single byte key in the range of 0,255, which is xor'd against
each byte in the list. We sort by fitting quotient which is generated for each
entry, and take the top 5 candidates."
  (let* ((bytes (if (stringp input)
                    (hex-string-to-bytes input)
                    input))
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

;; There's a file. It's been base64'd after being encrypted with repeating-key
;; XOR. Decrypt it.
;; https://www.cryptopals.com/sets/1/challenges/6

(defparameter *min-keysize* 2)
(defparameter *max-keysize* 40)
(defparameter *input-file-6* #p"../data/6.txt")

(defun string->binary (str)
  "Convert string into a list of bits. Since we're using ASCII we pad the bits
for each character to 7."
  (i:iter outer (i:for s in-string str)
    (i:iter (i:for c in-string (format nil "~7,'0B" (char-int s)))
      (i:in outer (i:collect (if (equal c #\1) 1 0))))))

(defun string->bytes (str)
  "Convert string into a list of bits. Since we're using ASCII we pad the bits
for each character to 7."
  (i:iter (i:for s in-string str)
    (i:collect (char-int s))))

(defun bytes->binary (bs)
  "Convert bytes into a list of bits. Since we're using ASCII we pad the bits
for each character to 7."
  (i:iter outer (i:for b in-vector bs)
    (i:iter (i:for c in-string (format nil "~7,'0B" b))
      (i:in outer (i:collect (if (equal c #\1) 1 0))))))

(defun hamming-distance (a b)
  "Compute the difference between the bits of strings a and b."
  (count 1 (mapcar #'logxor
                   (if (stringp a) (string->binary a) (bytes->binary a))
                   (if (stringp b) (string->binary b) (bytes->binary b)))))

(defun score-keysize (size bs)
  "To find the correct keysize we average the distance of MAX KEYSIZE blocks."
  (let* ((ds (i:iter (i:for n from 0 to (* *max-keysize* size) by size)
               (i:collect
                   (hamming-distance
                    (subseq bs n (+ n size))
                    (subseq bs (+ n size) (+ n (* 2 size)))))))
         (avg (/ (apply #'+ ds) (length ds)))
         (norm (float (/ avg size))))
    `(,norm ,(float avg) ,size)))

(defun seq->blocks (seq blocksize)
  "Convert a list into a list of lists of blocksize length. The final sublist
may be shorter than blocksize."
  (let* ((len (length seq))
         (num-bytes (/ len blocksize)))
    (i:iter (i:for i from 0 below num-bytes)
      (i:collect
          (subseq
           seq
           (* i blocksize)
           (let ((end (+ (* i blocksize) blocksize)))
             (if (>= end len) len end)))))))

(defun transpose-blocks (blocks blocksize)
  "Takes a list of blocks (vectors) and blocksize and makes a block that is the
first byte of every block, and a block that is the second byte of every block,
and so on."
  (let ((tbs (make-list blocksize)))
    (i:iter outer (i:for b in blocks)
      (i:iter (i:for i from 0 below blocksize)
        (when (< i (length b))
          (setf (nth i tbs) (cons (aref b i) (nth i tbs))))))
    (mapcar #'nreverse tbs)))

(defun challenge-6 (p)
  "Load a file encrypted with a rotating key XOR cipher, find the key, and
decrypt it. This requires moving through many intermediary steps.
TODO: There's way too much conversion from strings -> bytes -> vectors, etc."
  (let* ((bs (base64:base64-string-to-usb8-array (uiop:read-file-string p)))
         (ks (sort (i:iter (i:for n from *min-keysize* to *max-keysize*)
                     (i:collect (score-keysize n bs))) #'< :key #'car))
         (sizes (mapcar (lambda (k) (nth 2 k))
                        (sort (copy-seq ks) #'< :key #'car)))
         (blocks (seq->blocks bs (car sizes)))
         (transposed (transpose-blocks blocks (car sizes)))
         (xord (mapcar
                (lambda (b)
                  (single-byte-xor-cipher (coerce b '(vector (unsigned-byte 8)))))
                transposed))
         (key (coerce (mapcar (lambda (x) (code-char (nth 1 x))) xord) 'string))
         (decoded (hex-string-to-bytes
                   (repeating-key-xor
                    (base64:base64-string-to-string (uiop:read-file-string p))
                    :key key))))
    (coerce
     (i:iter (i:for b in-vector decoded)
       (i:collect (code-char b))) 'string)))

;;; Challenge 7
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; The Base64-encoded content in a file has been encrypted via AES-128 in ECB
;; mode under the key "YELLOW SUBMARINE". Decrypt it. You know the key,
;; after all

(defparameter *input-file-7* #p"../data/7.txt")

(defun decrypt-aes-128-ecb-base64 (base64-ciphertext key-string)
  "Decrypts a BASE64-CIPHERTEXT string using AES-128-ECB with KEY-STRING (ASCII)."
  (let* ((key (ironclad:ascii-string-to-byte-array key-string))
         (ciphertext (cl-base64:base64-string-to-usb8-array base64-ciphertext))
         (cipher (ironclad:make-cipher :aes :mode :ecb :key key :padding :pkcs7)))
    (ironclad:decrypt-message cipher ciphertext)))


(defun challenge-7 (filepath key)
  (coerce
   (map 'list #'code-char
        (decrypt-aes-128-ecb-base64 (uiop:read-file-string filepath) key))
   'string))

;;; Challenge 8
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; In this file are a bunch of hex-encoded ciphertexts.
;; One of them has been encrypted with ECB.
;; Detect it.

;; convert each ciphertext into a list of 16 byte blocks and see if they repeat?

(defparameter *input-file-8* #p"../data/8.txt")

(defun challenge-8 (filepath)
  "Break each line of ciphertext into 16 byte blocks and look for dupes."
  (let ((ls (uiop:read-file-lines filepath))
        (seen (make-hash-table :test #'equal)))
    (car
     (i:iter outer (i:for l in ls)
       (i:for j upfrom 1)
       (i:iter (i:for block in
                      (seq->blocks l 16))
         (if (gethash block seen)
             (i:in outer (i:adjoining (format nil "line: ~a ciphertext: ~a" j l) test #'equal))
             (setf (gethash block seen) t)))))))

