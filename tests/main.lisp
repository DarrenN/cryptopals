(defpackage cryptopals/tests/main
  (:use :cl
        :cryptopals
        :rove))
(in-package :cryptopals/tests/main)

;; NOTE: To run this test file, execute `(asdf:test-system :cryptopals)' in your Lisp.

;; Set 1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Challenge 1
;;
;; Convert hex to base64
;; The string:
;; 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
;; Should produce:
;; SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

(deftest set1/challenge1
  (testing "hex to base64"
    (ok (equal
         (cryptopals/set1:hex-to-base64
          "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
         "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"))))

;; Challenge 2
;;
;; Fixed XOR
;; Write a function that takes two equal-length buffers and produces their XOR combination.
;; If your function works properly, then when you feed it the string:
;; 1c0111001f010100061a024b53535009181c
;; ... after hex decoding, and when XOR'd against:
;; 686974207468652062756c6c277320657965
;; ... should produce:
;; 746865206b696420646f6e277420706c6179

(deftest set1/challenge2
  (testing "fixed xor"
    (ok (equal
         (cryptopals/set1:fixed-xor
          "1c0111001f010100061a024b53535009181c"
          "686974207468652062756c6c277320657965")
         "746865206b696420646f6e277420706c6179"))))

;; Challenge 3

(deftest set1/challenge3
  (testing "single byte xor cipher"
    (ok (equal
         (cryptopals/set1:single-byte-xor-cipher "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
         '(23 88 "cooking mc's like a pound of bacon")))))
