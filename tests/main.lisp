(defpackage cryptopals/tests/main
  (:use :cl
        :cryptopals
        :rove))
(in-package :cryptopals/tests/main)

;; NOTE: To run this test file, execute `(asdf:test-system :cryptopals)' in your Lisp.

(deftest test-target-1
  (testing "should (= 1 1) to be true"
    (ok (= 1 1))))

;; Set 1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Challenge 1

(deftest day1
  (testing "hex to base64"
    (ok (equal
         (cryptopals/set1:hex-to-base64
          "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
         "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"))))
