(defpackage cryptopals/tests/main
  (:use :cl
        :cryptopals
        :rove))
(in-package :cryptopals/tests/main)

;; NOTE: To run this test file, execute `(asdf:test-system :cryptopals)' in your Lisp.

(deftest test-target-1
  (testing "should (= 1 1) to be true"
    (ok (= 1 1))))
