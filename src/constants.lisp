(defpackage cryptopals/constants
  (:use :cl)
  (:import-from :serapeum #:dict :href)
  (:import-from :alexandria #:define-constant)
  (:export #:+english-letters+
           #:+english-occurance+
           #:+etaoin-shrdlu+))

(in-package :cryptopals/constants)

(define-constant +english-occurance+
  (dict
   "a" 8.2389258     "b" 1.5051398     "c" 2.8065007     "d" 4.2904556
   "e" 12.813865     "f" 2.2476217     "g" 2.0327458     "h" 6.1476691
   "i" 6.1476691     "j" 0.1543474     "k" 0.7787989     "l" 4.0604477
   "m" 2.4271893     "n" 6.8084376     "o" 7.5731132     "p" 1.9459884
   "q" 0.0958366     "r" 6.0397268     "s" 6.3827211     "t" 9.1357551
   "u" 2.7822893     "v" 0.9866131     "w" 2.3807842     "x" 0.1513210
   "y" 1.9913847     "z" 0.0746517)
  :test #'equalp)

(define-constant +english-letters+
  '("a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m" "n" "o" "p" "q" "r" "s"
    "t" "u" "v" "x" "y" "z")
  :test #'equalp)

(define-constant +etaoin-shrdlu+
  (dict
   "e" 1
   "t" 1
   "a" 1
   "o" 1
   "i" 1
   "n" 1
   "s" 1
   "h" 1
   "r" 1
   "d" 1
   "l" 1
   "u" 1
   " " 1)
  :test #'equalp)
