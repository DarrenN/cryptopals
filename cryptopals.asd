(defsystem "cryptopals"
  :version "0.0.1"
  :author "DarrenN"
  :license "BSD"
  :depends-on (:ironclad
               :babel
               :uiop
               :cl-base64
               :iterate
               :str
               :serapeum)
  :components ((:module "src"
                :components
                ((:file "main")
                 (:file "constants")
                 (:file "set1")
                 (:file "set2"))))
  :description "Cryptopals Cryptography Challenge"
  :in-order-to ((test-op (test-op "cryptopals/tests"))))

(defsystem "cryptopals/tests"
  :author "DarrenN"
  :license "BSD"
  :depends-on ("cryptopals"
               "rove")
  :components ((:module "tests"
                :components
                ((:file "main"))))
  :description "Test system for cryptopals"
  :perform (test-op (op c) (symbol-call :rove :run c)))
