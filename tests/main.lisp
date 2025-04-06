(defpackage cryptopals/tests/main
  (:use :cl
        :cryptopals
        :rove)
  (:import-from :str
                #:trim))
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
;; https://www.cryptopals.com/sets/1/challenges/2
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
;; https://www.cryptopals.com/sets/1/challenges/3
;;
;; Single-byte XOR cipher
;; The hex encoded string: 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
;; ... has been XOR'd against a single character. Find the key, decrypt the message.

(deftest set1/challenge3
  (testing "single byte xor cipher"
    (ok (equal
         (cryptopals/set1:single-byte-xor-cipher "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
         '(23 88 "cooking mc's like a pound of bacon")))))

;; Challenge 4
;; https://www.cryptopals.com/sets/1/challenges/4
;;
;; One of the 60-character strings in this file has been encrypted by single-character XOR.

(deftest set1/challenge4
  (testing "Detect single-character XOR"
    (ok (equal
         (cryptopals/set1:xor-cipher-file #p"../data/4.txt")
         '(22 53 "now that the party is jumping
")))))

;; Challenge 5
;; https://www.cryptopals.com/sets/1/challenges/5
;;
;; Implement repeating-key XOR
;; Here is the opening stanza of an important work of the English language:
;;
;; Burning 'em, if you ain't quick and nimble
;; I go crazy when I hear a cymbal
;;
;; Encrypt it, under the key "ICE", using repeating-key XOR.
;;
;; It should come out to:
;;
;; 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
;; a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

(deftest set1/challenge5
  (testing "Implement repeating key XOR"
    (ok (equal
         (cryptopals/set1:repeating-key-xor "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal" :key "ICE")
         "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"))))

;; Challenge 6
;; https://www.cryptopals.com/sets/1/challenges/6
;;
;; Break repeating-key XOR
;; There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
;; Decrypt it.

(defvar *output6*
  "I'm back and I'm ringin' the bell
A rockin' on the mike while the fly girls yell
In ecstasy in the back of me
Well that's my DJ Deshay cuttin' all them Z's
Hittin' hard and the girlies goin' crazy
Vanilla's on the mike, man I'm not lazy.

I'm lettin' my drug kick in
It controls my mouth and I begin
To just let it flow, let my concepts go
My posse's to the side yellin', Go Vanilla Go!

Smooth 'cause that's the way I will be
And if you don't give a damn, then
Why you starin' at me
So get off 'cause I control the stage
There's no dissin' allowed
I'm in my own phase
The girlies sa y they love me and that is ok
And I can dance better than any kid n' play

Stage 2 -- Yea the one ya' wanna listen to
It's off my head so let the beat play through
So I can funk it up and make it sound good
1-2-3 Yo -- Knock on some wood
For good luck, I like my rhymes atrocious
Supercalafragilisticexpialidocious
I'm an effect and that you can bet
I can take a fly girl and make her wet.

I'm like Samson -- Samson to Delilah
There's no denyin', You can try to hang
But you'll keep tryin' to get my style
Over and over, practice makes perfect
But not if you're a loafer.

You'll get nowhere, no place, no time, no girls
Soon -- Oh my God, homebody, you probably eat
Spaghetti with a spoon! Come on and say it!

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino
Intoxicating so you stagger like a wino
So punks stop trying and girl stop cryin'
Vanilla Ice is sellin' and you people are buyin'
'Cause why the freaks are jockin' like Crazy Glue
Movin' and groovin' trying to sing along
All through the ghetto groovin' this here song
Now you're amazed by the VIP posse.

Steppin' so hard like a German Nazi
Startled by the bases hittin' ground
There's no trippin' on mine, I'm just gettin' down
Sparkamatic, I'm hangin' tight like a fanatic
You trapped me once and I thought that
You might have it
So step down and lend me your ear
'89 in my time! You, '90 is my year.

You're weakenin' fast, YO! and I can tell it
Your body's gettin' hot, so, so I can smell it
So don't be mad and don't be sad
'Cause the lyrics belong to ICE, You can call me Dad
You're pitchin' a fit, so step back and endure
Let the witch doctor, Ice, do the dance to cure
So come up close and don't be square
You wanna battle me -- Anytime, anywhere

You thought that I was weak, Boy, you're dead wrong
So come on, everybody and sing this song

Say -- Play that funky music Say, go white boy, go white boy go
play that funky music Go white boy, go white boy, go
Lay down and boogie and play that funky music till you die.

Play that funky music Come on, Come on, let me hear
Play that funky music white boy you say it, say it
Play that funky music A little louder now
Play that funky music, white boy Come on, Come on, Come on
Play that funky music
")

(deftest set1/challenge6
  (testing "Hamming distance"
    (ok (equal (cryptopals/set1:hamming-distance "this is a test" "wokka wokka!!!") 37)))

  (testing "breaking-reverse-xor"
    (ok (equal (str:collapse-whitespaces (cryptopals/set1:load-encrypted-file #p"../data/6.txt"))
               (str:collapse-whitespaces *output6*)))))
