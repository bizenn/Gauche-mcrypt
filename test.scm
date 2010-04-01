;;; -*- mode: scheme; coding: utf-8 -*-
;;;
;;; test.scm:
;;;
;;; Copyright (c) 2005-2008 Tatsuya BIZENN, All rights reserved.

(define (x-is-a? expect result)
  (is-a? result expect))
(define (not-equal? expect result)
  (not (equal? expect result)))
(define (string!=? expect result)
  (not (string=? expect result)))

(use gauche.sequence)
(use gauche.uvector)
(use gauche.test)
(test-start "org.visha.crypt.mcrypt")

(use org.visha.crypt.mcrypt)
(test-module 'org.visha.crypt.mcrypt)

(define *key* "hogehoge")
(define *iv*  (string->u8vector "$KJh#(}q"))

(let1 mcrypt (make-mcrypt BLOWFISH CBC)
  (test* "make-mcrypt: BLOWFISH CBC" <mcrypt> mcrypt x-is-a?)
  (test* "mcrypt?" #t (mcrypt? mcrypt) eq?)
  (test* "mcrypt-block-mode?" #t (mcrypt-block-mode? mcrypt) eq?)
  (test* "mcrypt-block-algorithm?" #t (mcrypt-block-algorithm? mcrypt) eq?)
  (let* ((iv-size (mcrypt-iv-size mcrypt))
	 (iv (make-u8vector iv-size))
	 (ptext "BlowfishBlowfish")
	 (buf (string->u8vector ptext)))
    (test* "mcrypt-block-size: blowfish/CBC" 8 (mcrypt-block-size mcrypt) =)
    (test* "mcrypt-key-size: blowfish/CBC" 56 (mcrypt-key-size mcrypt) =)
    (test* "mcrypt-supported-key-sizes: blowfish/CBC" '() (mcrypt-supported-key-sizes mcrypt) equal?)
    (test* "mcrypt-iv-size: blowfish/CBC" 8 iv-size =)
    (test* "mcrypt-needs-iv?: blowfish/CBC" #t (mcrypt-needs-iv? mcrypt) eq?)
    (test* "mcrypt-generic-init" (undefined) (mcrypt-generic-init mcrypt *key* iv) eq?)
    (test* "mcrypt-generic: status" (undefined) (mcrypt-generic mcrypt buf 0 (size-of buf)) eq?)
    (test* "mcrypt-generic: result" ptext (u8vector->string buf) string!=?)
    (test* "mcrypt-generic-deinit" (undefined) (mcrypt-generic-deinit mcrypt) eq?)
    (test* "mcrypt-generic-init: again" (undefined) (mcrypt-generic-init mcrypt *key* iv) eq?)
    (test* "mdecrypt-generic: status" (undefined) (mdecrypt-generic mcrypt buf 0 (size-of buf)) eq?)
    (test* "mdecrypt-generic: result" ptext (u8vector->string buf) string=?))
    (test* "mcrypt-generic-deinit: again" (undefined) (mcrypt-generic-deinit mcrypt) eq?))

(let1 mcrypt (make-mcrypt BLOWFISH CBC)
  (for-each (lambda (p)
	      (let1 c (encrypt-string mcrypt p *key* :iv *iv*)
		(test* #`"encrypt-string: \",p\" w/o header" p c string!=?)
		(test* #`"decrypt-string: \",p\" w/o header" p (decrypt-string mcrypt c *key* :iv *iv*)))
	      (let1 c (encrypt-string mcrypt p *key* :add-header? #t)
		(test* #`"encrypt-string: \",p\" w/ header" p c string!=?)
		(test* #`"decrypt-string: \",p\" w/ header" p (decrypt-string mcrypt c *key*))))
	    '("" "twofish" "blowfish" "twofishtwofish" "blowfishhsifwolb" "日本語文字列")))

(test-section "encryption/decryption port")
(let ((m (make-mcrypt BLOWFISH CBC))
      (ptexts '("" "B" "BLOWFISH" "BLOWFISH0" "BLOWFISH01234567"
		"ふがががもげげげむごごごごごごごごごごごごごごごごごごごごごごごごごごごぶ")))
  (for-each
   (lambda (ptext)
     (mcrypt-generic-init m *key* *iv*)
     (let1 ctext (call-with-output-string (lambda (out)
					    (let1 out (open-output-encryption-port out m)
					      (display ptext out)
					      (close-output-port out)
					      )))
       (test* "open-output-encryption-port w/o header" ptext ctext string!=?)
       (mcrypt-generic-init m *key* *iv*)
       (call-with-input-string ctext
	 (lambda (in)
	   (let1 in (open-input-decryption-port in m)
	     (test* "open-input-decryption-port w/o header"
		    ptext (with-output-to-string (lambda ()
						   (port-for-each display (lambda () (read-block 1024 in)))))
		    string=?)
	     )))
       ))
   ptexts)
  (for-each
   (lambda (p)
     (let1 ctext (call-with-output-string
		   (lambda (out)
		     (call-with-output-encryption out m
						  (lambda (out) (display p out))
						  :key *key* :iv *iv* :add-header? #t)))
       (test* "call-with-output-encryption: w/ header" p ctext string!=?)
       (call-with-input-string ctext
	 (lambda (in)
	   (test* "call-with-input-decryption: w/ header"
		  p
		  (call-with-input-decryption in m
					      (lambda (in)
						(with-output-to-string
						  (lambda () (port-for-each display (lambda () (read-block 1024 in))))))
					      :key *key*)
		  string=?)))))
   ptexts)
  (for-each
   (lambda (p)
     (let1 ctext (call-with-output-string
		   (lambda (out)
		     (with-output-encryption out m
					     (lambda () (display p))
					     :key *key* :iv *iv* :add-header? #t)))
       (test* "with-output-encryption: w/ header" p ctext string!=?)
       (call-with-input-string ctext
	 (lambda (in)
	   (test* "with-input-decryption: w/ header"
		  p
		  (with-input-decryption in m
					 (lambda ()
					   (with-output-to-string
					     (lambda () (port-for-each display (lambda () (read-block 1024))))))
					 :key *key*)
		  string=?)))))
   ptexts)
  )

(test-end)
