;;; -*- mode: scheme; coding: utf-8 -*-
;;;
;;; mcrypt.scm: mcrypt binding module
;;;
;;; Copyright (c) 2005-2008 Tatsuya BIZENN, All rights reserved.

(define-module org.visha.crypt.mcrypt
  (use srfi-11)
  (use math.mt-random)
  (use gauche.sequence)
  (use gauche.uvector)
  (use gauche.vport)
  (export <mcrypt>
	  make-mcrypt
	  open-input-decryption-port
	  open-output-encryption-port
	  call-with-input-decryption
	  call-with-output-encryption
	  with-input-decryption
	  with-output-encryption
	  encrypt
	  encrypt-string
	  decrypt
	  decrypt-string
	  mcrypt-module-open
	  mcrypt?
	  mcrypt-generic-init
	  mcrypt-generic-deinit
	  mcrypt-generic
	  mdecrypt-generic
	  mcrypt-block-mode?
	  mcrypt-block-algorithm?
	  mcrypt-block-size
	  mcrypt-key-size
	  mcrypt-supported-key-sizes
	  mcrypt-iv-size
	  mcrypt-needs-iv?
	  BLOWFISH
	  DES
	  3DES
	  3WAY
	  GOST
	  SAFER-SK64
	  SAFER-SK128
	  CAST-128
	  CAST-256
	  xTEA
	  RC2
	  TWOFISH
	  SAFER+
	  LOKI97
	  SERPENT
	  RIJNDAEL-128
	  RIJNDAEL-192
	  RIJNDAEL-256
	  AES-128
	  AES-192
	  AES-256
	  ENIGMA
	  ARCFOUR
	  WAKE
	  CBC
	  ECB
	  CFB
	  OFB
	  nOFB
	  STREAM
	  ))
(select-module org.visha.crypt.mcrypt)
(dynamic-load "mcrypt")

(define (make-mcrypt algo mode . args)
  (let-keywords* args
      ((algorithm-dir #f)
       (mode-dir #f))
    (mcrypt-module-open algo algorithm-dir mode mode-dir)))

(define-constant %*header* "RandomIV")
(define-constant %*header-size* (string-size %*header*))

(define (%make-random-iv size)
  (let ((vec (make-u8vector size))
	(m (make <mersenne-twister> :seed (sys-time))))
    (for-each-with-index (lambda (i e) (u8vector-set! vec i (mt-random-integer m 255)))
			 vec)
    vec))

(define (open-input-decryption-port src mcrypt . args)
  (let-keywords* args
      ((padding #f)
       (buffer-size 0)
       (owner? #t)
       (iv #f)
       (key #f))
    (when key
      (let1 iv (if iv iv (if (equal? %*header* (string-incomplete->complete (read-block %*header-size* src)))
			     (let1 iv (make-u8vector (mcrypt-iv-size mcrypt))
			       (read-block! iv src)
			       iv)
			     (error "Cannot read IV header.")))
	(mcrypt-generic-init mcrypt key iv)))
    (%open-input-decryption-port src mcrypt
				 (case padding
				   ((:standard) PADDING_STD)
				   ((:oneandzeros) PADDING_1_0s)
				   ((:space) PADDING_SPACE)
				   ((:null) PADDING_NULL)
				   (else PADDING_STD))
				 buffer-size owner?)))

(define (open-output-encryption-port sink mcrypt . args)
  (let-keywords* args
      ((padding #f)
       (buffer-size 0)
       (owner? #t)
       (iv #f)
       (key #f)
       (add-header? #f))
    (when key
      (let1 iv (if iv iv (%make-random-iv (mcrypt-iv-size mcrypt)))
	(mcrypt-generic-init mcrypt key iv)
	(when add-header?
	  (display %*header* sink)
	  (write-block iv sink))))
    (%open-output-encryption-port sink mcrypt
				  (case padding
				    ((:standard) PADDING_STD)
				    ((:oneandzeros) PADDING_1_0s)
				    ((:space) PADDING_SPACE)
				    ((:null) PADDING_NULL)
				    (else PADDING_STD))
				  buffer-size owner?)))

(define (call-with-input-decryption src mcrypt proc . args)
  (let1 in (apply open-input-decryption-port src mcrypt args)
    (with-error-handler (lambda (e) (close-input-port in) (raise e))
			(lambda () (begin0 (proc in) (close-input-port in))))))

(define (call-with-output-encryption sink mcrypt proc . args)
  (let1 out (apply open-output-encryption-port sink mcrypt args)
    (with-error-handler (lambda (e) (close-output-port out) (raise e))
			(lambda () (begin0 (proc out) (close-output-port out))))))

(define (with-input-decryption src mcrypt thunk . args)
  (let1 in (apply open-input-decryption-port src mcrypt args)
    (with-error-handler (lambda (e) (close-input-port in) (raise e))
			(lambda ()
			  (begin0
			    (with-input-from-port in thunk)
			    (close-input-port in))))))

(define (with-output-encryption sink mcrypt thunk . args)
  (let1 out (apply open-output-encryption-port sink mcrypt args)
    (with-error-handler (lambda (e) (close-output-port out) (raise e))
			(lambda ()
			  (begin0
			    (with-output-to-port out thunk)
			    (close-output-port out))))))

(define (decrypt mcrypt key . args)
  (apply call-with-input-decryption (current-input-port) mcrypt
	 (lambda (in) (copy-port in (current-output-port)))
	 :key key args))

(define (encrypt mcrypt key . args)
  (apply call-with-output-encryption (current-output-port) mcrypt
	 (lambda (out) (copy-port (current-input-port) out))
	 :key key args))

(define (decrypt-string mcrypt cipher-text key . args)
  (with-input-from-string cipher-text
    (lambda ()
      (with-output-to-string (cut apply decrypt mcrypt key args)))))

(define (encrypt-string mcrypt plain-text key . args)
  (with-input-from-string plain-text
    (lambda ()
      (with-output-to-string (cut apply encrypt mcrypt key args)))))

(provide "org/visha/crypt/mcrypt")
