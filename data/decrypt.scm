#!/usr/bin/env gosh
;;; -*- mode: scheme; coding: utf-8 -*-

(use rfc.base64)
(use rfc.md5)
(use file.util)
(use gauche.uvector)
(use gauche.charconv)
(use org.visha.crypt.mcrypt)

;; Compatibility with Crypt::CBC
(define-constant *IV* (string->u8vector "$KJh#(}q"))
(define-constant *KEY* (file->string "Key.txt"))
(define-constant *KEY-LENGTH* 56)
(define (regenerate-key original-key key-size)
  (let loop ((material (md5-digest-string original-key)))
    (if (>= (string-size material) key-size)
	(substring material 0 key-size)
	(loop (string-append material (md5-digest-string material))))))

(define (with-input-decryption-from-base64)
  (decrypt-string (make-mcrypt BLOWFISH CBC)
		  (with-output-to-string base64-decode)
		  (regenerate-key *KEY* *KEY-LENGTH*) :padding :space :iv *IV*))

(define (blowfish&base64-file->plain-text-string fname)
  (with-input-from-file fname
    (lambda ()
      (call-with-input-string (with-input-decryption-from-base64)
	(lambda (in)
	  (with-input-conversion in
	    (lambda ()
	      (call-with-output-string (cut copy-port (current-input-port) <>)))
	    :encoding "ISO-2022-JP"))))))

(define (blowfish&base64-file->plain-text-file infile outfile)
  (with-input-from-file infile
    (lambda ()
      (call-with-input-string (with-input-decryption-from-base64)
	(lambda (in)
	  (call-with-output-file outfile
	    (cut copy-port in <>)))))))

(define (main args)
  0)
