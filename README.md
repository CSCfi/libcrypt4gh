# Library for Crypt4GH

`libcrypt4gh` is a C library supporting the [GA4GH file encryption format](http://samtools.github.io/hts-specs/crypt4gh.pdf).


# Installation

	autoreconf
	./configure
	make
	make install

# Documentation

Todo using external tools, or myself serving files on github.io?

# Implementation

We use [libsodium](https://github.com/jedisct1/libsodium) for the underlying implementation of Chacha20+Poly1305.  
Libsodium was assessed and shown to be [a secure, high-quality library that meets its stated usability and efficiency goals](https://www.privateinternetaccess.com/blog/libsodium-v1-0-12-and-v1-0-13-security-assessment/).


