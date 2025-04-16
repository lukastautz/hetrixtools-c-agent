default: libbearssl.a
	diet gcc -Os -O3 -static hetrixtools.c libbearssl.a -Wno-deprecated-declarations -o hetrixtools_agent
	elftrunc hetrixtools_agent hetrixtools_agent
libbearssl.a:
	git clone https://www.bearssl.org/git/BearSSL
	sh -c "cd BearSSL; make; cp build/libbearssl.a .."
