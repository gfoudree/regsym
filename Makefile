all: test.c
	gcc -fomit-frame-pointer -O0 test.c -o linear
