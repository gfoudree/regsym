all: test.c
	gcc -funroll-all-loops -funroll-loops -fomit-frame-pointer -O0 test.c -o linear
