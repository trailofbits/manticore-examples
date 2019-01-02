CC	= gcc
CFLAGS	= -g -static
COMPILE	= uc_crypto.c 

all:
	$(CC) $(CFLAGS) -I. *.c -o uc_crypto

clean:
	rm -rf mcore_*
	rm -rf __pycache__/
	rm uc_crypto
