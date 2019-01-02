/*
 * uc_crypto.c
 *
 * 	Tests underconstrained symbolic execution with
 * 	Manticore in order to reproduce previous carry 
 * 	propagation bug in TweetNaCl as well as to verify
 * 	correctness in the current implementation.
 *
 *  	Compile with:
 *  	  $ gcc -m32 -static -I. uc_crypto.c -o uc_crypto
*/

#include "vuln_tweetnacl.h"
#include <unistd.h>
#include <stdlib.h>

/* Since we can't efficiently analyze static/shared libraries, we can 
 * instead make an empty entry point, but use Manticore to hook and jump
 * to different functions.
 */
int main() 
{
	unsigned char n[32], r[32];

	size_t len;
	len = read(STDIN_FILENO, n, 32);
	if (len < 0) abort();

	crypto_scalarmult_base(r, n);
	return 0;
}
