/*
 * uc_crypto.c
 *
 * 	Tests underconstrained symbolic execution with
 * 	Manticore in order to reproduce previous carry 
 * 	propagation bug in TweetNaCl as well as to verify
 * 	correctness in the current implementation.
*/

#include "tweetnacl.h"

/* Since we can't efficiently analyze static/shared libraries, we can 
 * instead make an empty entry point, but use Manticore to hook and jump
 * to different functions.
 */
int main() 
{

}
