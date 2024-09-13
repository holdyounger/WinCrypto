/*
 * dcc2_tst.c  A 'very' simple OpenSSL primative only test app, showing the
 * MSCASH2 format.
 * Written June 24, 2011, Jim Fougeron.  Placed in public domain
 * This is a very slow, but easier to understand mscash2 hash computation program
 * It has been written 100% with oSSL primative functions (SHA1 and MD4).  It does
 * not use any hmac primatives.    This pbkdf2 'has' been reduced some, since we
 * know a 'little' info.  1. the key will always be smaller than SHA_DIGEST_LENGTH
 * thus we can remove an initial sha reduction.  2. we only use lower 128 bites, so
 * only xor the first 4 words, not first 5
 *
 * If the program is run with no params, then user=admin and pass=password is used
 * arguments -p=PASSWORD  and -u=USER can be used to change the pass / user
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include "openssl/sha.h"
#include "openssl/md4.h"

#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

 /*
  * This function is derived from IEEE Std 802.11-2004, Clause H.4.
  * The main construction is from PKCS#5 v2.0.  It is tweaked a little
  * to remove some code not needed for our SHA1-128 output.
  */
void pbkdf2(unsigned char key[], size_t key_len,
	unsigned char salt[], size_t salt_len,
	unsigned int rounds,
	unsigned char digest[])
{
	SHA_CTX ctx1, ctx2, tmp_ctx1, tmp_ctx2;
	unsigned char ipad[SHA_CBLOCK + 1], opad[SHA_CBLOCK + 1], tmp_hash[SHA_DIGEST_LENGTH];
	unsigned i, j;

	memset(ipad, 0x36, sizeof(ipad));
	memset(opad, 0x5C, sizeof(opad));

	for (i = 0; i < key_len; i++) {
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}

	SHA1_Init(&ctx1);
	SHA1_Init(&ctx2);

	SHA1_Update(&ctx1, ipad, SHA_CBLOCK);
	SHA1_Update(&ctx2, opad, SHA_CBLOCK);

	memcpy(&tmp_ctx1, &ctx1, sizeof(SHA_CTX));
	memcpy(&tmp_ctx2, &ctx2, sizeof(SHA_CTX));

	SHA1_Update(&ctx1, salt, salt_len);
	SHA1_Final(tmp_hash, &ctx1);

	SHA1_Update(&ctx2, tmp_hash, SHA_DIGEST_LENGTH);
	SHA1_Final(tmp_hash, &ctx2);

	memcpy(digest, tmp_hash, SHA_DIGEST_LENGTH);

	for (i = 1; i < rounds; i++)
	{
		memcpy(&ctx1, &tmp_ctx1, sizeof(SHA_CTX));
		memcpy(&ctx2, &tmp_ctx2, sizeof(SHA_CTX));

		SHA1_Update(&ctx1, tmp_hash, SHA_DIGEST_LENGTH);
		SHA1_Final(tmp_hash, &ctx1);

		SHA1_Update(&ctx2, tmp_hash, SHA_DIGEST_LENGTH);
		SHA1_Final(tmp_hash, &ctx2);

		for (j = 0; j < 4; j++)
			((unsigned int*)digest)[j] ^= ((unsigned int*)tmp_hash)[j];
	}
}

// simple 'to-unicode', adds null bytes. !WARNING! no overflow logic.
unsigned to_unicode(char* u16, char* a8) {
	unsigned cnt = strlen(a8);
	while (*a8) {
		*u16++ = *a8++;  *u16++ = 0;
	}
	return cnt << 1;
}

char hexdigit(int i) { // one hex digit
	if (i < 10) return i + '0';
	return (i - 10) + 'a';
}
char* to_hex(unsigned char* digest) {  // convert 16 byte digest to 32 byte hex
	static char buf[33];
	char* cp = buf;
	int i;
	for (i = 0; i < 16; ++i) {
		*cp++ = hexdigit(*digest >> 4); *cp++ = hexdigit(*digest++ & 0xF);
	}
	*cp = 0;
	return buf;
}

/*
 * usage:  dcc2_tst [-p=pass] [-u=username]
 */
int dcc2_tst(int argc, char** argv)
{
	// char* username = (char*)"shimingming", * password = (char*)"Admin@123";
	char* username = (char*)"administrator", * password = (char*)"Admin@2022";
	unsigned char username_lc[22], salt[44], pass_unicode[128 + 2], md4hash[16], digest[20];
	unsigned salt_len, pass_len;
	MD4_CTX ctx;
	int i;

	// see if -p= or -u= was used.  If so, then use them.
	for (i = 1; i < argc; ++i) {
		if (!strncmp(argv[i], "-p=", 3)) password = &argv[i][3];
		if (!strncmp(argv[i], "-u=", 3)) username = &argv[i][3];
	}

	// low case user name (the salt), and convert to unicode.
	strncpy((char*)username_lc, username, 21);
	username_lc[21] = 0;
	if (strlen(username) != strlen((char*)username_lc)) return !!printf("Error, the user name is longer than 21 bytes.  Aborting\n");
	salt_len = to_unicode((char*)salt, strlwr((char*)username_lc));

	// pasword to unicode
	pass_len = to_unicode((char*)pass_unicode, password);

	// now get NTLM of the password (MD4 of unicode)

	MD4_Init(&ctx);
	MD4_Update(&ctx, pass_unicode, pass_len);
	MD4_Final(md4hash, &ctx);
	// Now we have NTLM  md4Hash==NTLM of the password

	// Get DCC1.  That is MD4( NTLM . unicode(lc username) )
	MD4_Init(&ctx);
	MD4_Update(&ctx, md4hash, 16);
	MD4_Update(&ctx, salt, salt_len);
	MD4_Final(md4hash, &ctx);
	// now we have DCC1 (mscash) which is MD4 (MD4(unicode(pass)) . unicode(lc username))

	// we need to change the salt a little, before calling pbkdf2 (add a big endian 32 bit 1)
	memset(&salt[salt_len], 0, 4);
	salt[salt_len + 3] = 1;
	salt_len += 4;

	// Now compute DCC2
	pbkdf2(md4hash, 16, salt, salt_len, 10240, digest);

	// Ok, now output the hash:
	printf("%s:", username);
	printf("%$%s#%s:0:1:%s\n", username_lc, to_hex(digest), password);

	return 0;
}