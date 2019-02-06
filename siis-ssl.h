/**********************************************************************

   File          : siis-ssl.h

   Description   : This is the openssl interface; it provides friendlier
                   wrappers on top of the openssl API

***********************************************************************/

/**********************************************************************
Copyright (c) 2006-2018 The Pennsylvania State University
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of The Pennsylvania State University nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
***********************************************************************/


/* Library use functions */
extern int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
		   int aad_len, unsigned char *key, unsigned char *iv,
		   unsigned char *ciphertext, unsigned char *tag);
extern int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
		   int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
		   unsigned char *plaintext);
extern void digest_message(const unsigned char *message, size_t message_len, 
		    unsigned char **digest, unsigned int *digest_len);
extern int hmac_message(unsigned char* msg, size_t mlen, unsigned char** val, size_t* vlen, 
			 unsigned char *key);
extern int rsa_encrypt(unsigned char *msg, unsigned int msgLen, unsigned char **encMsg, unsigned char **ek,
		       unsigned int *ekl, unsigned char **iv, unsigned int *ivl, EVP_PKEY *pubkey);
extern int rsa_decrypt(unsigned char *encMsg, unsigned int encMsgLen, unsigned char *ek, unsigned int ekl,
		       unsigned char *iv, unsigned int ivl, unsigned char **decMsg, EVP_PKEY *privkey); 
extern ENGINE *engine_init( void );
extern int engine_cleanup( ENGINE *eng );
extern int crypto_init( void );
extern int crypto_cleanup( void );
extern void handleErrors(void);
