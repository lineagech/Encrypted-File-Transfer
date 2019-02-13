/***********************************************************************

   File          : transfer.c

   Description   : This file contains functions for securing transfering
                   files from client to server.

   Last Modified : 2018

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

/* Include Files */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

/* OpenSSL Include Files */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

/* Project Include Files */
#include "siis-util.h"
#include "siis-network.h"
#include "siis-ssl.h"
#include "transfer.h"


/* Functional Prototypes */

/**********************************************************************

    Function    : make_req_struct
    Description : build structure for request from input
    Inputs      : rptr - point to request struct - to be created
                  filename - filename
                  cmd - command string (small integer value)
                  type - - command type (small integer value)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int make_req_struct( struct rm_cmd **rptr, char *filename, char *cmd, char *type )
{
	struct rm_cmd *r;
	int rsize;
	int len; 

	assert(rptr != 0);
	assert(filename != 0);
	len = strlen( filename );

	rsize = sizeof(struct rm_cmd) + len;
	*rptr = r = (struct rm_cmd *) malloc( rsize );
	memset( r, 0, rsize );
	
	r->len = len;
	memcpy( r->fname, filename, r->len );  
	r->cmd = atoi( cmd );
	r->type = atoi( type );

	return 0;
}


/**********************************************************************

    Function    : get_message
    Description : receive data from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int get_message( int sock, ProtoMessageHdr *hdr, char *block )
{
	/* Read the message header */
	recv_data( sock, (char *)hdr, sizeof(ProtoMessageHdr), 
		   sizeof(ProtoMessageHdr) );
	hdr->length = ntohs(hdr->length);
	assert( hdr->length<MAX_BLOCK_SIZE );
	hdr->msgtype = ntohs( hdr->msgtype );
	if ( hdr->length > 0 )
		return( recv_data( sock, block, hdr->length, hdr->length ) );
	return( 0 );
}

/**********************************************************************

    Function    : wait_message
    Description : wait for specific message type from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
                  my - the message to wait for
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int wait_message( int sock, ProtoMessageHdr *hdr, 
                 char *block, ProtoMessageType mt )
{
	/* Wait for init message */
	int ret = get_message( sock, hdr, block );
	if ( hdr->msgtype != mt )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "Server unable to process message type [%d != %d]\n", 
			 hdr->msgtype, mt );
		errorMessage( msg );
		exit( -1 );
	}

	/* Return succesfully */
	return( ret );
}

/**********************************************************************

    Function    : send_message
    Description : send data over the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to send
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int send_message( int sock, ProtoMessageHdr *hdr, char *block )
{
     int real_len = 0;

     /* Convert to the network format */
     real_len = hdr->length;
     hdr->msgtype = htons( hdr->msgtype );
     hdr->length = htons( hdr->length );
     if ( block == NULL )
          return( send_data( sock, (char *)hdr, sizeof(hdr) ) );
     else 
          return( send_data(sock, (char *)hdr, sizeof(hdr)) ||
                  send_data(sock, block, real_len) );
}

/**********************************************************************

    Function    : encrypt_message
    Description : Get message encrypted (by encrypt) and put ciphertext 
                   and metadata for decryption into buffer
    Inputs      : plaintext - message
                : plaintext_len - size of message
                : key - symmetric key
                : buffer - place to put the initialization vector, 
                  ciphertext, and tag for decryption on other end
                : len - length of the buffer after message is set 
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int encrypt_message( unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key, 
		     unsigned char *buffer, unsigned int *len )
{
    // randomly generate an iv, encrypt the plaintext using the
    // key, and the final buffer starts with the iv, the ciphertext, and
    // the tag; the tag is for integrity checking

    /* Fill in your code here */
    int clen = 0;
    int plen;
    unsigned char* p_buffer;
    unsigned char* iv; // 16-bytes
    unsigned char* ciphertext;
    unsigned char* tag;
    
    iv = (unsigned char*)malloc( IVSIZE );
    ciphertext = (unsigned char*)malloc( plaintext_len );
    tag = (unsigned char*)malloc( TAGSIZE );
    if( generate_pseudorandom_bytes(iv, IVSIZE) )
    {
        errorMessage("generate iv randomly failed");
        return -1;
    }
    
    clen = encrypt( plaintext, plaintext_len, 
                    (unsigned char*)NULL, 0, 
                    key, iv, ciphertext, tag );
  
#if 0
    {
        unsigned char* plaintext_d;
        
        printf("iv is: \n");
        BIO_dump_fp(stdout, (const char*)iv, (int)IVSIZE);

        printf("tag is: \n");
        BIO_dump_fp(stdout, (const char*)tag, (int)TAGSIZE);
        
        printf("Encrypted text is: \n");
        BIO_dump_fp(stdout, (const char*)ciphertext, (int)clen);

        /* perform decrypt */
	    plaintext_d = (unsigned char *)malloc( clen+TAGSIZE );
	    memset( plaintext_d, 0, clen+TAGSIZE ); 
	    plen = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, 
		           tag, key, iv, plaintext_d );
	    assert( plen > 0 );

	    /* Show the decrypted text */
	    printf("Decrypted text is: \n");
    	BIO_dump_fp (stdout, (const char *)plaintext_d, (int)plen);
    }
#endif
    *len = 0;
    p_buffer = buffer;
    memcpy(p_buffer, iv, IVSIZE);
    *len += IVSIZE;

    p_buffer += IVSIZE;
    memcpy(p_buffer, ciphertext, clen);
    *len += clen;

    p_buffer += clen;
    memcpy(p_buffer, tag, TAGSIZE);
    *len += TAGSIZE;

    free(iv);
    free(ciphertext);
    free(tag);

    return 0;
}


/**********************************************************************

    Function    : decrypt_message
    Description : Recover plaintext from ciphertext (by decrypt)
                   using metadata from buffer
    Inputs      : buffer - initialization vector, ciphertext, and metadata 
                  in format set by encrypt_message
                : len - length of buffer containing ciphertext and metadata
                : key - symmetric key
                : plaintext - place to put decrypted message
                : plaintext_len - size of decrypted message
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int decrypt_message( unsigned char *buffer, unsigned int len, unsigned char *key, 
		     unsigned char *plaintext, unsigned int *plaintext_len )
{
    /* Fill in your code here */
    int clen;
    int plen;
    unsigned char* iv;
    unsigned char* ciphertext;
    unsigned char* tag;
    
    iv = (unsigned char*) malloc( IVSIZE );
    tag = (unsigned char*) malloc( TAGSIZE );
    clen = (len-TAGSIZE)-IVSIZE;
    ciphertext = (unsigned char*) malloc( clen );
    
    memcpy(iv, buffer, IVSIZE);
    memcpy(tag, buffer+len-TAGSIZE, TAGSIZE);
    memcpy(ciphertext, buffer+IVSIZE, clen);

#if 0
    printf("\n\ndecrypt_message:\n");
    printf("iv is: \n");
    BIO_dump_fp(stdout, (const char*)iv, (int)IVSIZE);

    printf("tag is: \n");
    BIO_dump_fp(stdout, (const char*)tag, (int)TAGSIZE);
        
    printf("Encrypted text is: \n");
    BIO_dump_fp(stdout, (const char*)ciphertext, (int)clen);
#endif

    /* perform decrypt */
	plaintext = (unsigned char *)malloc( clen+TAGSIZE );
	memset( plaintext, 0, clen+TAGSIZE ); 
	plen = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, 
	                tag, key, iv, plaintext );
    if( plen < 0 )
    {
        errorMessage("decrypt meesage failed");
        return -1;
    }
    *plaintext_len = plen;
    //assert( plen > 0 );

	/* Show the decrypted text */
	printf("Decrypted text is: \n");
    BIO_dump_fp (stdout, (const char *)plaintext, (int)plen);
  

    free(iv);
    free(tag);
    free(ciphertext);

    return 0;
}

/**********************************************************************

    Function    : generate_pseudorandom_bytes
    Description : Generate pseudorandom bytes using OpenSSL PRNG 
    Inputs      : buffer - buffer to fill
                  size - number of bytes to get
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int generate_pseudorandom_bytes(unsigned char *buffer, unsigned int size)
{
    /* Fill in your code here */
    static int initialized = 0;
    int rc;
    unsigned int err;
    RAND_METHOD* rm = RAND_get_rand_method();
    
    //if( rm == RAND_SSLeay())
    //{
    //    printf("Using default generator()\n");
    //}
    if( !initialized )
    {
        RAND_poll();
        initialized = 1;
    }
    rc = RAND_bytes(buffer, size);
    err = ERR_get_error();
    if( rc != 1 )
    {
        errorMessage("RAND_bytes failed");
        return -1;
    }
    return 0;
}


/**********************************************************************

    Function    : save_key
    Description : Save key of size keysize to file fname
    Inputs      : fname - file name
                  key - pointer to buffer that holds the key
                  keysize - size of the key
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

void save_key(const char *fname, unsigned char *key, unsigned int keysize) {

    /* Fill in your code here */
    int err;
    FILE* fp;
    size_t file_size;
    struct stat* file_stat;
    
    file_stat = (struct stat*) malloc(sizeof(struct stat));
    assert( file_stat != NULL );

    err = stat( fname, file_stat );
    if( !err ) {
        errorMessage("save_key: file already exists");
    }
    else {
        size_t st;
        fp = fopen(fname, "w");
        assert(fp);
        st = fwrite(key, 1, keysize, fp);
        if( st != keysize )
        {
            errorMessage("save_key: fwrite is not successful");
        }   
        fclose(fp);
    }    
}

/**********************************************************************

    Function    : load_key
    Description : Load key of size keysize from file fname
    Inputs      : fname - file name that holds the key
                  key - pointer to buffer (should be allocated by the
                  caller of load_key)
                  keysize - size of the key
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

void load_key(const char *fname, unsigned char *key, unsigned int keysize) {

    /* Fill in your code here */
    int err;
    FILE* fp;
    size_t file_size;  
    struct stat* fstat;

    fstat = (struct stat*) malloc(sizeof(struct stat));
    assert( fstat != NULL );
    
    err = stat(fname, fstat);
    if( err )
    {
        errorMessage("load_key: file not exist");
    }
    else if( fstat->st_size == 0 )
    {
        errorMessage("load_key: file is empty");
    }
    else {
        size_t st;
        fp = fopen(fname, "r");
        assert(fp != NULL);
        st = fread(key, 1, keysize, fp);
        if( st != keysize )
        {
            errorMessage("load_key: fwrite is not successful");
        }
        close(fp);
    }
}



/* 

  CLIENT FUNCTIONS 

*/


/**********************************************************************

    Function    : transfer_file
    Description : transfer the entire file over the wire
    Inputs      : r - rm_cmd describing what to transfer and do
                  fname - the name of the file
                  sock - the socket
                  key - the cipher to encrypt the data with
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int transfer_file( struct rm_cmd *r, char *fname, int sock, 
		   unsigned char *key )
{
	/* Local variables */
	int readBytes = 1, totalBytes = 0, fh;
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];

	/* Read the next block */
	if ( (fh=open(fname, O_RDONLY, 0)) == -1 )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "failure opening file [%.64s]\n", fname );
		errorMessage( msg );
		exit( -1 );
	}

	/* Send the command */
	hdr.msgtype = FILE_XFER_INIT;
	hdr.length = sizeof(struct rm_cmd) + r->len;
	send_message( sock, &hdr, (char *)r );

	/* Start transferring data */
	while ( (r->cmd == CMD_CREATE) && (readBytes != 0) )
	{
		/* Read the next block */
		if ( (readBytes=read( fh, block, BLOCKSIZE )) == -1 )
		{
			/* Complain, explain, and exit */
			errorMessage( "failed read on data file.\n" );
			exit( -1 );
		}
		
		/* A little bookkeeping */
		totalBytes += readBytes;
		printf( "Reading %10d bytes ...\n", totalBytes );

		/* Send data if needed */
		if ( readBytes > 0 ) 
		{
#ifdef DEBUG
			printf("Block is:\n");
			BIO_dump_fp (stdout, (const char *)block, readBytes);
#endif

			/* Encrypt block and send */
            /* Fill in your code here */
            unsigned char buffer[IVSIZE+BLOCKSIZE+TAGSIZE];
		    unsigned int len = 0;
            encrypt_message( (unsigned char*)block, (unsigned int)readBytes, key, buffer, &len );

            hdr.msgtype = FILE_XFER_BLOCK;
            hdr.length = len;
            send_message( sock, &hdr, (char*)buffer );
        }
	}

	/* Send the ack, wait for server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );
	wait_message( sock, &hdr, block, EXIT );

	/* Clean up the file, return successfully */
	close( fh );
	return( 0 );
}


/**********************************************************************

    Function    : client_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : r - cmd describing what to transfer and do
                  fname - filename of the file to transfer
                  address - address of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int client_secure_transfer( struct rm_cmd *r, char *fname, char *address ) 
{
	/* Local variables */
	unsigned char key[KEYSIZE];
	int sock;

    // load encryption key
    load_key("./enckey", key, KEYSIZE);

	sock = connect_client( address );
	// symmetric key crypto for file transfer
	transfer_file( r, fname, sock, key );
	// Done
	close( sock );

	/* Return successfully */
	return( 0 );
}

/* 

  SERVER FUNCTIONS 

*/

/**********************************************************************

    Function    : test_aes
    Description : test the aes encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_aes( )
{
	int rc = 0;
	unsigned char *key;
	unsigned char *ciphertext, *tag;
	unsigned char *plaintext;
	unsigned char *iv = (unsigned char *)"0123456789012345";
	int clen = 0, plen = 0;
	char msg[] = "Help me, Mr. Wizard!";
	unsigned int plaintext_len = strlen(msg);

	printf("*** Test AES encrypt and decrypt. ***\n");

	/* make key */
	key= (unsigned char *)malloc( KEYSIZE );
	/* demonstrate with fixed key - don't do this in real systems */
	memcpy( key, "ABCDEFGH_IJKLMNOabcdefgh_ijklmno", KEYSIZE );  
	assert( rc == 0 );

	/* perform encrypt */
	ciphertext = (unsigned char *)malloc( plaintext_len );
	tag = (unsigned char *)malloc( TAGSIZE );
	clen = encrypt( (unsigned char *) msg, plaintext_len, (unsigned char *)NULL, 0, key, iv, ciphertext, tag);
	assert(( clen > 0 ) && ( clen <= plaintext_len ));

	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, clen);
	
	printf("Tag is:\n");
	BIO_dump_fp (stdout, (const char *)tag, TAGSIZE);

	/* perform decrypt */
	plaintext = (unsigned char *)malloc( clen+TAGSIZE );
	memset( plaintext, 0, clen+TAGSIZE ); 
	plen = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, 
		       tag, key, iv, plaintext );
	assert( plen > 0 );

	/* Show the decrypted text */
#if DEBUG
	printf("Decrypted text is: \n");
	BIO_dump_fp (stdout, (const char *)plaintext, (int)plen);
#endif
	
	printf("Msg: %s\n", plaintext );
#if 1
    { 
        printf("\n");
        printf("\n");
        unsigned char* buffer = malloc(IVSIZE+clen+TAGSIZE);
        unsigned int len;
        encrypt_message(plaintext, plaintext_len, key, buffer, &len );
        decrypt_message( buffer, len, key, plaintext, &plaintext_len );
    }
#endif
	return 0;
}

/**********************************************************************

    Function    : receive_file
    Description : receive a file over the wire
    Inputs      : sock - the socket to receive the file over
                  key - the AES key used to encrypt the traffic
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

#define FILE_PREFIX "./shared/"

int receive_file( int sock, unsigned char *key ) 
{
	/* Local variables */
	unsigned long totalBytes = 0;
	int done = 0, fh = 0;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	struct rm_cmd *r = NULL;
	char block[MAX_BLOCK_SIZE];
	unsigned char plaintext[MAX_BLOCK_SIZE+TAGSIZE];
	char *fname = NULL;
	int rc = 0;

	/* clear */
	bzero(block, MAX_BLOCK_SIZE);

	/* Receive the init message */
	wait_message( sock, &hdr, block, FILE_XFER_INIT );

	/* set command structure */
	struct rm_cmd *tmp = (struct rm_cmd *)block;
	unsigned int len = tmp->len;
	r = (struct rm_cmd *)malloc( sizeof(struct rm_cmd) + len );
	r->cmd = tmp->cmd, r->type = tmp->type, r->len = len;
	memcpy( r->fname, tmp->fname, len );

	/* open file */
	if ( r->type == TYP_DATA_SHARED ) {
		unsigned int size = r->len + strlen(FILE_PREFIX) + 1;
		fname = (char *)malloc( size );
		snprintf( fname, size, "%s%.*s", FILE_PREFIX, (int) r->len, r->fname );
		if ( (fh=open( fname, O_WRONLY|O_CREAT, 0700)) > 0 );
		else assert( 0 );

	}
	else assert( 0 );

	/* read the file data, if it's a create */ 
	if ( r->cmd == CMD_CREATE ) {
		/* Repeat until the file is transferred */
		printf( "Receiving file [%s] ..\n", fname );
		while (!done)
		{
			/* Wait message, then check length */
			get_message( sock, &hdr, block );
			if ( hdr.msgtype == EXIT ) {
				done = 1;
				break;
			}
			else
			{
#if DEBUG
                          printf("Received Block (%u bytes) is:\n", hdr.length);
                          BIO_dump_fp (stdout, (const char *)block, hdr.length);
#endif

                          /* Write the data file information */
                          rc = decrypt_message( (unsigned char *)block, hdr.length, key, 
                                                plaintext, &outbytes );
                          assert( rc  == 0 );
                          write( fh, plaintext, outbytes );

#if DEBUG
                          printf("Decrypted Block is:\n");
                          BIO_dump_fp (stdout, (const char *)plaintext, outbytes);
#endif

                          totalBytes += outbytes;
                          printf( "Received/written %ld bytes ...\n", totalBytes );
			}
		}
		printf( "Total bytes [%ld].\n", totalBytes );
		/* Clean up the file, return successfully */
		close( fh );
	}
	else {
		printf( "Server: illegal command %d\n", r->cmd );
		//	     exit( -1 );
	}

	/* Server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );

	return( 0 );
}

/**********************************************************************

    Function    : server_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : key - the encryption key
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int server_secure_transfer(unsigned char *key)
{
	/* Local variables */
	int server, errored, newsock;
	fd_set readfds;

	/* initialize */
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();

	// Test AES symmetric key encryption
#ifdef DEBUG
	test_aes();
#endif

	/* Connect the server/setup */
	server = server_connect();
	errored = 0;

    // load encryption key
    load_key("./enckey", key, KEYSIZE);

	/* Repeat until the socket is closed */
	while ( !errored )
	{
		FD_ZERO( &readfds );
		FD_SET( server, &readfds );
		if ( select(server+1, &readfds, NULL, NULL, NULL) < 1 )
		{
			/* Complain, explain, and exit */
			char msg[128];
			sprintf( msg, "failure selecting server connection [%.64s]\n",
				 strerror(errno) );
			errorMessage( msg );
			errored = 1;
		}
		else
		{
			/* Accept the connect, receive the file, and return */
			if ( (newsock = server_accept(server)) != -1 )
			{
				/* receive file, shutdown */
				receive_file( newsock, key );
				close( newsock );
			}
			else
			{
				/* Complain, explain, and exit */
				char msg[128];
				sprintf( msg, "failure accepting connection [%.64s]\n", 
					 strerror(errno) );
				errorMessage( msg );
				errored = 1;
			}
		}
	}

	/* Return successfully */
	return( 0 );
}

