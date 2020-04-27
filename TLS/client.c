#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <fcntl.h>
#include <resolv.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define CA "key/ca.crt"
#define CLIENT_CERT "key/client.crt"
#define CLIENT_KEY	"key/client.key"
#define MAXBUF 2048

int main(int argc, char *argv[])
{
	int server, len, fd, size;
	char buffer[MAXBUF];
    const SSL_METHOD *method;
    SSL_CTX *ctx;
	SSL *ssl;

/*------------ initialize client CTX ------------*/

	SSL_library_init();

    OpenSSL_add_all_algorithms(); 

    SSL_load_error_strings();

	// create new context with TLS method
    method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);

    if(ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
 
/*----------- load certification -----------*/

	// set CA
	if (SSL_CTX_load_verify_locations(ctx, CA, NULL) <= 0)
	{
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    // set the certificate
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    // set the private key
    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    // verify if server certificate and private-key match
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(-1);
    }

	// wait for server certificate
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

/*----------- client connect to server -----------*/

	struct sockaddr_in addr;

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);

	if((server = socket(AF_INET , SOCK_STREAM , 0)) == -1)
	{
		perror("socket error");
		exit(-1);
	}

	if(inet_aton("127.0.0.1", (struct in_addr *) &addr.sin_addr.s_addr) == 0)
	{
		perror("addr error");
		exit(-1);
	}

	if(connect(server, (struct sockaddr *) &addr, sizeof(addr)) != 0)
	{
		perror("connect error");
		exit(-1);
	}
	printf("server connected success\n");

/*----------- create SSL structure -----------*/

    ssl = SSL_new(ctx);    	// load ctx into new SSL
    SSL_set_fd(ssl, server); // connect socket and SSL

/*----------- get server information -----------*/

    if (SSL_connect(ssl) == -1)     // connect to server
	{
		printf("SSL connect error\n");
		ERR_print_errors_fp(stderr);
	}

	/*-------- get server certificate --------*/
	else
	{
		printf("Connected With %s Encryption\n", SSL_get_cipher(ssl));
		X509 *cert;
		char *str;

		cert = SSL_get_peer_certificate(ssl);
		if (cert != NULL)
		{
			printf("Server Certificates Information:\n");

			str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
			printf("Certificates: %s\n", str);
			free(str);

			str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
			printf("Issuer: %s\n", str);

			long ve = SSL_get_verify_result(ssl);
			if(SSL_get_verify_result(ssl) == X509_V_OK)
				printf("Server Verification Succeeded.\n");
			else {
				printf("Server Verification Failed. Error code: %ld\n", ve);
				exit(-1);
			}

			free(str);
			X509_free(cert);
		}
		else
			printf("No Certificates from server.\n");
	}

/*---------------------- handshake finish ----------------------*/
	/*-------- get file_list from server --------*/

	bzero(buffer, MAXBUF + 1);
	len = SSL_read(ssl, buffer, sizeof(buffer));

	if(len < 0)
	{
		printf("receive file list fail\n");
		exit(-1);
	}
	
	printf("----- Choose one file -----\n");
	printf("%s\n", buffer);

	/*-------- send file_name to server --------*/

	printf("Input a file: ");
	char fileName[10] = "";
	scanf("%s", fileName);

	len = SSL_write(ssl, fileName, strlen(fileName));
	if (len < 0)
		printf("filename send fail\n");

	/*------- get file_content from server -------*/

	bzero(buffer, MAXBUF + 1);
	len = SSL_read(ssl, buffer, sizeof(buffer));
	if(len < 0)
		printf("get file_content fail\n");

	if(strcmp(buffer, "No this file") == 0)
		printf("No this file\n");
	else
	{
		/*------- build an empty file -------*/

		char new_file[100] = "./client_file/";
		if((fd = open(strcat(new_file, buffer), O_CREAT | O_TRUNC | O_RDWR, 0666)) < 0)
		{
			perror("open file error");
			exit(-1);
		}

		/*------- write the file_content -------*/

		while(1)
		{
			bzero(buffer, MAXBUF + 1);
			len = SSL_read(ssl, buffer, sizeof(buffer));
			if(len == 0)
			{
				printf("Receive File Success!\n\n");
				break;
			}
			else if(len < 0)
			{
				printf("receive message fail\n");
				exit(-1);
			}
			if(write(fd, buffer, len) < 0)
			{
				perror("SSL write error");
				exit(-1);
			}
		}
	}

/*----------- close connect -----------*/

	close(fd);
	SSL_shutdown(ssl);
	SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);

    return 0;
}
