#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <resolv.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define CA "key/ca.crt"
#define SERVER_CERT "key/server.crt"
#define SERVER_KEY	"key/server.key"
#define MAXBUF 2048

int main(int argc, char *argv[])
{
	int sock_fd, len, fd;
	char fileName[50] = "./server_file/";
	char buffer[MAXBUF];
    const SSL_METHOD *method;
    SSL_CTX *ctx;

/*---------initialize server CTX ---------*/

	SSL_library_init();

    OpenSSL_add_all_algorithms();

    SSL_load_error_strings();

	// create new context with TLS method
    method = TLSv1_2_server_method();
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
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    // set the private key
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
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

	// wait for client certificate
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

/*----------- create TCP server socket -----------*/

	printf("server is running\n");

	struct sockaddr_in serverInfo;

	bzero(&serverInfo, sizeof(serverInfo));
	serverInfo.sin_family = PF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(8080);

	// socket building
	if((sock_fd = socket(PF_INET , SOCK_STREAM , 0)) == -1)
	{
		perror("socket error");
		exit(-1);
	}
	// socket connection
	if(bind(sock_fd,(struct sockaddr *)&serverInfo,sizeof(serverInfo)) == -1)
	{
		perror("bind error");
		exit(-1);
	}
	// listen queue
	if(listen(sock_fd, 20) == -1)
	{
		perror("listen error");
		exit(-1);
	}

/*----------- wait to client -----------*/
    while(1)
    {
        struct sockaddr_in clientInfo;
        socklen_t len = sizeof(clientInfo);
        int client_fd = accept(sock_fd, (struct sockaddr*)&clientInfo, &len);
		if(client_fd == -1)
		{
			perror("accept client socket error");
			exit(-1);
		}
        printf("Connection: %s: %d\n", inet_ntoa(clientInfo.sin_addr), ntohs(clientInfo.sin_port));

/*----------- create SSL structure -----------*/

        SSL *ssl = SSL_new(ctx);    // load ctx into new SSL
        SSL_set_fd(ssl, client_fd); // connect socket and SSL

/*-------- get client infromation --------*/

	/*----- verify certification from client -----*/

        if (SSL_accept(ssl) == -1) // accept client
		{
			perror("SSL accept error\n");
			ERR_print_errors_fp(stderr);
			close(client_fd);
		}
	/*----------- get client certificate -----------*/
		else
		{
			printf("Connected With %s Encryption\n", SSL_get_cipher(ssl));
			X509 *cert;
			char *str;

			cert = SSL_get_peer_certificate(ssl);
			if (cert != NULL)
			{
				printf("Client Certificates Information:\n");

				str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
				printf("Certificates: %s\n", str);
				free(str);

				str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
				printf("Issuer: %s\n", str);

				long ve = SSL_get_verify_result(ssl);
				if(SSL_get_verify_result(ssl) == X509_V_OK)
					printf("Client Verification Succeeded.\n\n");
				else {
					printf("Client Verification Failed. Error code: %ld\n", ve);
					exit(-1);
				}

				free(str);
				X509_free(cert);
			}
			else
				printf("No Certificates from client.\n");
		}

/*---------------------- handshake finish ----------------------*/
	/*------- send file_list to client -------*/

		struct dirent *de; // Pointer for directory entry
		DIR *dr = opendir("./server_file");
		char file_list[200] = "";

		if (dr == NULL)  // opendir returns NULL if couldn't open directory 
		{ 
			printf("There have no file in server directory");
			strcat(file_list, "There have no file in server directory");
		}

		while ((de = readdir(dr)) != NULL) 
		{
			if(de->d_name[0] == '.')
				continue;
			strcat(file_list, de->d_name);
			strcat(file_list, "  ");
		}

		closedir(dr);

		len = SSL_write(ssl, file_list, strlen(file_list));
		if (len < 0)
			printf("file_list send fail\n");

	/*------ get file_name from client, open file ------*/

		bzero(buffer, MAXBUF + 1);
		len = SSL_read(ssl, buffer, sizeof(buffer));

		char fileName[50] = "./server_file/", sendFile[50] = "";
		strcat(fileName, buffer);

		if((fd = open(fileName, O_RDONLY, 0666)) < 0)
		{
			strcat(sendFile, "No this file");
		}
		else
		{
			printf("Open File: %s\n", fileName);
			for(int i=0, j=0; i<=strlen(fileName); i++)
			{
				if(fileName[i] == '/')
				{
					j = 0;
					continue;
				}
				else
				{
					sendFile[j] = fileName[i];
					j++;
				}
			}
		}
		len = SSL_write(ssl, sendFile, strlen(sendFile));
		if (len < 0)
			printf("file send fail\n");

	/*----------- send file_content to client -----------*/

		bzero(buffer, MAXBUF + 1);
		int size = 0;
		size = read(fd, buffer, sizeof(buffer));

		if(size < 0)
		{
			perror("read error");
			//exit(-1);
		}
		else
		{
			len = SSL_write(ssl, buffer, size);
			if (len < 0)
				printf("file send fail\n");
			printf("Send File To Client Success\n\n");
		}
		bzero(buffer, MAXBUF);	

/*----------- close connect -----------*/

		close(fd);
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(client_fd);
    }
    close(sock_fd);
    SSL_CTX_free(ctx);

    return 0;
}
