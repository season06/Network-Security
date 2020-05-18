#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <resolv.h>
#include <malloc.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define CA "key/ca.crt"
#define SERVER_CERT "key/server.crt"
#define SERVER_KEY	"key/server.key"
#define MAXBUF 1024

char buffer[MAXBUF];

void handle_socket(SSL*);
void runCgi(SSL*, char*, char*, char*);

int main(int argc , char *argv[])
{
	int sock_fd, len;
	char fileName[50] = "./server_file/";
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

/*----------- create TCP server socket -----------*/

	printf("server is running\n");

	struct sockaddr_in serverInfo;

	bzero(&serverInfo, sizeof(serverInfo));
	serverInfo.sin_family = AF_INET; // Ipv4
    serverInfo.sin_addr.s_addr = INADDR_ANY; // IP address
    serverInfo.sin_port = htons(8000);	// port

	// socket building
	if((sock_fd = socket(AF_INET , SOCK_STREAM , 0)) == -1)
		perror("socket error");

	// socket connection
	if(bind(sock_fd,(struct sockaddr *)&serverInfo,sizeof(serverInfo)) == -1)
	{
		perror("bind error");
		exit(-1);
	}

	// listen queue
	if(listen(sock_fd, 5) == -1)
	{
		perror("listen error");
		exit(-1);
	}

/*----------- wait for client -----------*/
	while(1)
	{
		struct sockaddr_in clientInfo;
		socklen_t len = sizeof(clientInfo);

		// wait for request from client
		int client_fd = accept(sock_fd, (struct sockaddr*)&clientInfo, &len);
		if(client_fd == -1)
		{
			perror("accept client socket error");
			exit(-1);
		}
		printf("Connection: %s, port: %d\n", inet_ntoa(clientInfo.sin_addr), ntohs(clientInfo.sin_port));

/*----------- create SSL structure -----------*/

        SSL *ssl = SSL_new(ctx);    // load ctx into new SSL
        SSL_set_fd(ssl, client_fd); // connect socket and SSL

/*------------- accept client ------------*/

        if (SSL_accept(ssl) == -1)
		{
			perror("SSL accept error\n");
			ERR_print_errors_fp(stderr);
			close(client_fd);
			break;
		}
/*------------- handshake finish -------------*/
		
		int pid = fork();
		if(pid < 0)
		{
			perror("fork error");
			exit(-1);
		}
		else
		{
			if(pid == 0)	// child process
			{
				close(sock_fd);
				handle_socket(ssl);
			}
			else			// parent process
			{
				close(client_fd);
			}
		}
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(client_fd);
	}

/*----------- close connect -----------*/

	close(sock_fd);
	SSL_CTX_free(ctx);
	
	return 0;
}

void handle_socket(SSL *ssl)
{
	// read request from client
	int ret = SSL_read(ssl, buffer, MAXBUF);
	if(ret == 0 || ret == -1)
	{
		perror("reed client error!");
		SSL_shutdown(ssl);
		SSL_free(ssl);
		exit(-1);
	}
	if(ret > 0 && ret < MAXBUF)
		buffer[ret] = 0;
	else
		buffer[0] = 0;

	// analysis buffer
	int i, j;
	char method[10], url[10];
	for(i = 0, j = 0; buffer[j] != ' '; i++, j++)
		method[i] = buffer[j];
	method[i] = '\0';

	while(buffer[j] == ' ' && j < sizeof(buffer))
		j++;

	for(i = 0; buffer[j] != ' '; i++, j++)
		url[i] = buffer[j];
	url[i] = '\0';

printf("method: %s\n", method);
printf("url: %s\n", url);

	// GET and POST
	char post_msg[100];
	if(strcmp(method, "GET") == 0 || strcmp(method, "get") == 0)
	{
		printf("GET!\n");
	}
	else if(strcmp(method, "POST") == 0 || strcmp(method, "post") == 0)
	{
		char *delim = ": \r\n";
		char *temp = strtok(buffer, delim);
		int n = 0;
		while(temp != NULL)
		{
			strcpy(post_msg, temp);
			temp = strtok(NULL, delim);
		}
		printf("POST!\n");
	}

	// router
	int cgi = 1;
	char router[30];
	if(strcmp(url, "/") == 0)
		strcpy(router, "./cgi_bin/home.cgi\0");
	else if(strcmp(url, "/show") == 0)
		strcpy(router, "./cgi_bin/show.cgi\0");
	else if(strcmp(url, "/copy") == 0)
	{
		char file_content[50] = "", ch;
		FILE *fp = fopen("./cgi_src/copyFile", "r");
		while((ch = fgetc(fp)) != EOF)
		{
			strncat(file_content, &ch, 1);
		}
		SSL_write(ssl, file_content, strlen(file_content));
		cgi = 0;
	}
	else
	{
		char error[] = "404 Not Found";
		SSL_write(ssl, error, strlen(error));
		cgi = 0;
	}

printf("router: %s\n", router);

	if(cgi)
		runCgi(ssl, router, method, post_msg);
}

void runCgi(SSL *ssl, char* router, char* method, char* post_msg)
{
	sprintf(buffer, "HTTP/1.1 200 OK\r\n\r\n");
	SSL_write(ssl, buffer, strlen(buffer));

	int cgiin[2], cgiout[2];
	pid_t cpid;
	int status;
	char c;

	if(pipe(cgiin) == -1 || pipe(cgiout) == -1) {
		perror("create pipe error\n");
		exit(-1);
	}

	cpid = fork();
	if(cpid < 0) {
		perror("fork error\n");
		exit(-1);
	}

	if(cpid == 0)	// child process
	{	
		printf("child process!\n");

		close(cgiin[1]);
		close(cgiout[0]);

		dup2(cgiin[0], STDIN_FILENO);
		dup2(cgiout[1], STDOUT_FILENO);

		close(cgiin[0]);
		close(cgiout[1]);

		execlp(router, router, NULL);
		exit(0);
	}
	else	// parant process
	{	
		printf("parent process!\n");
		
		close(cgiout[1]);
		close(cgiin[0]);

		write(cgiin[1], post_msg, strlen(post_msg));

		while(read(cgiout[0], &c, 1) > 0)
		{
			SSL_write(ssl, &c, 1);
		}

		close(cgiout[0]);
		close(cgiin[1]);

		waitpid(cpid, &status, 0);	
	}
}
