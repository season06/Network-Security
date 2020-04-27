#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#define BUFFER_SIZE 1024

void handle_socket(int);
void runCgi(int, char*, char*, char*);

char buffer[BUFFER_SIZE];

int main(int argc , char *argv[])
{
	printf("server is running\n");
	// server infomation
	struct sockaddr_in serverInfo;

	serverInfo.sin_family = AF_INET; // Ipv4
    serverInfo.sin_addr.s_addr = INADDR_ANY; // IP address
    serverInfo.sin_port = htons(8000);	// port

	// socket building
	int sock_fd;
	if((sock_fd = socket(AF_INET , SOCK_STREAM , 0)) == -1)
		perror("socket error");

	// solve the problem -> bind error: Address already in use
	int on = 1;
	if((setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0)
	{
		perror("setsockopt error");
		exit(-1);
	}

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

	while(1)
	{
		struct sockaddr_in clientInfo;
		socklen_t clientLen = sizeof(clientInfo);

		// wait for request from client
		int client_fd = accept(sock_fd, (struct sockaddr*)&clientInfo, &clientLen);
		if(client_fd == -1)
		{
			perror("accept client socket error");
			exit(-1);
		}
		
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
				handle_socket(client_fd);
			}
			else			// parent process
			{
				close(client_fd);
			}
		}
	}
	close(sock_fd);
	exit(0);
}

void handle_socket(int client_fd)
{
	// read request from client
	int ret = read(client_fd, buffer, BUFFER_SIZE);
	if(ret == 0 || ret == -1)
	{
		perror("read client error!");
		exit(-1);
	}
	if(ret > 0 && ret < BUFFER_SIZE)
		buffer[ret] = 0;
	else
		buffer[0] = 0;

printf("%s", buffer);

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
	int cgi = 1;
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
	char router[30];
	if(strcmp(url, "/") == 0 || strcmp(url, "/view") == 0)
		strcpy(router, "./cgi_bin/view.cgi\0");
	else if(strcmp(url, "/insert") == 0)
		strcpy(router, "./cgi_bin/form.cgi\0");
	else if(strcmp(url, "/show") == 0)
		strcpy(router, "./cgi_bin/insert.cgi\0");
	else
	{
		char error[] = "404 Not Found";
		write(client_fd, "404 Not Found", strlen(error));
		cgi = 0;
	}

printf("router: %s\n", router);

	if(cgi)
		runCgi(client_fd, router, method, post_msg);
}

void runCgi(int client_fd, char* router, char* method, char* post_msg)
{
	sprintf(buffer, "HTTP/1.1 200 OK\r\n\r\n");
	write(client_fd, buffer, strlen(buffer));

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
		close(client_fd);
		exit(-1);
	}

	// child process
	if(cpid == 0) {	
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
	// parant process
	else {	
		printf("parent process!\n");
		
		close(cgiout[1]);
		close(cgiin[0]);

		write(cgiin[1], post_msg, strlen(post_msg));

		while(read(cgiout[0], &c, 1) > 0)
		{
			write(client_fd, &c, 1);
		}

		close(cgiout[0]);
		close(cgiin[1]);

		waitpid(cpid, &status, 0);	
	}
}
