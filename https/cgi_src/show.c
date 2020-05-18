#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#define HEADER \
	"<!DOCTYPE html>" \
	"<html>" \
	"<head>" \
		"<title>FILE</title>" \
	"</head>" \
	"<body>" \

#define FOOTER \
	"</body>" \
	"</html>" \

int main()
{
	printf(HEADER);

	int unread, length;
	char *buffer, fileName[50] = "./server_file/", ch;
	FILE *fp;

	while(unread < 1)
	{
		if(ioctl(STDIN_FILENO, FIONREAD, &unread))
		{
			perror("ioctl");
			exit(-1);
		}
	}

	buffer = (char*)malloc(sizeof(char)*(unread+1));
	read(STDIN_FILENO, buffer, unread);

	char file[10] = "";
	strncpy(file, buffer+2, strlen(buffer)-2);
	strcat(fileName, file);

	if((fp = fopen(fileName, "r")) == NULL)
	{
		printf("<h2>No this file: %s</h2>", file);
	}
	else
	{
		printf("<h2>FileName:</h2> %s<br><br>", file);
		printf("<h2>File Content:</h2>");

		int f = open("./cgi_src/copyFile", O_WRONLY|O_CREAT, 0700);
		ftruncate(f, 0);
		while((ch = fgetc(fp)) != EOF)
		{
			printf("%c", ch);
			write(f, &ch, 1);
		}
		close(f);

		printf("<br><br><br>");
		printf("<a href=\"./copy\" download=\"%s\">Download File</a>", file);
	}
	fclose(fp);

	printf(FOOTER);
}
