#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <error.h>
#include <sys/ioctl.h>

#define HEADER \
	"<html>" \
	"<head>" \
		"<title>Repository - Insert</title>" \
	"</head>" \
	"<body>" \
		"<h2>" \

#define FOOTER \
		"</h2>" \
	"</body>" \
	"</html>" \

int main()
{
	int unread, length;
	char *buf;

	while(unread < 1)
	{
		if(ioctl(STDIN_FILENO, FIONREAD, &unread))
		{
			perror("ioctl");
			exit(-1);
		}
	}

	buf = (char*)malloc(sizeof(char)*(unread+1));
	read(STDIN_FILENO, buf, unread);

	printf(HEADER);

	int ck = 0;
	for(int i=0; buf[i] != '\0'; i++)
	{
		printf("%c", buf[i]);
		if(ck)
		{
			FILE *fp = fopen("repository", "a");
			fprintf(fp, "%c", buf[i]);
			fclose(fp);
		}
		if(buf[i]=='=')
			ck=1;
	}
	FILE *fp = fopen("repository", "a");
	fprintf(fp, "\n");
	fclose(fp);

	printf("\n\n\n<p>insert success!!</p>");
	printf(FOOTER);
}
