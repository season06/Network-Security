#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEADER \
	"<html>" \
	"<head>" \
		"<title>Repository</title>" \
	"</head>" \
	"<body>" \
		"<h2>" \

#define FOOTER \
		"</h2>" \
	"</body>" \
	"</html>" \

int main()
{
	FILE *fp = fopen("repository", "r+");
	char *temp = NULL;
	size_t len = 0;
	ssize_t read;

	printf(HEADER);

	while((read = getline(&temp, &len, fp) != -1))
	{
		printf("%s", temp);
		printf("<br>");
	}
	
	printf(FOOTER);

	fclose(fp);
}
