#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	FILE *fp = fopen("form.html", "r+");
	char *temp = NULL;
	size_t len = 0;
	ssize_t read;

	while((read = getline(&temp, &len, fp) != -1))
	{
		printf("%s", temp);
	}
	
	fclose(fp);
}
