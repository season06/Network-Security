#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#define HEADER \
	"<html>" \
	"<head>" \
		"<title>Choose File</title>" \
	"</head>" \
	"<body>" \

#define FOOTER \
	"</body>" \
	"</html>" \

int main()
{
	printf(HEADER);

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
	printf("%s", file_list);

	char BODY[200] = "	<h3>Choose one file:</h3>	\
						<form method=\"POST\" action=\"show\">	\
							<input type=\"text\" name=\"f\">	\
							<input type=\"submit\" value=\"submit\"> \
						</form>";

	printf("%s", BODY);

	printf(FOOTER);
}
