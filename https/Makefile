all:
	gcc webserver.c -o webserver.out -L/usr/lib -lssl -lcrypto
	gcc -o ./cgi_bin/home.cgi ./cgi_src/home.c
	gcc -o ./cgi_bin/show.cgi ./cgi_src/show.c
webserver: webserver.c
	gcc webserver.c -o webserver.out -L/usr/lib -lssl -lcrypto
home: home.c
	gcc -o ./cgi_bin/home.cgi ./cgi_src/home.c
show: show.c
	gcc -o ./cgi_bin/show.cgi ./cgi_src/show.c
clean:
	rm -f webserver.out
	rm -f ./cgi_bin/home.cgi
	rm -f ./cgi_bin/show.cgi
