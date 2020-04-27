all: webserver.c
	gcc -o server.out webserver.c
	gcc -o ./cgi_bin/view.cgi ./cgi_src/view.c
	gcc -o ./cgi_bin/insert.cgi ./cgi_src/insert.c
	gcc -o ./cgi_bin/form.cgi ./cgi_src/form.c
server: webserver.c
	gcc -o server.out webserver.c
view: view.c
	gcc -o ./cgi_bin/view.cgi ./cgi_src/view.c
insert: insert.c
	gcc -o ./cgi_bin/insert.cgi ./cgi_src/insert.c
form:
	gcc -o ./cgi_bin/form.cgi ./cgi_src/form.c
clean:
	rm -f server.out
	rm -f ./cgi_bin/view.cgi
	rm -f ./cgi_bin/insert.cgi
	rm -f ./cgi_bin/form.cgi
