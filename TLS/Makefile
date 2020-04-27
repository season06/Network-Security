all:
	gcc server.c -o server.out -L/usr/lib -lssl -lcrypto
	gcc client.c -o client.out -L/usr/lib -lssl -lcrypto
server:
	gcc server.c -o server.out -L/usr/lib -lssl -lcrypto
client:
	gcc client.c -o client.out -L/usr/lib -lssl -lcrypto
clean:
	rm server.out client.out
