build:
	mkdir -p bin
	gcc -o bin/echo_server echo_server.c && chmod 755 bin/echo_server