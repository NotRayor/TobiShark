
rawsocket:rawsocket.o
	gcc -o rawsocket rawsocket.o

rawsocket.o:rawsocket.c
	gcc -c rawsocket.c
