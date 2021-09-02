TARGETS=crack

all: $(TARGETS)


sha256.o: sha256.c sha256.h
	gcc -std=c99 -Wall -ggdb -Werror -c sha256.c

crack: crack.c sha256.o
	gcc $^ -o $@ -std=c99 -Wall -ggdb -lm

diffie: DiffieHellman.c
	gcc $^ -o $@ -std=c99 -Wall -ggdb -lm

diffies: DiffieHellmanServer.c
	gcc $^ -o $@ -std=c99 -Wall -ggdb -lm
