CC = gcc
CFLAGS = -std=c99 -Wall -ggdb -Werror
OBJ = crack.o guess.o sha256.o

.o%: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

crack: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

dh: dh.o
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean

clean:
	rm -f crack
	rm -f dh
	rm -f $(OBJ)
	rm -f dh.o
