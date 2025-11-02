CC = gcc
CFLAGS = -Wall -g
LDFLAGS =

all: mfc_c_test

mfc_c_test: mfc_c_test.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f mfc_c_test
