CC = gcc
CFLAGS =-c -std=gnu11 -fstack-protector-all -fPIC
LDFLAGS = -Wl,-z,now -Wl,-z,relro #-pie

sources = tinypad.c pwnio.c
objects = $(sources:.c=.o)
solution= tinypad

.PHONY: clean
all: $(sources) $(solution)

$(solution): $(objects)
	$(CC) $(LDFLAGS) $(objects) -o $@
.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm $(objects) $(solution)
