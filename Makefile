CC = gcc
CFLAGS = -g -I/usr/local/include
LDFLAGS = -L/usr/local/lib -Wl,-z,wxneeded
LIBS = -lunicorn -pthread

SRCS = main.c periph.c
OBJS = $(SRCS:.c=.o)

.PHONY: clean

main: clean $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-rm -f main $(OBJS)
