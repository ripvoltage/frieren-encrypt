CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lcrypto
TARGET  = fencrypt

SRCS = main.c file_encrypt.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c file_encrypt.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
