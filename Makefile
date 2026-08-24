CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = bpf_compiler

all: $(TARGET)

$(TARGET): compiler.c
	$(CC) $(CFLAGS) -o $(TARGET) compiler.c

clean:
	rm -f $(TARGET) output.bpf

