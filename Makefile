CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = bpfc

all: $(TARGET)

$(TARGET): bpfc.c
	$(CC) $(CFLAGS) -o $(TARGET) bpfc.c

clean:
	rm -f $(TARGET) output.bpf

