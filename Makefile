CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lnetfilter_queue
TARGET = nfqnl_test
SRC = nfqnl_test.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
