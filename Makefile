CC = gcc
CFLAGS = -Wall -I./src -I/usr/local/opt/libpcap/include
LDFLAGS = -L/usr/local/opt/libpcap/lib -lpcap
TARGET = bin/toy-tcpip
SRCDIR = src
TESTDIR = tests
OBJDIR = obj

# Source files
SRCS = $(SRCDIR)/raw_socket_device.c $(TESTDIR)/raw_socket_main.c
OBJS = $(OBJDIR)/raw_socket_device.o $(OBJDIR)/raw_socket_main.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: $(TESTDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	sudo $(TARGET)

clean:
	rm -rf $(TARGET) $(OBJS)

.PHONY: all run clean