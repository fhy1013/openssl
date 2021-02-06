CC=g++

BIN = ../bin

INCLUDE = -I../inc

CFLAGS = -Wall -g

# LIBFLAGS = -L../lib -lssl -lcrypto -lpthread
LIBFLAGS = -L../lib -lcrypto -lpthread

SRCS = $(wildcard *.cpp)
OBJS = $(patsubst %.cpp,%.o,$(SRCS))

TARGET = run

ALL:$(OBJS)
	$(CC) -o $(BIN)/$(TARGET) $(OBJS) $(LIBFLAGS) $(CFLAGS)

%.o:%.cpp
	$(CC) -c $(CFLAGS) $(INCLUDE) $< -o $@

clean:
	rm -f $(OBJS)
	rm -f $(BIN)/$(TARGET)
