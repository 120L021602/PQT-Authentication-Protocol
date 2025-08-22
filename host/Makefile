CC      = $(CROSS_COMPILE)gcc -lpthread
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

OBJS = main.o socket_zmq.o cafun.o socket_handle.o selfqueue.o

CFLAGS += -Wall -I../ta/include -I$(TEEC_EXPORT)/include -I./include -I../talib2/include -I../ta2/include -I./zeromq/include -I/home/kidds/liboqs_ta/liboqs-main/build/include

LDADD += -lteec -L$(TEEC_EXPORT)/lib  -L./zeromq/lib/ -lzmq  -L/home/kidds/liboqs_ta/liboqs-main/build/lib -loqs

BINARY = node1

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) -o $@ $^ $(LDADD)

*.o : *.c
	$(CC) $(CFLAGS) -c $< $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)
