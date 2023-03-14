TARGET=http

CFLAGS += $(EXTRA_CFLAGS) -Wall -g -O0
CFLAGS += -DMEM_POOL=1
CFLAGS += -DATOMIC_STACK_SPINLOCK=0
CFLAGS += -mcx16 -DHAS_128BIT_CAS=0
#CFLAGS += -fsanitize=address
LDFLAGS += -lpthread
#LDFLAGS += -static

OBJECTS = rbtree.c log.c md5.c atomic_stack.c mem.c hash.c net.c aio.c dns.c http_parser.c http_header.c http_session.c main.c

HFILES =

TARGET: $(HFILES) $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(HFILES) $(OBJECTS) $(LDFLAGS)

test:
	./$(TARGET)
clean:
	rm -f $(TARGET) *.o
	rm -f debug.log
	rm -f gmon.out
