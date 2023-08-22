TARGET=http

CFLAGS += $(EXTRA_CFLAGS) -Wall -g -O0
CFLAGS += -DMEM_POOL=1
CFLAGS += -DATOMIC_STACK_SPINLOCK=0
CFLAGS += -mcx16 -DHAS_128BIT_CAS=0
#CFLAGS += -fsanitize=address
LDFLAGS += -lpthread
#LDFLAGS += -static

OBJECTS = main.c log.c atomic_stack.c rbtree.c mem.c aio_thread.c net_thread.c dns.c http_header.c http_parser.c http_session.c

HFILES =

TARGET: $(HFILES) $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(HFILES) $(OBJECTS) $(LDFLAGS)

test:
	./$(TARGET)
clean:
	rm -f $(TARGET) *.o
	rm -f debug.log
	rm -f gmon.out
