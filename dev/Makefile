TARGET=http

CFLAGS += $(EXTRA_CFLAGS) -Wall -g -O0
#CFLAGS += -fsanitize=address
LDFLAGS += -lpthread
#LDFLAGS += -static


OBJECTS = main.c rbtree.c mem.c log.c net.c net_epoll.c task_thread.c net_thread.c http_session.c http_header.c http_parser.c

HFILES =

TARGET: $(HFILES) $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(HFILES) $(OBJECTS) $(LDFLAGS)

test:
	./$(TARGET)
clean:
	rm -f $(TARGET) *.o
	rm -f debug.log
	rm -f gmon.out

#top -p `pgrep -x http` -H
