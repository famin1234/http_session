TARGET=http

CFLAGS += $(EXTRA_CFLAGS) -Wall -g -O0
#CFLAGS += -fsanitize=address
LDFLAGS += -lpthread
#LDFLAGS += -static


OBJECTS = main.c rbtree.c mem.c log.c task_thread.c net_module.c epoll_module.c

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
