#include <unistd.h>
#include <signal.h>
#include "task_thread.h"
#include "log.h"

static volatile int stop = 0;

static void sig_int(int sig)
{
    stop = 1;
}

int main(int argc, char *argv[])
{
    if (signal(SIGINT, sig_int) == SIG_ERR) {
        LOG(LOG_ERROR, "regist SIGINT error\n");
        return -1;
    }
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        LOG(LOG_ERROR, "regist SIGPIPE error\n");
        return -1;
    }
    log_set_thread_name("main_0");
    //net_threads_create(1);
    task_threads_create(1);
    while (!stop) {
        usleep(10 * 1000);
    }
    //net_threads_exit();
    task_threads_exit();
    return 0;
}
