#include <unistd.h>
#include <signal.h>
#include "log.h"
#include "thread.h"
#include "http_session.h"

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
    threads_init();
    http_session_init("0.0.0.0", 8080);
    while (!stop) {
        usleep(100 * 1000);
    }
    threads_uninit();
    return 0;
}
