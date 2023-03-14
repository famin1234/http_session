#include "mem.h"
#include "net.h"
#include "aio.h"
#include "http_session.h"
#include "dns.h"
#include "log.h"

static void sig_int(int sig)
{
    net_threads_signal_exit();
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
    log_thread_name("main[0]");
    mem_pools_init();
    aio_init();
    net_init();
    dns_init();
    http_session_init();
    aio_threads_run(1);
    net_threads_run(1);
    net_threads_join();
    aio_threads_signal_exit();
    aio_threads_join();
    http_session_clean();
    dns_clean();
    net_clean();
    aio_clean();
    mem_pools_clean();
    return 0;
}
