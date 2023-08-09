#include "mem.h"
#include "net.h"
#include "aio.h"
#include "http_session.h"
#include "dns.h"
#include "log.h"

static struct net_thread_t *net_threads = NULL;
static struct aio_thread_t *aio_threads = NULL;
static int net_threads_num = 0;
static int aio_threads_num = 0;

static int net_threads_run(int num)
{
    struct conn_t *conn;
    net_socket_t sock;
    struct net_listen_t *nl;
    char str[64];
    int i;

    assert(net_threads_num == 0);
    net_threads_num = num;
    net_threads = mem_malloc(sizeof(struct net_thread_t) * net_threads_num);
    memset(net_threads, 0, sizeof(struct net_thread_t) * net_threads_num);
    for (i = 0; i < net_threads_num; i++) {
        snprintf(net_threads[i].name, sizeof(net_threads[i].name), "net[%d]", i);
        if (net_thread_init(&net_threads[i])) {
            LOG(LOG_ERROR, "%s net_thread_init error\n", net_threads[i].name);
            assert(0);
        }
    }
    list_for_each_entry(nl, &net_listen_list, node) {
        for (i = 0; i < net_threads_num; i++) {
            if (i == 0) {
                sock = socket(nl->conn_addr.addr.sa_family, SOCK_STREAM, IPPROTO_TCP);
                if (sock < 0) {
                    LOG(LOG_ERROR, "%s sock=%d %s error:%s\n", net_threads[i].name, sock, conn_addr_ntop(&nl->conn_addr, str, sizeof(str)), strerror(errno));
                    break;
                }
                if (net_listen(sock, &nl->conn_addr)) {
                    LOG(LOG_ERROR, "%s sock=%d %s listen error: %s\n", net_threads[i].name, sock, conn_addr_ntop(&nl->conn_addr, str, sizeof(str)), strerror(errno));
                    close(sock);
                    break;
                }
                LOG(LOG_INFO, "%s sock=%d %s listen ok\n", net_threads[i].name, sock, conn_addr_ntop(&nl->conn_addr, str, sizeof(str)));
            } else {
                sock = dup(sock);
                if (sock < 0) {
                    LOG(LOG_ERROR, "%s sock=%d %s listen dup error: %s\n", net_threads[i].name, sock, conn_addr_ntop(&nl->conn_addr, str, sizeof(str)), strerror(errno));
                    break;
                }
                LOG(LOG_INFO, "%s sock=%d %s listen dup ok\n", net_threads[i].name, sock, conn_addr_ntop(&nl->conn_addr, str, sizeof(str)));
            }
            conn = conn_alloc();
            conn->sock = sock;
            conn->peer_addr = nl->conn_addr;
            conn->net_thread = &net_threads[i];
            conn_nonblock(conn);
            conn->handle_read = nl->handle;
            conn->handle_write = NULL;
            conn->handle_timeout = conn_close;
            conn->data = NULL;
            conn_timer_set(conn, INT64_MAX - net_threads[i].time_current);
            conn_enable(conn, CONN_READ);
        }
    }
    for (i = 0; i < net_threads_num; i++) {
        if (pthread_create(&net_threads[i].tid, NULL, net_thread_loop, &net_threads[i])) {
            LOG(LOG_ERROR, "%s pthread_create error\n", net_threads[i].name);
            assert(0);
        }
    }
    return 0;
}

static void net_threads_signal_exit()
{
    int i;

    for (i = 0; i < net_threads_num; i++) {
        net_threads[i].exit = 1;
    }
}

static void net_threads_join()
{
    int i;

    for (i = 0; i < net_threads_num; i++) {
        pthread_join(net_threads[i].tid, NULL);
    }
    for (i = 0; i < net_threads_num; i++) {
        net_thread_clean(&net_threads[i]);
    }
    mem_free(net_threads);
    net_threads = NULL;
    net_threads_num = 0;
}

static int aio_threads_run(int num)
{
    int i;

    assert(aio_threads_num == 0);
    aio_threads_num = num;
    aio_threads = mem_malloc(sizeof(struct aio_thread_t) * aio_threads_num);
    memset(aio_threads, 0, sizeof(struct aio_thread_t) * aio_threads_num);
    for (i = 0; i < aio_threads_num; i++) {
        snprintf(aio_threads[i].name, sizeof(aio_threads[i].name), "aio[%d]", i);
        if (aio_thread_init(&aio_threads[i])) {
            LOG(LOG_ERROR, "%s aio_thread_init error\n", aio_threads[i].name);
            assert(0);
        }
    }
    for (i = 0; i < aio_threads_num; i++) {
        if (pthread_create(&aio_threads[i].tid, NULL, aio_thread_loop, &aio_threads[i])) {
            LOG(LOG_ERROR, "%s pthread_create error\n", aio_threads[i].name);
            assert(0);
        }
    }
    return 0;
}

static void aio_threads_signal_exit()
{
    int i;

    for (i = 0; i < aio_threads_num; i++) {
        aio_threads[i].exit = 1;
    }
    aio_thread_signal();
}

static int aio_threads_join()
{
    int i;

    for (i = 0; i < aio_threads_num; i++) {
        pthread_join(aio_threads[i].tid, NULL);
    }
    for (i = 0; i < aio_threads_num; i++) {
        aio_thread_clean(&aio_threads[i]);
    }
    mem_free(aio_threads);
    aio_threads = NULL;
    aio_threads_num = 0;
    return 0;
}

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
