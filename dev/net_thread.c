#include "mem.h"
#include "log.h"
#include "net_thread.h"

struct net_thread_t *net_threads = NULL;
int net_threads_num = 0;

static void *net_thread_loop(void *arg)
{
    struct net_thread_t *net_thread = (struct net_thread_t *)arg;

    pthread_setname_np(pthread_self(), net_thread->name);
    log_set_thread_name(net_thread->name);
    LOG(LOG_INFO, "%s run\n", net_thread->name);
    net_loop_loop(&net_thread->net_loop);
    LOG(LOG_INFO, "%s exit\n", net_thread->name);
    return NULL;
}

int net_threads_create(int num)
{
    int i;

    net_threads = (struct net_thread_t *)mem_malloc(sizeof(struct net_thread_t) * num);
    memset(net_threads, 0, sizeof(struct net_thread_t) * num);
    for (i = 0; i < num; i++) {
        snprintf(net_threads[i].name, sizeof(net_threads[i].name), "net_%d", i);
        if (net_loop_init(&net_threads[i].net_loop)) {
            break;
        }
        if (pthread_create(&net_threads[i].tid, NULL, net_thread_loop, &net_threads[i])) {
            LOG(LOG_ERROR, "%s pthread_create error\n", net_threads[i].name);
            net_loop_uninit(&net_threads[i].net_loop);
            break;
        }
    }
    net_threads_num = i;
    return net_threads_num;
}

int net_threads_exit()
{
    int i;

    for (i = 0; i < net_threads_num; i++) {
        net_loop_exit(&net_threads[i].net_loop);
        pthread_join(net_threads[i].tid, NULL);
        net_loop_uninit(&net_threads[i].net_loop);
    }

    mem_free(net_threads);
    net_threads = NULL;
    net_threads_num = 0;
    return 0;
}
