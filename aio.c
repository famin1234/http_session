#include "os.h"
#include "mem.h"
#include "log.h"
#include "aio.h"

struct list_head_t aio_list;
pthread_mutex_t aio_mutex;
pthread_cond_t aio_cond;

int aio_init()
{
    INIT_LIST_HEAD(&aio_list);
    pthread_mutex_init(&aio_mutex, NULL);
    pthread_cond_init(&aio_cond, NULL);
    return 0;
}

void aio_clean()
{
    pthread_mutex_destroy(&aio_mutex);
    pthread_cond_destroy(&aio_cond);
}

int aio_busy(struct aio_t *aio)
{
    if (aio->exec) {
        return 1;
    }
    return 0;
}

int aio_thread_init(struct aio_thread_t *aio_thread)
{
    LOG(LOG_INFO, "%s init\n", aio_thread->name);
    return 0;
}

void *aio_thread_loop(void *data)
{
    struct aio_thread_t *aio_thread = data;
    struct aio_t *aio;

    log_thread_name(aio_thread->name);
    while (!aio_thread->exit) {
        pthread_mutex_lock(&aio_mutex);
        if (list_empty(&aio_list)) {
            pthread_cond_wait(&aio_cond, &aio_mutex);
            if (list_empty(&aio_list)) {
                pthread_mutex_unlock(&aio_mutex);
                break;
            }
        }
        aio = d_list_head(&aio_list, struct aio_t, node);
        list_del(&aio->node);
        pthread_mutex_unlock(&aio_mutex);
        aio->exec(aio);
    }
    LOG(LOG_INFO, "exit\n");
    return NULL;
}

void aio_thread_clean(struct aio_thread_t *aio_thread)
{
    LOG(LOG_INFO, "%s clean\n", aio_thread->name);
}

void aio_thread_signal()
{
    pthread_mutex_lock(&aio_mutex);
    pthread_cond_broadcast(&aio_cond);
    pthread_mutex_unlock(&aio_mutex);
}
