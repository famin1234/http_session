#include "os.h"
#include "mem.h"
#include "log.h"
#include "aio.h"

static struct aio_list_t aio_list;

int aio_init()
{
    INIT_LIST_HEAD(&aio_list.list);
    pthread_mutex_init(&aio_list.mutex, NULL);
    pthread_cond_init(&aio_list.cond, NULL);
    return 0;
}

void aio_clean()
{
    pthread_mutex_destroy(&aio_list.mutex);
    pthread_cond_destroy(&aio_list.cond);
}

void aio_handle_exec(struct aio_t *aio)
{
    aio_handle_t handle;

    handle = aio->exec;
    aio->exec = NULL;
    handle(aio);
}

void aio_handle_done(struct aio_t *aio)
{
    aio_handle_t handle;

    handle = aio->done;
    aio->done = NULL;
    handle(aio);
}

int aio_busy(struct aio_t *aio)
{
    if (aio->exec || aio->done) {
        return 1;
    }
    return 0;
}

int aio_loop_init(struct aio_loop_t *aio_loop)
{
    LOG(LOG_INFO, "%s init\n", aio_loop->name);
    return 0;
}

void *aio_loop_loop(void *data)
{
    struct aio_loop_t *aio_loop = data;
    struct aio_t *aio;

    log_thread_name(aio_loop->name);
    while (!aio_loop->exit) {
        pthread_mutex_lock(&aio_list.mutex);
        if (list_empty(&aio_list.list)) {
            pthread_cond_wait(&aio_list.cond, &aio_list.mutex);
            if (list_empty(&aio_list.list)) {
                pthread_mutex_unlock(&aio_list.mutex);
                break;
            }
        }
        aio = d_list_head(&aio_list.list, struct aio_t, node);
        list_del(&aio->node);
        pthread_mutex_unlock(&aio_list.mutex);
        aio_handle_exec(aio);
    }
    LOG(LOG_INFO, "exit\n");
    return NULL;
}

void aio_loop_clean(struct aio_loop_t *aio_loop)
{
    LOG(LOG_INFO, "%s clean\n", aio_loop->name);
}

void aio_loop_signal()
{
    pthread_mutex_lock(&aio_list.mutex);
    pthread_cond_broadcast(&aio_list.cond);
    pthread_mutex_unlock(&aio_list.mutex);
}
