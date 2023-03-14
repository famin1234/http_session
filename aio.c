#include "os.h"
#include "mem.h"
#include "log.h"
#include "aio.h"

struct aio_thread_t *aio_threads = NULL;
int aio_threads_num = 0;
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

static int aio_thread_init(struct aio_thread_t *aio_thread)
{
    LOG(LOG_INFO, "%s init\n", aio_thread->name);
    return 0;
}

static void *aio_thread_loop(void *data)
{
    struct aio_thread_t *aio_thread = data;
    struct aio_t *aio;

    log_thread_name(aio_thread->name);
    while (!aio_thread->exit) {
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

static void aio_thread_clean(struct aio_thread_t *aio_thread)
{
    LOG(LOG_INFO, "%s clean\n", aio_thread->name);
}

int aio_threads_run(int num)
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

void aio_threads_signal_exit()
{
    int i;

    for (i = 0; i < aio_threads_num; i++) {
        aio_threads[i].exit = 1;
    }
    pthread_mutex_lock(&aio_list.mutex);
    pthread_cond_broadcast(&aio_list.cond);
    pthread_mutex_unlock(&aio_list.mutex);
}

int aio_threads_join()
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
