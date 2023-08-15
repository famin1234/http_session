#include "os.h"
#include "log.h"
#include "mem.h"
#include "action.h"
#include "aio_thread.h"

struct list_head_t list;
pthread_mutex_t mutex;
pthread_cond_t cond;
static struct aio_thread_t *aio_threads = NULL;
static int aio_threads_num = 0;

static int aio_thread_init(struct aio_thread_t *aio_thread)
{
    return 0;
}

static void *aio_thread_loop(void *data)
{
    struct aio_thread_t *aio_thread = data;
    struct action_t *action;

    log_thread_name(aio_thread->name);
    while (!aio_thread->exit) {
        pthread_mutex_lock(&mutex);
        if (list_empty(&list)) {
            pthread_cond_wait(&cond, &mutex);
            if (list_empty(&list)) {
                pthread_mutex_unlock(&mutex);
                break;
            }
        }
        action = d_list_head(&list, struct action_t, node);
        list_del(&action->node);
        pthread_mutex_unlock(&mutex);
        action->handle(action);
    }
    LOG(LOG_INFO, "exit\n");
    return NULL;
}

static void aio_thread_clean(struct aio_thread_t *aio_thread)
{
    LOG(LOG_INFO, "%s clean\n", aio_thread->name);
}

int aio_threads_run(int n)
{
    int i;

    INIT_LIST_HEAD(&list);
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond, NULL);

    assert(aio_threads_num == 0);
    aio_threads_num = n;
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

void aio_threads_join()
{
    int i;

    for (i = 0; i < aio_threads_num; i++) {
        pthread_join(aio_threads[i].tid, NULL);
    }
    for (i = 0; i < aio_threads_num; i++) {
        aio_thread_clean(&aio_threads[i]);
    }

    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);

    mem_free(aio_threads);
    aio_threads = NULL;
    aio_threads_num = 0;
}

void aio_threads_signal()
{
    pthread_mutex_lock(&mutex);
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&mutex);
}

void aio_threads_exit()
{
    int i;

    for (i = 0; i < aio_threads_num; i++) {
        aio_threads[i].exit = 1;
    }
    aio_threads_signal();
}
