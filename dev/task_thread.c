#include <assert.h>
#include "list.h"
#include "mem.h"
#include "log.h"
#include "task_thread.h"

static struct list_head_t list;
static pthread_mutex_t mutex;
static pthread_cond_t cond;
struct task_thread_t *task_threads = NULL;
int task_threads_num = 0;
static int task_threads_wait = 0;
static int signal_exit = 0;

static void *task_thread_loop(void *arg)
{
    struct task_thread_t *task_thread = (struct task_thread_t *)arg;
    struct task_t *task;

    pthread_setname_np(pthread_self(), task_thread->name);
    log_set_thread_name(task_thread->name);
    LOG(LOG_INFO, "%s run\n", task_thread->name);
    while (1) {
        pthread_mutex_lock(&mutex);
        if (list_empty(&list)) {
            if (signal_exit) {
                pthread_mutex_unlock(&mutex);
                break;
            } else {
                task_threads_wait++;
                pthread_cond_wait(&cond, &mutex);
                task_threads_wait--;
                if (list_empty(&list)) {
                    pthread_mutex_unlock(&mutex);
                    continue;
                }
            }
        }
        task = d_list_head(&list, struct task_t, node);
        list_del(&task->node);
        pthread_mutex_unlock(&mutex);
        task->handle(task);
    }
    LOG(LOG_INFO, "%s exit\n", task_thread->name);
    return NULL;
}

int task_threads_create(int num)
{
    int i;

    INIT_LIST_HEAD(&list);
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond, NULL);

    task_threads = (struct task_thread_t *)mem_malloc(sizeof(struct task_thread_t) * num);
    memset(task_threads, 0, sizeof(struct task_thread_t) * num);
    for (i = 0; i < num; i++) {
        snprintf(task_threads[i].name, sizeof(task_threads[i].name), "task_%d", i);
        if (pthread_create(&task_threads[i].tid, NULL, task_thread_loop, &task_threads[i])) {
            LOG(LOG_ERROR, "%s pthread_create error\n", task_threads[i].name);
            break;
        }
    }
    task_threads_num = i;
    return 0;
}

int task_threads_post(struct task_t *task)
{
    pthread_mutex_lock(&mutex);
    if (signal_exit) {
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    list_add_tail(&task->node, &list);
    if (task_threads_wait > 0) {
        pthread_cond_broadcast(&cond);
    }
    pthread_mutex_unlock(&mutex);
    return 0;
}

int task_threads_exit()
{
    int i;

    pthread_mutex_lock(&mutex);
    signal_exit = 1;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&mutex);

    for (i = 0; i < task_threads_num; i++) {
        pthread_join(task_threads[i].tid, NULL);
    }
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);

    mem_free(task_threads);
    task_threads = NULL;
    task_threads_num = 0;
    return 0;
}
