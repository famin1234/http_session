#include "mem.h"
#include "log.h"
#include "net.h"
#include "thread.h"

static struct net_handle_t *net_handles = NULL;
static struct thread_t *net_threads = NULL;
static int net_threads_num = 0;
static struct thread_t *task_threads = NULL;
static int task_threads_num = 0;

static struct list_head_t task_threads_list;
static pthread_mutex_t task_threads_mutex;
static pthread_cond_t task_threads_cond;
static int task_threads_wait = 0;
static int task_threads_exit = 0;

static void *task_thread_loop(void *arg)
{
    struct thread_t *thread = (struct thread_t *)arg;
    struct task_t *task;

    pthread_setname_np(pthread_self(), thread->name);
    log_set_thread_name(thread->name);
    LOG(LOG_INFO, "%s run\n", thread->name);
    while (1) {
        pthread_mutex_lock(&task_threads_mutex);
        if (list_empty(&task_threads_list)) {
            if (task_threads_exit) {
                pthread_mutex_unlock(&task_threads_mutex);
                break;
            } else {
                task_threads_wait++;
                pthread_cond_wait(&task_threads_cond, &task_threads_mutex);
                task_threads_wait--;
                if (list_empty(&task_threads_list)) {
                    pthread_mutex_unlock(&task_threads_mutex);
                    continue;
                }
            }
        }
        task = d_list_head(&task_threads_list, struct task_t, node);
        list_del(&task->node);
        pthread_mutex_unlock(&task_threads_mutex);
        task->handle(task);
    }
    LOG(LOG_INFO, "%s exit\n", thread->name);
    return NULL;
}

static void *net_thread_loop(void *arg)
{
    struct thread_t *thread = (struct thread_t *)arg;

    pthread_setname_np(pthread_self(), thread->name);
    log_set_thread_name(thread->name);
    LOG(LOG_INFO, "%s run\n", thread->name);
    net_handle_loop((struct net_handle_t *)thread->data);
    LOG(LOG_INFO, "%s exit\n", thread->name);
    return NULL;
}

int threads_init(int net_threads_num, int task_threads_num)
{
    int i;

    log_set_thread_name("main_0");

    INIT_LIST_HEAD(&task_threads_list);
    pthread_mutex_init(&task_threads_mutex, NULL);
    pthread_cond_init(&task_threads_cond, NULL);

    task_threads = (struct thread_t *)mem_malloc(sizeof(struct thread_t) * task_threads_num);
    memset(task_threads, 0, sizeof(struct thread_t) * task_threads_num);
    for (i = 0; i < task_threads_num; i++) {
        snprintf(task_threads[i].name, sizeof(task_threads[i].name), "task_%d", i);
        if (pthread_create(&task_threads[i].tid, NULL, task_thread_loop, &task_threads[i])) {
            LOG(LOG_ERROR, "%s pthread_create error\n", task_threads[i].name);
            break;
        }
    }
    task_threads_num = i;

    net_threads = (struct thread_t *)mem_malloc(sizeof(struct thread_t) * net_threads_num);
    memset(net_threads, 0, sizeof(struct thread_t) * net_threads_num);
    net_handles = (struct net_handle_t *)mem_malloc(sizeof(struct net_handle_t) * net_threads_num);
    memset(net_handles, 0, sizeof(struct net_handle_t) * net_threads_num);
    for (i = 0; i < net_threads_num; i++) {
        net_threads[i].data = &net_handles[i];
        snprintf(net_threads[i].name, sizeof(net_threads[i].name), "net_%d", i);
        if (net_handle_init((struct net_handle_t *)net_threads[i].data)) {
            LOG(LOG_ERROR, "%s net_handle_init error\n", net_threads[i].name);
            break;
        }
        if (pthread_create(&net_threads[i].tid, NULL, net_thread_loop, &net_threads[i])) {
            LOG(LOG_ERROR, "%s pthread_create error\n", net_threads[i].name);
            break;
        }
    }
    net_threads_num = i;

    return 0;
}

int threads_uninit()
{
    int i;

    for (i = 0; i < net_threads_num; i++) {
        net_handle_exit((struct net_handle_t *)net_threads[i].data);
        pthread_join(net_threads[i].tid, NULL);
        net_handle_uninit((struct net_handle_t *)net_threads[i].data);
    }
    mem_free(net_handles);
    net_handles = NULL;
    mem_free(net_threads);
    net_threads = NULL;
    net_threads_num = 0;

    pthread_mutex_lock(&task_threads_mutex);
    task_threads_exit = 1;
    pthread_cond_broadcast(&task_threads_cond);
    pthread_mutex_unlock(&task_threads_mutex);

    for (i = 0; i < task_threads_num; i++) {
        pthread_join(task_threads[i].tid, NULL);
    }
    pthread_mutex_destroy(&task_threads_mutex);
    pthread_cond_destroy(&task_threads_cond);
    mem_free(task_threads);
    task_threads = NULL;
    task_threads_num = 0;
    return 0;
}
