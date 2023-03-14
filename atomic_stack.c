#include "atomic_stack.h"

void atomic_stack_init(struct atomic_stack_t *atomic_stack)
{
    memset(atomic_stack, 0, sizeof(struct atomic_stack_t));
#if ATOMIC_STACK_SPINLOCK
    pthread_spin_init(&atomic_stack->spinlock, PTHREAD_PROCESS_PRIVATE);
#endif
}

void atomic_stack_push(struct atomic_stack_t *atomic_stack, struct atomic_node_t *node)
{
    struct atomic_head_t old;
    struct atomic_head_t head;

#if ATOMIC_STACK_SPINLOCK
    pthread_spin_lock(&atomic_stack->spinlock);
    old = atomic_stack->head;
    node->next = old.node;
    head.node = node;
    atomic_stack->head = head;
    pthread_spin_unlock(&atomic_stack->spinlock);
#else
    do {
        old = atomic_stack->head;
        node->next = ATOMIC_HEAD_NODE(old);
        ATOMIC_HEAD_SET(head, node, ATOMIC_HEAD_VERSION(old) + 1);
    } while (!__sync_bool_compare_and_swap(&atomic_stack->head.data, old.data, head.data));
#endif
}

struct atomic_node_t *atomic_stack_pop(struct atomic_stack_t *atomic_stack)
{
    struct atomic_head_t old;
    struct atomic_head_t head;

#if ATOMIC_STACK_SPINLOCK
    pthread_spin_lock(&atomic_stack->spinlock);
    old = atomic_stack->head;
    if (!old.node) {
        pthread_spin_unlock(&atomic_stack->spinlock);
        return NULL;
    }
    head.node = (old.node)->next;
    atomic_stack->head = head;
    pthread_spin_unlock(&atomic_stack->spinlock);
    return old.node;
#else
    do {
        old = atomic_stack->head;
        if (!ATOMIC_HEAD_NODE(old)) {
            return NULL;
        }
        ATOMIC_HEAD_SET(head, ATOMIC_HEAD_NODE(old)->next, ATOMIC_HEAD_VERSION(old));
    } while (!__sync_bool_compare_and_swap(&atomic_stack->head.data, old.data, head.data));
    return ATOMIC_HEAD_NODE(old);
#endif
}

void atomic_stack_clean(struct atomic_stack_t *atomic_stack)
{
#if ATOMIC_STACK_SPINLOCK
    pthread_spin_destroy(&atomic_stack->spinlock);
#endif
}
