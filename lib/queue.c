#include <linux/queue.h>
#include <linux/slab.h>         // kmalloc()

static int isFull(queue_t* queue)
{
    return (queue->size == queue->capacity);
}

static int isEmpty(queue_t* queue)
{
    return (queue->size == 0);
}

void enqueue(queue_t* queue, int item)
{
    if (isFull(queue))
        return;
    queue->rear = (queue->rear + 1) % queue->capacity;
    queue->arr[queue->rear] = item;
    queue->size = queue->size + 1;
}

int dequeue(queue_t* queue)
{
    if (isEmpty(queue))
        return -1;
    int item = queue->arr[queue->front];
    queue->front = (queue->front + 1) % queue->capacity;
    queue->size = queue->size - 1;
    return item;
}

int front(queue_t* queue)
{
    if (isEmpty(queue))
        return -1;
    return queue->arr[queue->front];
}

queue_t* alloc_queue(int capacity) {
    queue_t* queue = (queue_t *) kmalloc(sizeof(queue_t), GFP_KERNEL);

    if (queue == NULL) {
        return NULL;
    }

    queue->arr = kmalloc(sizeof(int) * capacity, GFP_KERNEL);

    if (queue->arr == NULL) {
        kfree(queue);
        return NULL;
    }

    queue->capacity = capacity;
    queue->front = queue->size = 0;

    // This is important, see the enqueue
    queue->rear = capacity - 1;
    return queue;
}

queue_t* make_queue(int capacity)
{
    queue_t *queue = alloc_queue(capacity);
    if (queue == NULL) {
        return NULL;
    }

    for (int i = 0; i < capacity; i++) {
        enqueue(queue, i);
    }

    return queue;
}

void free_queue(queue_t* queue) {
    kfree(queue->arr);
    kfree(queue);
}