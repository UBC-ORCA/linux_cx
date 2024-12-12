#ifndef QUEUE_H
#define QUEUE_H

#define CX_TABLE_SIZE 1024

typedef struct {
    int *arr;
    int front;
    int rear;
    int size;
    int capacity;
} queue_t;

queue_t *alloc_queue(int capacity);

queue_t *make_queue(int capacity);

void enqueue(queue_t *queue, int element);

int dequeue(queue_t *queue);

int front(queue_t* queue);

void free_queue(queue_t *queue);

#endif