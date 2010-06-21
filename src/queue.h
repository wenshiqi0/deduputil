#ifndef _QUEUE_H
#define _QUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

struct qnode {
        void *data;
        struct qnode *next;
};

struct linkqueue{
        struct qnode *front;
        struct qnode *rear;
};

int queue_init(struct linkqueue *q);
int queue_destroy(struct linkqueue *q);
int queue_empty(struct linkqueue *q);
int queue_push(struct linkqueue *q, void *e);
int queue_pop(struct linkqueue *q, void **e);

#ifdef __cplusplus
}
#endif

#endif
