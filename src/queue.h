#ifndef _QUEUE_H
#define _QUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

struct qnode {
        void *data;
        struct qnode *next;
};
#define QNODE_SIZE	(sizeof(struct qnode))

typedef struct linkqueue{
        struct qnode *front;
        struct qnode *rear;
	int (*compare)(void *e1, void *e2);
} link_queue;
#define LINKQUEUE_SIZE	(sizeof(struct linkqueue))

struct linkqueue *queue_creat();
int queue_destroy(struct linkqueue *q);
int queue_empty(struct linkqueue *q);
int queue_push(struct linkqueue *q, void *e);
int queue_pop(struct linkqueue *q, void **e);
int queue_lrupush(struct linkqueue *q, void *e);

#ifdef __cplusplus
}
#endif

#endif
