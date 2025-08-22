#ifndef SELFQUEUE_H
#define SELFQUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include "cafun.h"

typedef struct QueueNode
{
	unsigned char time_rid[8];
	past_tm cur_time;
	char ip[27];
	struct QueueNode* next;
}QueueNode;

typedef	struct Queue
{
	QueueNode* head;
	QueueNode* tail;
}Queue;

extern Queue sk_update_queue;
extern Queue pkey_update_queue;

void QueueInit(Queue* pq);
void QueueDestory(Queue* pq);
void QueuePush(Queue* pq, past_tm* pt, char *oppo_ip);
void QueuePop(Queue* pq);
bool QueueEmpty(Queue* pq);
QueueNode* QueueFront(Queue* pq);
int QueueSize(Queue* pq);

#endif
