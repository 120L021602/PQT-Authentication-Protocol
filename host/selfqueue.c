
#include "selfqueue.h"

Queue sk_update_queue; 
Queue pkey_update_queue;

void QueueInit(Queue* pq)
{
	assert(pq);
	pq->head = pq->tail = NULL;
}

void QueueDestory(Queue* pq)
{
	assert(pq);
	QueueNode* cur = pq->head;
	while (cur)
	{
		QueueNode* next = cur->next;
		free(cur);
		cur = next;
	}
	pq->tail = pq->head = NULL;
}

void QueuePush(Queue* pq, past_tm *pt, char *oppo_ip)
{
	assert(pq);
	QueueNode* newNode = (QueueNode*)malloc(sizeof(QueueNode));
	if (NULL == newNode)
	{
		printf("malloc error\n");
		exit(-1);
	}
	newNode->cur_time.year = pt->year;
	newNode->cur_time.month = pt->month;
	newNode->cur_time.day = pt->day;
	memmove(newNode->ip, oppo_ip, 26);
    newNode->next = NULL;
	if (pq->tail == NULL)
	{
		assert(pq->head == NULL);
		pq->head = pq->tail = newNode;
	}
	else
	{
		pq->tail->next = newNode;
		pq->tail = newNode;
	}

}

void QueuePop(Queue* pq)
{
	assert(pq);
	assert(pq->head && pq->tail);
	if (pq->head->next == NULL)
	{
		free(pq->head);
		pq->head = pq->tail = NULL;
	}
	else
	{
		QueueNode* next = pq->head->next;
		free(pq->head);
		pq->head = next;
	}
}

bool QueueEmpty(Queue* pq)
{
	assert(pq);

	return pq->head == NULL;
}
QueueNode* QueueFront(Queue* pq)
{
    assert(pq);
	assert(pq->head);
    return pq->head;
}
// QDateType QueueFront(Queue* pq)
// {
// 	assert(pq);
// 	assert(pq->head);

// 	return pq->head->val;
// }

int QueueSize(Queue* pq)
{
	assert(pq);
	QueueNode* cur = pq->head;
	int count = 0;
	while (cur)
	{
		cur = cur->next;
		count++;
	}
	return count;
}

