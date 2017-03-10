#include <pthread.h>
#include <stdlib.h>
#include "send_queue.h"
struct  send_package_queue *InitQueue(void)  
{  
    struct  send_package_queue *pqueue = (struct  send_package_queue *)malloc(sizeof(struct  send_package_queue));  
    if(pqueue!=NULL)  
    {  
        pqueue->front = NULL;  
        pqueue->rear = NULL;  
        pqueue->size = 0;  
        pthread_mutex_init(&pqueue->node_mutex, NULL);
    }  
    return pqueue;  
}  
 
char IsEmpty(struct  send_package_queue *pqueue)  
{  
    if(pqueue->front==NULL && pqueue->rear==NULL && pqueue->size==0)  
        return 1;  
    else  
        return 0;  
} 

char EnQueue(struct  send_package_queue *pqueue, void* node_data)
{  
	struct send_package_qnode *pnode = (struct send_package_qnode* )malloc(sizeof(struct send_package_qnode));  
	if(pnode != NULL)  
	{  
        
		pnode->node_data = node_data; 
		pnode->next = NULL;
        pthread_mutex_lock(&pqueue->node_mutex); 
        do{
            if(IsEmpty(pqueue))  
            {  
                pqueue->front = pnode;  
            }  
            else  
            {  
                pqueue->rear->next = pnode;  
            }  
            pqueue->rear = pnode;  
            pqueue->size++;             
        }while(0);
		pthread_mutex_unlock(&pqueue->node_mutex);
	}  
	else
		return -1;     
	return 0;  
}  
  
void* DeQueue(struct  send_package_queue *pqueue)  
{  
    struct send_package_qnode *pnode = pqueue->front;
    if(pnode == NULL)
        return NULL;
    void* node_data = NULL;
    if(IsEmpty(pqueue) != 1 && pnode != NULL)  
    {  	
        pthread_mutex_lock(&pqueue->node_mutex);
        do{  
            node_data = pnode->node_data;
            pqueue->size--;  
            pqueue->front = pnode->next;   
            if(pqueue->size==0)  
                pqueue->rear = NULL;  
        }while(0);
		pthread_mutex_unlock(&pqueue->node_mutex);   
    }     
    free(pnode);
    return node_data;      
} 

void ClearQueue(struct  send_package_queue *pqueue)  
{  
    while(IsEmpty(pqueue)!=1)  
    {  
        DeQueue(pqueue);  
    }  
} 

void DestroyQueue(struct  send_package_queue *pqueue)  
{  
    if(IsEmpty(pqueue)!=1)  
        ClearQueue(pqueue);  
    free(pqueue);  
}  

int GetSize(struct  send_package_queue *pqueue)  
{  
    return pqueue->size;  
}  

struct send_package_qnode *GetFront(struct  send_package_queue *pqueue)  
{  
    return pqueue->front;  
}  
struct send_package_qnode *GetRear(struct  send_package_queue *pqueue)  
{  
    return pqueue->rear;  
}  