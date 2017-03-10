#ifndef SEND_QUEUE_H
#define SEND_QUEUE_H
    struct send_package_qnode{
        struct send_package_qnode* next;
        void* node_data;
    };    
    struct  send_package_queue
    {  
        struct send_package_qnode* front;  
        struct send_package_qnode* rear;  
        int size;  
        pthread_mutex_t  node_mutex;
    };  
    struct  send_package_queue *InitQueue(void);
    char IsEmpty(struct  send_package_queue *pqueue);
    char EnQueue(struct  send_package_queue *pqueue, void* node_data);
    void* DeQueue(struct  send_package_queue *pqueue);
    void ClearQueue(struct  send_package_queue *pqueue);
    void DestroyQueue(struct  send_package_queue *pqueue);
    int GetSize(struct  send_package_queue *pqueue);
    struct send_package_qnode *GetFront(struct  send_package_queue *pqueue);
    struct send_package_qnode *GetRear(struct  send_package_queue *pqueue);

#endif