#ifndef UDT_UTILS_H_
#define UDT_UTILS_H_

#define DEBUG

#ifdef DEBUG

#include <stdio.h>
#define console_log_mod(MODIFIER, LOGDATA)  fprintf(stderr, MODIFIER, LOGDATA)
#define console_log(LOGDATA)                fprintf(stderr, "%s\n", LOGDATA)

#else

#define console_log_mod(MODIFIER, LOGDATA)
#define console_log(LOGDATA)

#endif // !DEBUG

#define linked_list_add(buffer, block)                      \
do                                                          \
{                                                           \
    pthread_mutex_lock(&(buffer.mutex));                    \
                                                            \
    if (buffer.size == 0)                                   \
        buffer.first = block;                               \
    else                                                    \
    {                                                       \
        block->next = buffer.last;                          \
        block->next->next = block;                          \
        block->next = NULL;                                 \
    }                                                       \
                                                            \
    buffer.last = block;                                    \
    buffer.size++;                                          \
                                                            \
    pthread_mutex_unlock(&(buffer.mutex));                  \
    pthread_cond_signal(&(buffer.cond));                    \
} while (0)

#define linked_list_get(buffer, block)                      \
do                                                          \
{                                                           \
    pthread_mutex_lock(&(buffer.mutex));                    \
                                                            \
    if (buffer.size == 0)                                   \
        pthread_cond_wait(&(buffer.cond), &(buffer.mutex)); \
                                                            \
    block = buffer.first;                                   \
    buffer.first = block->next;                             \
    buffer.size--;                                          \
    pthread_mutex_unlock(&(buffer.mutex));                  \
                                                            \
} while (0)

// typedef pthread_t tid_t;
// typedef void * (*thread_worker_t) (void *);

// tid_t thread_start (thread_worker_t, void *); 
// void  thread_stop  (tid_t);

#endif // !UDT_UTILS_H_
