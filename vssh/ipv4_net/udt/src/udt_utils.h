#ifndef UDT_UTILS_H_
#define UDT_UTILS_H_

#include "ipv4_net_config.h"
#include <stdio.h>
#include <syslog.h>

#ifdef _UDT_LOG_
    #define udt_syslog(priority, fmt, ...) \
        syslog(priority, "[UDT]: " fmt, ##__VA_ARGS__)
#else
    #define udt_console_log(priority, fmt, ...)
#endif // !_UDT_DEBUG_

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
    if (buffer.size == 0)                                   \
        block = NULL;                                       \
    else                                                    \
    {                                                       \
        block = buffer.first;                               \
        buffer.first = block->next;                         \
        buffer.size--;                                      \
    }                                                       \
                                                            \
    pthread_mutex_unlock(&(buffer.mutex));                  \
                                                            \
} while (0)

#endif // !UDT_UTILS_H_
