#ifndef __LIST__H___
#define __LIST__H___

#include <stddef.h>

struct list_head_
{
    struct list_head_ *next_;
    struct list_head_ *prev_;
};

typedef struct list_head_ list_head;

#ifdef LIST_HEAD_INIT
    #undef LIST_HEAD_INIT
#endif

#ifdef LIST_HEAD
    #undef LIST_HEAD
#endif

#define LIST_HEAD_INIT(list_name) { &(list_name), &(list_name) }

#define LIST_HEAD(list_name) \
    list_head list_name = LIST_HEAD_INIT(list_name)

#ifndef container_of
    #define container_of(ptr, type, member)                             \
    ({                                                                  \
        const typeof(((type *)0)->member) *__mptr = (ptr);              \
        (type *)((char *)__mptr - offsetof(type, member));              \
    })
#endif

#define list_foreach(pos, head)                                         \
    for                                                                 \
    (                                                                   \
        pos =  (head)->next_;                                           \
        pos != (head);                                                  \
        pos =  pos->next_                                               \
    )

#define list_foreach_entry(pos, head, member)                           \
    for                                                                 \
    (                                                                   \
        pos =  container_of((head)->next_, typeof(*pos), member);       \
        pos != container_of((head), typeof(*pos), member);              \
        pos =  container_of((pos)->member.next_, typeof(*pos), member)  \
    )

static inline void INIT_LIST_HEAD(list_head *head)
{
    head->next_ = head;
    head->prev_ = head;
}

static inline void list_insert(list_head *pos, list_head *new)
{
    new->prev_        = pos;
    new->next_        = pos->next_;
    pos->next_        = new;
    new->next_->prev_ = new;
}

static inline void list_add(list_head *head, list_head *new)
{
    list_insert(head, new);
}

static inline void list_add_tail(list_head *head, list_head *new)
{
    list_insert(head->prev_, new);
}

static inline void list_del_entry__ (list_head *entry)
{
    entry->prev_->next_ = entry->next_;
    entry->next_->prev_ = entry->prev_;
}

static inline void list_del(list_head *entry)
{
    list_del_entry__(entry);
    entry->next_ = NULL;
    entry->prev_ = NULL;
}

static inline void list_del_init(list_head *entry)
{
	list_del_entry__(entry);
	INIT_LIST_HEAD(entry);
}

static inline int list_empty(const list_head *head)
{
    return head->next_ == head->prev_;
}

static inline int list_empty_careful(const list_head *head)
{
	list_head *next = head->next_;
	return (next == head) && (next == head->prev_);
}

static inline void list_replace(list_head *old, list_head *new)
{
	new->next_ = old->next_;
	new->next_->prev_ = new;
	new->prev_ = old->prev_;
	new->prev_->next_ = new;
}

static inline void list_replace_init(list_head *old, list_head *new)
{
	list_replace(old, new);
	INIT_LIST_HEAD(old);
}

static inline void list_swap(list_head *entry1, list_head *entry2)
{
	list_head *pos = entry2->prev_;

	list_del(entry2);
	list_replace(entry1, entry2);

	if (pos == entry1)
		pos = entry2;

	list_add(pos, entry1);
}

static inline int list_is_first(const list_head *list, const list_head *head)
{
	return list->prev_ == head;
}

static inline int list_is_last(const list_head *list, const list_head *head)
{
	return list->next_ == head;
}

static inline void list_move(list_head *list, list_head *head)
{
	list_del_entry__(list);
	list_add(head, list);
}

static inline void list_move_tail(list_head *list, list_head *head)
{
	list_del_entry__(list);
	list_add_tail(head, list);
}

static inline void list_bulk_move_tail(list_head *head, list_head *first, list_head *last)
{
	first->prev_->next_ = last->next_;
	last->next_->prev_ = first->prev_;

	head->prev_->next_ = first;
	first->prev_ = head->prev_;

	last->next_ = head;
	head->prev_ = last;
}

static inline void list_rotate_left(list_head *head)
{
	list_head *first = NULL;

	if (!list_empty(head))
    {
		first = head->next_;
		list_move_tail(head, first);
	}
}

static inline void list_rotate_to_front(list_head *list, list_head *head)
{
	list_move_tail(head, list);
}

static inline int list_is_singular(const list_head *head)
{
	return !list_empty(head) && (head->next_ == head->prev_);
}

#endif // !__LIST__H___
