#ifndef _LIST_HEAD_H__
#define _LIST_HEAD_H__

/* Basic type for the double-link list.  */
typedef struct list_head
{
	struct list_head *next;
	struct list_head *prev;
} list_t;

/* Initialize a new list head.  */
#define INIT_LIST_HEAD(ptr) \
	(ptr)->next = (ptr)->prev = (ptr)

/* Add new element at the head of the list.  */
static inline void
list_add (list_t *newp, list_t *head)
{ 
	newp->next = head->next;
	newp->prev = head; 
	head->next->prev = newp;
	head->next = newp;
}

/* Remove element from list.  */
static inline void
list_del (list_t *elem)
{
	elem->next->prev = elem->prev;
	elem->prev->next = elem->next;
}

/* Join two lists.  */
static inline void
list_splice (list_t *add, list_t *head)
{
	/* Do nothing if the list which gets added is empty.  */
	if (add != add->next)
	{
		add->next->prev = head;
		add->prev->next = head->next;
		head->next->prev = add->prev;
		head->next = add->next;
	}
}

static inline int list_empty(const list_t *head)
{
        return head->next == head;
}

/* Get typed element from list at a given position.  */
#define list_entry(ptr, type, member)    ((type *) ((char *) (ptr) - (unsigned long) (&((type *) 0)->member)))

#define list_first_entry(ptr, type, member) \
        list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member) \
        list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each_entry(pos, head, member)                          \
        for (pos = list_first_entry(head, typeof(*pos), member);        \
             &pos->member != (head);                                    \
             pos = list_next_entry(pos, member))

#endif
