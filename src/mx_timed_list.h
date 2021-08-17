#ifndef __MX_TIMED_LIST__
#define __MX_TIMED_LIST__

struct list_head
{
    struct list_head *prev;
    struct list_head *next;
};

#define LIST_HEAD(name) \
    struct list_head name = { &(name), &(name) }

#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; \
            pos != (head); \
            pos = n, n = pos->next)

/**
 * @brief
 *
 * @param list
 */
static inline void list_init(struct list_head *list)
{
    list->prev = list;
    list->next = list;
}

/**
 * @brief
 *
 * @param entry
 * @param prev
 * @param next
 */
static inline void __list_add(struct list_head *entry,
                              struct list_head *prev,
                              struct list_head *next)
{
    next->prev = entry;
    entry->next = next;
    entry->prev = prev;
    prev->next = entry;
}

/**
 * @brief
 *
 * @param prev
 * @param next
 */
static inline void __list_del(struct list_head *prev, struct list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

/**
 * @brief
 *
 * @param entry
 * @param head
 */
static inline void list_insert(struct list_head *entry, struct list_head *head)
{
    __list_add(entry, head, head->next);
}

/**
 * @brief
 *
 * @param entry
 */
static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);
    entry->prev = NULL;
    entry->next = NULL;
}

/**
 * @brief
 *
 * @param entry
 * @param head
 */
static inline void list_push(struct list_head *entry, struct list_head *head)
{
    __list_add(entry, head->prev, head);
}

/**
 * @brief
 *
 * @param head
 *
 * @return
 */
static inline struct list_head *list_pop(struct list_head *head)
{
    struct list_head *entry;

    if (head->next == head)
    {
        return NULL;
    }

    entry = head->next;
    list_del(entry);
    return entry;
}

/**
 * @brief: add entry to a position by specify function
 *
 * @param entry
 * @param head
 * @param func
 */
static inline void list_insert_by(
    struct list_head *entry,
    struct list_head *head,
    int (*func)(struct list_head *, struct list_head *, struct list_head *)
)
{
    struct list_head *pos;
    int rv;

    list_for_each(pos, head)
    {
        rv = func(entry, pos, head);

        if (rv == 1)
        {
            __list_add(entry, pos, pos->next);
            return;
        }
        else if (rv == -1)
        {
            __list_add(entry, pos->prev, pos);
            return;
        }
    }

    list_push(entry, head);
}

/**
 * @brief
 *
 * @param entry
 * @param head
 * @param func
 */
static inline struct list_head *list_search(
    struct list_head *head,
    void *param,
    int (*func)(struct list_head *, void *param))
{
    struct list_head *pos;
    int rv;

    list_for_each(pos, head)
    {
        rv = func(pos, param);

        if (rv == 1)
        {
            return pos;
        }
    }

    return NULL;
}

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define list_entry(ptr,type,member)     \
    container_of(ptr, type, member)

#endif
