/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org, 
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/tree.h>

#include "thread/thread.h"
#include "avl/avl.h"
#include "httpp/httpp.h"
#include "net/sock.h"

#include "connection.h"

#include "source.h"
#include "admin.h"
#include "global.h"
#include "refbuf.h"
#include "client.h"
#include "stats.h"
#include "xslt.h"
#include "util.h"
#include "fserve.h"
#define CATMODULE "stats"
#include "logging.h"

#if !defined HAVE_ATOLL && defined HAVE_STRTOLL
#define atoll(nptr) strtoll(nptr, (char **)NULL, 10)
#endif

#define VAL_BUFSIZE 20
#define STATS_BLOCK_CONNECTION  01

#define STATS_EVENT_SET     0
#define STATS_EVENT_INC     1
#define STATS_EVENT_DEC     2
#define STATS_EVENT_ADD     3
#define STATS_EVENT_SUB     4
#define STATS_EVENT_REMOVE  5
#define STATS_EVENT_HIDDEN  0x80

typedef struct _stats_node_tag
{
    char *name;
    char *value;
    int  flags;
} stats_node_t;

typedef struct _stats_event_tag
{
    char *source;
    char *name;
    char *value;
    int  flags;
    int  action;

    struct _stats_event_tag *next;
} stats_event_t;

typedef struct _stats_source_tag
{
    char *source;
    int  flags;
    avl_tree *stats_tree;
} stats_source_t;

typedef struct _event_listener_tag
{
    int mask;
    unsigned int content_len;
    char *source;

    /* queue for unwritten stats to stats clients */
    refbuf_t *recent_block;
    client_t *client;

    struct _event_listener_tag *next;
} event_listener_t;


typedef struct _stats_tag
{
    avl_tree *global_tree;
    avl_tree *source_tree;

    /* list of listeners for stats */
    event_listener_t *event_listeners;
    mutex_t listeners_lock;

} stats_t;

static volatile int _stats_running = 0;

static stats_t _stats;


static int _compare_stats(void *a, void *b, void *arg);
static int _compare_source_stats(void *a, void *b, void *arg);
static int _free_stats(void *key);
static int _free_source_stats(void *key);
static stats_node_t *_find_node(const avl_tree *tree, const char *name);
static stats_source_t *_find_source(avl_tree *tree, const char *source);
static void process_event (stats_event_t *event);
static void _add_stats_to_stats_client (client_t *client, const char *fmt, va_list ap);
static void stats_listener_send (int flags, const char *fmt, ...);

unsigned int throttle_sends;

/* simple helper function for creating an event */
static void build_event (stats_event_t *event, const char *source, const char *name, const char *value)
{
    event->source = (char *)source;
    event->name = (char *)name;
    event->value = (char *)value;
    event->flags = STATS_PUBLIC;
    if (source) event->flags |= STATS_SLAVE;
    if (value)
        event->action = STATS_EVENT_SET;
    else
        event->action = STATS_EVENT_REMOVE;
}


void stats_initialize(void)
{
    if (_stats_running)
        return;

    /* set up global struct */
    _stats.global_tree = avl_tree_new(_compare_stats, NULL);
    _stats.source_tree = avl_tree_new(_compare_source_stats, NULL);

    _stats.event_listeners = NULL;
    thread_mutex_create (&_stats.listeners_lock);

    _stats_running = 1;

    stats_event_time (NULL, "server_start", STATS_GENERAL);

    /* global currently active stats */
    stats_event_flags (NULL, "clients", "0", STATS_COUNTERS);
    stats_event_flags (NULL, "connections", "0", STATS_COUNTERS);
    stats_event_flags (NULL, "sources", "0", STATS_COUNTERS);
    stats_event_flags (NULL, "stats", "0", STATS_COUNTERS);
    stats_event_flags (NULL, "banned_IPs", "0", STATS_COUNTERS);
    stats_event (NULL, "listeners", "0");

    /* global accumulating stats */
    stats_event_flags (NULL, "client_connections", "0", STATS_COUNTERS);
    stats_event_flags (NULL, "source_client_connections", "0", STATS_COUNTERS);
    stats_event_flags (NULL, "source_relay_connections", "0", STATS_COUNTERS);
    stats_event_flags (NULL, "source_total_connections", "0", STATS_COUNTERS);
    stats_event_flags (NULL, "stats_connections", "0", STATS_COUNTERS);
    stats_event_flags (NULL, "listener_connections", "0", STATS_COUNTERS);
    stats_event_flags (NULL, "outgoing_kbitrate", "0", STATS_COUNTERS|STATS_REGULAR);
    stats_event_flags (NULL, "stream_kbytes_sent", "0", STATS_COUNTERS|STATS_REGULAR);
    stats_event_flags (NULL, "stream_kbytes_read", "0", STATS_COUNTERS|STATS_REGULAR);
}

void stats_shutdown(void)
{
    if(!_stats_running) /* We can't shutdown if we're not running. */
        return;

    _stats_running = 0;

    avl_tree_free(_stats.source_tree, _free_source_stats);
    avl_tree_free(_stats.global_tree, _free_stats);
    thread_mutex_destroy (&_stats.listeners_lock);
}


/* simple name=tag stat create/update */
void stats_event(const char *source, const char *name, const char *value)
{
    stats_event_t event;

    if (value && xmlCheckUTF8 ((unsigned char *)value) == 0)
    {
        WARN3 ("seen non-UTF8 data (%s), probably incorrect metadata (%s, %s)",
                source?source:"global", name, value);
        return;
    }
    build_event (&event, source, name, (char *)value);
    process_event (&event);
}


/* wrapper for stats_event, this takes a charset to convert from */
void stats_event_conv(const char *mount, const char *name, const char *value, const char *charset)
{
    const char *metadata = value;
    xmlBufferPtr conv = xmlBufferCreate ();

    if (charset && value)
    {
        xmlCharEncodingHandlerPtr handle = xmlFindCharEncodingHandler (charset);

        if (handle)
        {
            xmlBufferPtr raw = xmlBufferCreate ();
            xmlBufferAdd (raw, (const xmlChar *)value, strlen (value));
            if (xmlCharEncInFunc (handle, conv, raw) > 0)
                metadata = (char *)xmlBufferContent (conv);
            xmlBufferFree (raw);
            xmlCharEncCloseFunc (handle);
        }
        else
            WARN1 ("No charset found for \"%s\"", charset);
    }

    stats_event (mount, name, metadata);
    xmlBufferFree (conv);
}

/* set stat with flags, name can be NULL if it applies to a whole
 * source stats tree. */
void stats_event_flags (const char *source, const char *name, const char *value, int flags)
{
    stats_event_t event;

    build_event (&event, source, name, value);
    event.flags = flags;
    if (value)
        event.action |= STATS_EVENT_HIDDEN;
    else
        event.action = STATS_EVENT_HIDDEN;
    process_event (&event);
}

/* printf style formatting for stat create/update */
void stats_event_args(const char *source, char *name, char *format, ...)
{
    va_list val;
    int ret;
    char buf[1024];

    if (name == NULL)
        return;
    va_start(val, format);
    ret = vsnprintf(buf, sizeof (buf), format, val);
    va_end(val);

    if (ret < 0 || (unsigned int)ret >= sizeof (buf))
    {
        WARN2 ("problem with formatting %s stat %s",
                source==NULL ? "global" : source, name);
        return;
    }
    stats_event(source, name, buf);
}

static char *_get_stats(const char *source, const char *name)
{
    stats_node_t *stats = NULL;
    stats_source_t *src = NULL;
    char *value = NULL;

    if (source == NULL) {
        avl_tree_rlock (_stats.global_tree);
        stats = _find_node(_stats.global_tree, name);
        if (stats) value = (char *)strdup(stats->value);
        avl_tree_unlock (_stats.global_tree);
    } else {
        avl_tree_rlock (_stats.source_tree);
        src = _find_source(_stats.source_tree, source);
        if (src)
        {
            avl_tree_rlock (src->stats_tree);
            avl_tree_unlock (_stats.source_tree);
            stats = _find_node(src->stats_tree, name);
            if (stats) value = (char *)strdup(stats->value);
            avl_tree_unlock (src->stats_tree);
        }
        else
            avl_tree_unlock (_stats.source_tree);
    }

    return value;
}

char *stats_get_value(const char *source, const char *name)
{
    return(_get_stats(source, name));
}


char *stats_retrieve (long handle, const char *name)
{
    char *v = NULL;
    stats_source_t *src_stats = (stats_source_t *)handle;
    stats_node_t *stats = _find_node (src_stats->stats_tree, name);

    if (stats) v =  strdup (stats->value);
    return v;
}


/* increase the value in the provided stat by 1 */
void stats_event_inc(const char *source, const char *name)
{
    stats_event_t event;
    char buffer[VAL_BUFSIZE] = "1";
    build_event (&event, source, name, buffer);
    /* DEBUG2("%s on %s", name, source==NULL?"global":source); */
    event.action = STATS_EVENT_INC;
    process_event (&event);
}

void stats_event_add(const char *source, const char *name, unsigned long value)
{
    stats_event_t event;
    char buffer [VAL_BUFSIZE];

    if (value == 0)
        return;
    build_event (&event, source, name, buffer);
    snprintf (buffer, VAL_BUFSIZE, "%ld", value);
    event.action = STATS_EVENT_ADD;
    /* DEBUG2("%s on %s", name, source==NULL?"global":source); */
    process_event (&event);
}

void stats_event_sub(const char *source, const char *name, unsigned long value)
{
    stats_event_t event;
    char buffer[VAL_BUFSIZE];

    if (value == 0)
        return;
    build_event (&event, source, name, buffer);
    /* DEBUG2("%s on %s", name, source==NULL?"global":source); */
    snprintf (buffer, VAL_BUFSIZE, "%ld", value);
    event.action = STATS_EVENT_SUB;
    process_event (&event);
}

/* decrease the value in the provided stat by 1 */
void stats_event_dec(const char *source, const char *name)
{
    stats_event_t event;
    char buffer[VAL_BUFSIZE] = "0";
    /* DEBUG2("%s on %s", name, source==NULL?"global":source); */
    build_event (&event, source, name, buffer);
    event.action = STATS_EVENT_DEC;
    process_event (&event);
}

/* note: you must call this function only when you have exclusive access
** to the avl_tree
*/
static stats_node_t *_find_node(const avl_tree *stats_tree, const char *name)
{
    stats_node_t *stats;
    avl_node *node;
    int cmp;

    /* get the root node */
    node = stats_tree->root->right;
    
    while (node) {
        stats = (stats_node_t *)node->key;
        cmp = strcmp(name, stats->name);
        if (cmp < 0) 
            node = node->left;
        else if (cmp > 0)
            node = node->right;
        else
            return stats;
    }
    
    /* didn't find it */
    return NULL;
}

/* note: you must call this function only when you have exclusive access
** to the avl_tree
*/
static stats_source_t *_find_source(avl_tree *source_tree, const char *source)
{
    stats_source_t *stats;
    avl_node *node;
    int cmp;

    /* get the root node */
    node = source_tree->root->right;
    while (node) {
        stats = (stats_source_t *)node->key;
        cmp = strcmp(source, stats->source);
        if (cmp < 0)
            node = node->left;
        else if (cmp > 0)
            node = node->right;
        else
            return stats;
    }

    /* didn't find it */
    return NULL;
}


/* helper to apply specialised changes to a stats node */
static void modify_node_event (stats_node_t *node, stats_event_t *event)
{
    if (node == NULL || event == NULL)
        return;
    if (event->action & STATS_EVENT_HIDDEN)
    {
        node->flags = event->flags;
        event->action &= ~STATS_EVENT_HIDDEN;
        if (event->value == NULL)
            return;
    }
    if (event->action != STATS_EVENT_SET)
    {
        int64_t value = 0;

        switch (event->action)
        {
            case STATS_EVENT_INC:
                value = atoll (node->value)+1;
                break;
            case STATS_EVENT_DEC:
                value = atoll (node->value)-1;
                break;
            case STATS_EVENT_ADD:
                value = atoll (node->value) + atoll (event->value);
                break;
            case STATS_EVENT_SUB:
                value = atoll (node->value) - atoll (event->value);
                break;
            default:
                break;
        }
        snprintf (event->value, VAL_BUFSIZE, "%" PRId64, value);
    }
    if (node->value)
    {
        free (node->value);
        node->value = strdup (event->value);
    }
    DEBUG3 ("update \"%s\" %s (%s)", event->source?event->source:"global", node->name, node->value);
}


static void process_global_event (stats_event_t *event)
{
    stats_node_t *node = NULL;

    avl_tree_wlock (_stats.global_tree);
    /* DEBUG3("global event %s %s %d", event->name, event->value, event->action); */
    if (event->action == STATS_EVENT_REMOVE)
    {
        /* we're deleting */
        node = _find_node(_stats.global_tree, event->name);
        if (node != NULL)
        {
            stats_listener_send (node->flags, "DELETE global %s\n", event->name);
            avl_delete(_stats.global_tree, (void *)node, _free_stats);
        }
        avl_tree_unlock (_stats.global_tree);
        return;
    }
    node = _find_node(_stats.global_tree, event->name);
    if (node)
    {
        modify_node_event (node, event);
        if ((node->flags & STATS_REGULAR) == 0)
            stats_listener_send (node->flags, "EVENT global %s %s\n", node->name, node->value);
    }
    else
    {
        /* add node */
        node = (stats_node_t *)calloc(1, sizeof(stats_node_t));
        node->name = (char *)strdup(event->name);
        node->value = (char *)strdup(event->value);
        node->flags = event->flags;

        avl_insert(_stats.global_tree, (void *)node);
        stats_listener_send (node->flags, "EVENT global %s %s\n", event->name, event->value);
    }
    avl_tree_unlock (_stats.global_tree);
}


static void process_source_stat (stats_source_t *src_stats, stats_event_t *event)
{
    if (event->name)
    {
        stats_node_t *node = _find_node (src_stats->stats_tree, event->name);
        if (node == NULL)
        {
            /* adding node */
            if (event->action != STATS_EVENT_REMOVE && event->value)
            {
                DEBUG3 ("new node on %s \"%s\" (%s)", src_stats->source, event->name, event->value);
                node = (stats_node_t *)calloc (1,sizeof(stats_node_t));
                node->name = (char *)strdup (event->name);
                node->value = (char *)strdup (event->value);
                node->flags = event->flags;
                if (src_stats->flags & STATS_HIDDEN)
                    node->flags |= STATS_HIDDEN;
                stats_listener_send (node->flags, "EVENT %s %s %s\n", src_stats->source, event->name, event->value);
                avl_insert (src_stats->stats_tree, (void *)node);
            }
            return;
        }
        if (event->action == STATS_EVENT_REMOVE)
        {
            DEBUG2 ("delete node %s from %s", event->name, src_stats->source);
            stats_listener_send (node->flags, "DELETE %s %s\n", src_stats->source, event->name);
            avl_delete (src_stats->stats_tree, (void *)node, _free_stats);
            return;
        }
        modify_node_event (node, event);
        stats_listener_send (node->flags, "EVENT %s %s %s\n", src_stats->source, node->name, node->value);
        return;
    }
    if (event->action == STATS_EVENT_REMOVE && event->name == NULL)
    {
        avl_tree_unlock (src_stats->stats_tree);
        avl_tree_wlock (_stats.source_tree);
        avl_tree_wlock (src_stats->stats_tree);
        avl_delete (_stats.source_tree, (void *)src_stats, _free_source_stats);
        avl_tree_unlock (_stats.source_tree);
        return;
    }
    /* change source flags status */
    if (event->action & STATS_EVENT_HIDDEN)
    {
        avl_node *node = avl_get_first (src_stats->stats_tree);
        int visible = 0;

        if ((event->flags&STATS_HIDDEN) == (src_stats->flags&STATS_HIDDEN))
            return;
        if (src_stats->flags & STATS_HIDDEN)
        {
            stats_node_t *ct = _find_node (src_stats->stats_tree, "content-type");
            const char *type = "audio/mpeg";
            if (ct)
                type = ct->name;
            src_stats->flags &= ~STATS_HIDDEN;
            stats_listener_send (src_stats->flags, "NEW %s %s\n", type, src_stats->source);
            visible = 1;
        }
        else
        {
            stats_listener_send (src_stats->flags, "DELETE %s\n", src_stats->source);
            src_stats->flags |= STATS_HIDDEN;
        }
        while (node)
        {
            stats_node_t *stats = (stats_node_t*)node->key;
            if (visible)
            {
                stats->flags &= ~STATS_HIDDEN;
                stats_listener_send (stats->flags, "EVENT %s %s %s\n", src_stats->source, stats->name, stats->value);
            }
            else
                stats->flags |= STATS_HIDDEN;
            node = avl_get_next (node);
        }
    }
}


static void process_source_event (stats_event_t *event)
{
    stats_source_t *snode;

    avl_tree_wlock (_stats.source_tree);
    snode = _find_source(_stats.source_tree, event->source);
    if (snode == NULL)
    {
        if (event->action == STATS_EVENT_REMOVE)
        {
            avl_tree_unlock (_stats.source_tree);
            return;
        }
        snode = (stats_source_t *)calloc(1,sizeof(stats_source_t));
        if (snode == NULL)
            abort();
        DEBUG1 ("new source stat %s", event->source);
        snode->source = (char *)strdup(event->source);
        snode->stats_tree = avl_tree_new(_compare_stats, NULL);
        snode->flags = STATS_SLAVE|STATS_GENERAL|STATS_HIDDEN;

        avl_insert(_stats.source_tree, (void *)snode);
    }
    if (event->action == STATS_EVENT_REMOVE && event->name == NULL)
    {
        int fallback_stream = 0;
        avl_tree_wlock (snode->stats_tree);
        fallback_stream = _find_node (snode->stats_tree, "fallback") == NULL ? 1 : 0;
        if (fallback_stream)
            avl_delete(_stats.source_tree, (void *)snode, _free_source_stats);
        else
            avl_tree_unlock (snode->stats_tree);
        avl_tree_unlock (_stats.source_tree);
        return;
    }
    avl_tree_wlock (snode->stats_tree);
    avl_tree_unlock (_stats.source_tree);
    process_source_stat (snode, event);
    avl_tree_unlock (snode->stats_tree);
}


void stats_set_time (long handle, const char *name, int flags, time_t tm)
{
    char buffer[100];

    util_get_clf_time (buffer, sizeof (buffer), tm);
    stats_set_flags (handle, name, buffer, flags);
}


void stats_event_time (const char *mount, const char *name, int flags)
{
    time_t now = time(NULL);
    char buffer[100];

    util_get_clf_time (buffer, sizeof (buffer), now);
    stats_event_flags (mount, name, buffer, flags);
}


static int stats_listeners_send (client_t *client)
{
    int loop = 8, total = 0;
    int ret = 0;
    event_listener_t *listener = client->shared_data;

    if (client->connection.error || global.running != ICE_RUNNING)
        return -1;
    if (client->refbuf && client->refbuf->flags & STATS_BLOCK_CONNECTION)
        loop = 4;
    else
        /* allow for 200k lag but only after 2Meg has been sent, give connection time
         * to cacth up after the large dump at the beginning */
        if (client->connection.sent_bytes > 2000000 && listener->content_len > 200000)
        {
            WARN1 ("dropping stats client, %ld in queue", listener->content_len);
            return -1;
        }
    client->schedule_ms = client->worker->time_ms;
    thread_mutex_lock (&_stats.listeners_lock);
    while (1)
    {
        refbuf_t *refbuf = client->refbuf;

        if (refbuf == NULL)
        {
            client->schedule_ms = client->worker->time_ms + 60;
            break;
        }
        if (loop == 0 || total > 32768)
            break;
        ret = format_generic_write_to_client (client);
        if (ret > 0)
        {
            total += ret;
            listener->content_len -= ret;
        }
        if (client->pos == refbuf->len)
        {
            client->refbuf = refbuf->next;
            refbuf->next = NULL;
            refbuf_release (refbuf);
            client->pos = 0;
            if (client->refbuf == NULL)
            {
                if (listener->content_len)
                    WARN1 ("content length is %u", listener->content_len);
                listener->recent_block = NULL;
                client->schedule_ms = client->worker->time_ms + 50;
                break;
            }
            loop--;
        }
        else
        {
            client->schedule_ms = client->worker->time_ms + 200;
            break; /* short write, so stop for now */
        }
    }
    thread_mutex_unlock (&_stats.listeners_lock);
    if (client->connection.error || global.running != ICE_RUNNING)
        return -1;
    return 0;
}


static void clear_stats_queue (client_t *client)
{
    refbuf_t *refbuf = client->refbuf;
    while (refbuf)
    {
        refbuf_t *to_go = refbuf;
        refbuf = to_go->next;
        if (to_go->_count != 1) DEBUG1 ("odd count for stats %d", to_go->_count);
        to_go->next = NULL;
        refbuf_release (to_go);
    }
    client->refbuf = NULL;
}


static void stats_listener_send (int mask, const char *fmt, ...)
{
    va_list ap;
    event_listener_t *listener;

    va_start(ap, fmt);

    thread_mutex_lock (&_stats.listeners_lock);
    listener = _stats.event_listeners;

    while (listener)
    {
        int admuser = listener->mask & STATS_HIDDEN,
            hidden = mask & STATS_HIDDEN,
            flags = mask & ~STATS_HIDDEN;

        if (admuser || (hidden == 0 && (flags & listener->mask)))
            _add_stats_to_stats_client (listener->client, fmt, ap);
        listener = listener->next;
    }
    thread_mutex_unlock (&_stats.listeners_lock);
    va_end(ap);
}


/* called after each xml reload */
void stats_global (ice_config_t *config)
{
    stats_event_flags (NULL, "server_id", config->server_id, STATS_GENERAL);
    stats_event_flags (NULL, "host", config->hostname, STATS_GENERAL);
    stats_event (NULL, "location", config->location);
    stats_event (NULL, "admin", config->admin);
    thread_spin_lock (&global.spinlock);
    global.max_rate = config->max_bandwidth;
    throttle_sends = 0;
    thread_spin_unlock (&global.spinlock);
}

static void process_event (stats_event_t *event)
{
    if (event == NULL)
        return;
    /* check if we are dealing with a global or source event */
    if (event->source == NULL)
        process_global_event (event);
    else
        process_source_event (event);
}


static int _append_to_bufferv (refbuf_t *refbuf, int max_len, const char *fmt, va_list ap)
{
    char *buf = (char*)refbuf->data + refbuf->len;
    int len = max_len - refbuf->len;
    int ret;
    va_list vl;

    va_copy (vl, ap);
    if (len <= 0)
        return -1;
    ret = vsnprintf (buf, len, fmt, vl);
    if (ret < 0 || ret >= len)
        return -1;
    refbuf->len += ret;
    return ret;
}

static int _append_to_buffer (refbuf_t *refbuf, int max_len, const char *fmt, ...)
{
    int ret;
    va_list va;

    va_start (va, fmt);
    ret = _append_to_bufferv (refbuf, max_len, fmt, va);
    va_end(va);
    return ret;
}


static void _add_node_to_stats_client (client_t *client, refbuf_t *refbuf)
{
    if (refbuf->len)
    {
        event_listener_t *listener = client->shared_data;

        if (listener->recent_block)
        {
            listener->recent_block->next = refbuf;
            listener->recent_block = refbuf;
        }
        else
        {
            listener->recent_block = refbuf;
            client->refbuf = refbuf;
        }
        listener->content_len += refbuf->len;
    }
}


static void _add_stats_to_stats_client (client_t *client, const char *fmt, va_list ap)
{
    event_listener_t *listener = client->shared_data;
    refbuf_t *r = listener->recent_block;

    if (r && (r->flags & STATS_BLOCK_CONNECTION) == 0)
    {
        /* lets see if we can append to an existing block */
        if (r->len < 1390)
        {
            int written = _append_to_bufferv (r, 1400, fmt, ap);
            if (written > 0)
            {
                listener->content_len += written;
                return;
            }
        }
    }
    r = refbuf_new (1400);
    r->len = 0;
    if (_append_to_bufferv (r, 1400, fmt, ap) < 0)
    {
        WARN1 ("stat details are too large \"%s\"", fmt);
        refbuf_release (r);
        return;
    }
    _add_node_to_stats_client (client, r);
    client->schedule_ms = 0;
}


static xmlNodePtr _dump_stats_to_doc (xmlNodePtr root, const char *show_mount, int flags)
{
    avl_node *avlnode;
    xmlNodePtr ret = NULL;

    /* general stats first */
    avl_tree_rlock (_stats.global_tree);
    avlnode = avl_get_first(_stats.global_tree);
    while (avlnode)
    {
        stats_node_t *stat = avlnode->key;
        if (stat->flags & flags)
            xmlNewTextChild (root, NULL, XMLSTR(stat->name), XMLSTR(stat->value));
        avlnode = avl_get_next (avlnode);
    }
    avl_tree_unlock (_stats.global_tree);
    /* now per mount stats */
    avl_tree_rlock (_stats.source_tree);
    avlnode = avl_get_first(_stats.source_tree);
    while (avlnode)
    {
        stats_source_t *source = (stats_source_t *)avlnode->key;
        if (((flags&STATS_HIDDEN) || (source->flags&STATS_HIDDEN) == (flags&STATS_HIDDEN)) &&
                (show_mount == NULL || strcmp (show_mount, source->source) == 0))
        {
            avl_node *avlnode2;
            xmlNodePtr xmlnode = xmlNewTextChild (root, NULL, XMLSTR("source"), NULL);
            avl_tree_rlock (source->stats_tree);
            avlnode2 = avl_get_first (source->stats_tree);

            xmlSetProp (xmlnode, XMLSTR("mount"), XMLSTR(source->source));
            if (ret == NULL)
                ret = xmlnode;
            while (avlnode2)
            {
                stats_node_t *stat = avlnode2->key;
                if ((flags&STATS_HIDDEN) || (stat->flags&STATS_HIDDEN) == (flags&STATS_HIDDEN))
                    xmlNewTextChild (xmlnode, NULL, XMLSTR(stat->name), XMLSTR(stat->value));
                avlnode2 = avl_get_next (avlnode2);
            }
            avl_tree_unlock (source->stats_tree);
        }
        avlnode = avl_get_next (avlnode);
    }
    avl_tree_unlock (_stats.source_tree);
    return ret;
}


/* factoring out code for stats loops
** this function copies all stats to queue, and registers 
*/
static void _register_listener (client_t *client)
{
    event_listener_t *listener = client->shared_data;
    avl_node *node;
    stats_event_t stats_count;
    refbuf_t *refbuf;
    size_t size = 8192;
    char buffer[20];

    build_event (&stats_count, NULL, "stats_connections", buffer);
    stats_count.action = STATS_EVENT_INC;
    process_event (&stats_count);

    /* first we fill our queue with the current stats */
    refbuf = refbuf_new (size);
    refbuf->len = 0;

    /* the global stats */
    avl_tree_rlock (_stats.global_tree);
    node = avl_get_first(_stats.global_tree);
    while (node)
    {
        stats_node_t *stat = node->key;

        if (stat->flags & listener->mask)
        {
            if (_append_to_buffer (refbuf, size, "EVENT global %s %s\n", stat->name, stat->value) < 0)
            {
                _add_node_to_stats_client (client, refbuf);
                refbuf = refbuf_new (size);
                refbuf->len = 0;
                continue;
            }
        }
        node = avl_get_next(node);
    }
    avl_tree_unlock (_stats.global_tree);
    /* now the stats for each source */
    avl_tree_rlock (_stats.source_tree);
    node = avl_get_first(_stats.source_tree);
    while (node)
    {
        avl_node *node2;
        stats_node_t *metadata_stat = NULL;
        stats_source_t *snode = (stats_source_t *)node->key;

        if (snode->flags & listener->mask)
        {
            stats_node_t *ct = _find_node (snode->stats_tree, "content-type");
            const char *type = "audio/mpeg";
            if (ct)
                type = ct->name;
            if (_append_to_buffer (refbuf, size, "NEW %s %s\n", type, snode->source) < 0)
            {
                _add_node_to_stats_client (client, refbuf);
                refbuf = refbuf_new (size);
                refbuf->len = 0;
                continue;
            }
        }
        node = avl_get_next(node);
        avl_tree_rlock (snode->stats_tree);
        node2 = avl_get_first(snode->stats_tree);
        while (node2)
        {
            stats_node_t *stat = node2->key;
            if (metadata_stat == NULL && strcmp (stat->name, "metadata_updated") == 0)
                metadata_stat = stat;
            else if (stat->flags & listener->mask)
            {
                if (_append_to_buffer (refbuf, size, "EVENT %s %s %s\n", snode->source, stat->name, stat->value) < 0)
                {
                    _add_node_to_stats_client (client, refbuf);
                    refbuf = refbuf_new (size);
                    refbuf->len = 0;
                    continue;
                }
            }
            node2 = avl_get_next (node2);
        }
        while (metadata_stat)
        {
            if (_append_to_buffer (refbuf, size, "EVENT %s %s %s\n", snode->source, metadata_stat->name, metadata_stat->value) < 0)
            {
                _add_node_to_stats_client (client, refbuf);
                refbuf = refbuf_new (size);
                refbuf->len = 0;
                continue;
            }
            break;
        }
        avl_tree_unlock (snode->stats_tree);
    }
    avl_tree_unlock (_stats.source_tree);
    _add_node_to_stats_client (client, refbuf);

    /* now we register to receive future event notices */
    thread_mutex_lock (&_stats.listeners_lock);
    listener->next = _stats.event_listeners;
    _stats.event_listeners = listener;
    thread_mutex_unlock (&_stats.listeners_lock);
}


static void stats_client_release (client_t *client)
{
    event_listener_t *listener, **trail;

    thread_mutex_lock (&_stats.listeners_lock);
    listener = _stats.event_listeners;
    trail = &_stats.event_listeners;

    while (listener)
    {
        if (listener == client->shared_data)
        {
            stats_event_t stats_count;
            char buffer [20];

            *trail = listener->next;
            thread_mutex_unlock (&_stats.listeners_lock);
            clear_stats_queue (client);
            free (listener->source);
            free (listener);
            client_destroy (client);
            build_event (&stats_count, NULL, "stats_connections", buffer);
            stats_count.action = STATS_EVENT_DEC;
            process_event (&stats_count);
            return;
        }
        trail = &listener->next;
        listener = listener->next;
    }
    thread_mutex_unlock (&_stats.listeners_lock);
}


struct _client_functions stats_client_send_ops =
{
    stats_listeners_send,
    stats_client_release
};

void stats_add_listener (client_t *client, int mask)
{
    event_listener_t *listener = calloc (1, sizeof (event_listener_t));
    listener->mask = mask;

    client->respcode = 200;
    client->ops = &stats_client_send_ops;
    client->shared_data = listener;
    client_set_queue (client, NULL);
    client->refbuf = refbuf_new (100);
    snprintf (client->refbuf->data, 100,
            "HTTP/1.0 200 OK\r\nCapability: streamlist stats\r\n\r\n");
    client->refbuf->len = strlen (client->refbuf->data);
    listener->content_len = client->refbuf->len;
    listener->recent_block = client->refbuf;
    listener->client = client;

    _register_listener (client);
    client->flags |= CLIENT_ACTIVE;
}


int stats_transform_xslt (client_t *client, const char *uri)
{
    xmlDocPtr doc;
    char *xslpath = util_get_path_from_normalised_uri (uri, 0);
    const char *mount = httpp_get_query_param (client->parser, "mount");
    int ret;

    if (mount == NULL && client->server_conn->shoutcast_mount && strcmp (uri, "/7.xsl") == 0)
        mount = client->server_conn->shoutcast_mount;

    doc = stats_get_xml (STATS_PUBLIC, mount);

    ret = xslt_transform (doc, xslpath, client);

    xmlFreeDoc(doc);
    free (xslpath);
    return ret;
}

xmlDocPtr stats_get_xml (int flags, const char *show_mount)
{
    xmlDocPtr doc;
    xmlNodePtr node;

    doc = xmlNewDoc (XMLSTR("1.0"));
    node = xmlNewDocNode (doc, NULL, XMLSTR("icestats"), NULL);
    xmlDocSetRootElement(doc, node);

    node = _dump_stats_to_doc (node, show_mount, flags);

    if (show_mount && node)
    {
		source_t *source;
        /* show each listener */
        avl_tree_rlock (global.source_tree);
        source = source_find_mount_raw (show_mount);

        if (source)
        {
            thread_mutex_lock (&source->lock);
            admin_source_listeners (source, node);
            thread_mutex_unlock (&source->lock);
            avl_tree_unlock (global.source_tree);
        }
        else
        {
            fbinfo finfo;

            avl_tree_unlock (global.source_tree);
            finfo.flags = FS_FALLBACK;
            finfo.mount = (char*)show_mount;
            finfo.limit = 0;
            finfo.fallback = NULL;

            fserve_list_clients_xml (node, &finfo);
        }
    }
    return doc;
}

static int _compare_stats(void *arg, void *a, void *b)
{
    stats_node_t *nodea = (stats_node_t *)a;
    stats_node_t *nodeb = (stats_node_t *)b;

    return strcmp(nodea->name, nodeb->name);
}

static int _compare_source_stats(void *arg, void *a, void *b)
{
    stats_source_t *nodea = (stats_source_t *)a;
    stats_source_t *nodeb = (stats_source_t *)b;

    return strcmp(nodea->source, nodeb->source);
}

static int _free_stats(void *key)
{
    stats_node_t *node = (stats_node_t *)key;
    free(node->value);
    free(node->name);
    free(node);
    
    return 1;
}

static int _free_source_stats(void *key)
{
    stats_source_t *node = (stats_source_t *)key;
    stats_listener_send (node->flags, "DELETE %s\n", node->source);
    DEBUG1 ("delete source node %s", node->source);
    avl_tree_unlock (node->stats_tree);
    avl_tree_free(node->stats_tree, _free_stats);
    free(node->source);
    free(node);

    return 1;
}


/* return a list of blocks which contain lines of text. Each line is a mountpoint
 * reference that a slave will use for relaying.  The prepend setting is to indicate
 * if some something else needs to be added to each line.
 */
refbuf_t *stats_get_streams (int prepend)
{
#define STREAMLIST_BLKSIZE  4096
    avl_node *node;
    unsigned int remaining = STREAMLIST_BLKSIZE, prelen;
    refbuf_t *start = refbuf_new (remaining), *cur = start;
    const char *pre = "";
    char *buffer = cur->data;

    if (prepend)
        pre = "/admin/streams?mount=";
    prelen = strlen (pre);

    /* now the stats for each source */
    avl_tree_rlock (_stats.source_tree);
    node = avl_get_first(_stats.source_tree);
    while (node)
    {
        int ret;
        stats_source_t *source = (stats_source_t *)node->key;

        if ((source->flags & STATS_HIDDEN) == 0)
        {
            if (remaining <= strlen (source->source) + prelen + 3)
            {
                cur->len = STREAMLIST_BLKSIZE - remaining;
                cur->next = refbuf_new (STREAMLIST_BLKSIZE);
                remaining = STREAMLIST_BLKSIZE;
                cur = cur->next;
                buffer = cur->data;
            }
            ret = snprintf (buffer, remaining, "%s%s\r\n", pre, source->source);
            if (ret > 0)
            {
                buffer += ret;
                remaining -= ret;
            }
        }
        node = avl_get_next(node);
    }
    avl_tree_unlock (_stats.source_tree);
    cur->len = STREAMLIST_BLKSIZE - remaining;
    return start;
}



/* This removes any source stats from virtual mountpoints, ie mountpoints
 * where no source_t exists. This function requires the global sources lock
 * to be held before calling.
 */
void stats_clear_virtual_mounts (void)
{
    avl_node *snode;

    avl_tree_wlock (_stats.source_tree);
    snode = avl_get_first(_stats.source_tree);
    while (snode)
    {
        stats_source_t *src = (stats_source_t *)snode->key;
        source_t *source = source_find_mount_raw (src->source);

        if (source == NULL)
        {
            stats_node_t *node;
            avl_tree_wlock (src->stats_tree);
            node = _find_node (src->stats_tree, "fallback");
            if (node == NULL)
            {
                /* no source_t and no fallback file stat, so delete */
                snode = avl_get_next (snode);
                avl_delete (_stats.source_tree, src, _free_source_stats);
                continue;
            }
            avl_tree_unlock (src->stats_tree);
        }

        snode = avl_get_next (snode);
    }
    avl_tree_unlock (_stats.source_tree);
}


void stats_global_calc (void)
{
    stats_event_t event;
    avl_node *anode;
    char buffer [VAL_BUFSIZE];

    connection_stats ();
    avl_tree_rlock (_stats.global_tree);
    anode = avl_get_first(_stats.global_tree);
    while (anode)
    {
        stats_node_t *node = (stats_node_t *)anode->key;

        if (node->flags & STATS_REGULAR)
            stats_listener_send (node->flags, "EVENT global %s %s\n", node->name, node->value);
        anode = avl_get_next (anode);
    }
    avl_tree_unlock (_stats.global_tree);
    build_event (&event, NULL, "outgoing_kbitrate", buffer);
    event.flags = STATS_COUNTERS|STATS_HIDDEN;

    snprintf (buffer, sizeof(buffer), "%" PRIu64,
            (int64_t)global_getrate_avg (global.out_bitrate) * 8 / 1024);
    process_event (&event);
}


long stats_handle (const char *mount)
{
    stats_source_t *src_stats;

    if (mount == NULL)
        return 0;
    avl_tree_wlock (_stats.source_tree);
    src_stats = _find_source(_stats.source_tree, mount);
    if (src_stats == NULL)
    {
        src_stats = (stats_source_t *)calloc (1, sizeof (stats_source_t));
        if (src_stats == NULL)
            abort();
        DEBUG1 ("new source stat %s", mount);
        src_stats->source = (char *)strdup (mount);
        src_stats->stats_tree = avl_tree_new (_compare_stats, NULL);
        src_stats->flags = STATS_SLAVE|STATS_GENERAL|STATS_HIDDEN;

        avl_insert (_stats.source_tree, (void *)src_stats);
    }
    avl_tree_wlock (src_stats->stats_tree);
    avl_tree_unlock (_stats.source_tree);

    return (long)src_stats;
}


long stats_lock (long handle, const char *mount)
{
    stats_source_t *src_stats = (stats_source_t *)handle;
    if (src_stats == NULL)
        src_stats = (stats_source_t*)stats_handle (mount);
    else
        avl_tree_wlock (src_stats->stats_tree);
    return (long)src_stats;
}


void stats_release (long handle)
{
    stats_source_t *src_stats = (stats_source_t *)handle;
    if (src_stats)
        avl_tree_unlock (src_stats->stats_tree);
}


// assume source stats are write locked 
void stats_set (long handle, const char *name, const char *value)
{
    if (handle)
    {
        stats_source_t *src_stats = (stats_source_t *)handle;
        stats_event_t event;

        build_event (&event, src_stats->source, name, (char *)value);
        process_source_stat (src_stats, &event);
    }
}


void stats_set_args (long handle, const char *name, const char *format, ...)
{
    va_list val;
    int ret;
    stats_source_t *src_stats = (stats_source_t *)handle;
    char buf[1024];

    if (name == NULL)
        return;
    va_start (val, format);
    ret = vsnprintf (buf, sizeof (buf), format, val);
    va_end (val);

    if (ret < 0 || (unsigned int)ret >= sizeof (buf))
    {
        WARN2 ("problem with formatting %s stat %s",
                src_stats == NULL ? "global" : src_stats->source, name);
        return;
    }
    stats_set (handle, name, buf);
}


void stats_set_flags (long handle, const char *name, const char *value, int flags)
{
    stats_source_t *src_stats = (stats_source_t *)handle;
    stats_event_t event;

    build_event (&event, src_stats->source, name, value);
    event.flags = flags;
    if (value)
        event.action |= STATS_EVENT_HIDDEN;
    else
        event.action = STATS_EVENT_HIDDEN;
    process_source_stat (src_stats, &event);
}


static xmlParserCtxtPtr get_parser_for_decode (const char *value)
{
    char semi = '\0';
    const char *p = strchr (value, '&');

    if (p)
    {
        if (sscanf (p, "&%*7[^; ]%c", &semi) == 1 && semi == ';')
            return xmlNewParserCtxt();
    }
    return NULL;
}


static void stats_set_entity_decode (long handle, const char *name, const char *value)
{
    xmlParserCtxtPtr parser = get_parser_for_decode (value);

    if (parser)
    {
        xmlChar *decoded = xmlStringDecodeEntities (parser,
                (const xmlChar *) value, XML_SUBSTITUTE_BOTH, 0, 0, 0);
        stats_set (handle, name, (void*)decoded);
        xmlFreeParserCtxt (parser);
        xmlFree (decoded);
        return;
    }
    stats_set (handle, name, value);
}


void stats_set_conv (long handle, const char *name, const char *value, const char *charset)
{
    if (charset)
    {
        xmlCharEncodingHandlerPtr encoding = xmlFindCharEncodingHandler (charset);

        if (encoding)
        {
            xmlBufferPtr in = xmlBufferCreate ();
            xmlBufferPtr conv = xmlBufferCreate ();

            xmlBufferCCat (in, value);
            if (xmlCharEncInFunc (encoding, conv, in) > 0)
                stats_set_entity_decode (handle, name, (void*)xmlBufferContent (conv));
            xmlBufferFree (in);
            xmlBufferFree (conv);
            xmlCharEncCloseFunc (encoding);
            return;
        }
        WARN1 ("No charset found for \"%s\"", charset);
        return;
    }
    stats_set_entity_decode (handle, name, value);
}


void stats_listener_to_xml (client_t *listener, xmlNodePtr parent)
{
    const char *useragent;
    char buf[30];

    xmlNodePtr node = xmlNewChild (parent, NULL, XMLSTR("listener"), NULL);

    snprintf (buf, sizeof (buf), "%lu", listener->connection.id);
    xmlSetProp (node, XMLSTR("id"), XMLSTR(buf));

    xmlNewChild (node, NULL, XMLSTR("IP"), XMLSTR(listener->connection.ip));

    useragent = httpp_getvar (listener->parser, "user-agent");
    if (useragent && xmlCheckUTF8((unsigned char *)useragent))
    {
        xmlChar *str = xmlEncodeEntitiesReentrant (parent->doc, XMLSTR(useragent));
        xmlNewChild (node, NULL, XMLSTR("UserAgent"), str);
        xmlFree (str);
    }

    if ((listener->flags & (CLIENT_ACTIVE|CLIENT_IN_FSERVE)) == CLIENT_ACTIVE)
    {
        source_t *source = listener->shared_data;
        snprintf (buf, sizeof (buf), "%"PRIu64, source->client->queue_pos - listener->queue_pos);
    }
    else
        snprintf (buf, sizeof (buf), "0");
    xmlNewChild (node, NULL, XMLSTR("lag"), XMLSTR(buf));

    if (listener->worker)
    {
        snprintf (buf, sizeof (buf), "%lu",
                (unsigned long)(listener->worker->current_time.tv_sec - listener->connection.con_time));
        xmlNewChild (node, NULL, XMLSTR("Connected"), XMLSTR(buf));
    }
    if (listener->username)
    {
        xmlChar *str = xmlEncodeEntitiesReentrant (parent->doc, XMLSTR(listener->username));
        xmlNewChild (node, NULL, XMLSTR("username"), str);
        xmlFree (str);
    }
}

