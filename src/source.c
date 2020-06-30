/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2014, Karl Heyes <karl@kheyes.plus.com>
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org>,
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

/* -*- c-basic-offset: 4; indent-tabs-mode: nil; -*- */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#include "compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <ogg/ogg.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include "thread/thread.h"
#include "avl/avl.h"
#include "httpp/httpp.h"
#include "net/sock.h"

#include "connection.h"
#include "global.h"
#include "refbuf.h"
#include "client.h"
#include "stats.h"
#include "logging.h"
#include "cfgfile.h"
#include "util.h"
#include "source.h"
#include "format.h"
#include "fserve.h"
#include "auth.h"
#include "slave.h"

#undef CATMODULE
#define CATMODULE "source"

#define MAX_FALLBACK_DEPTH 10


/* avl tree helper */
static void _parse_audio_info (source_t *source, const char *s);
static void source_client_release (client_t *client);
static int  source_listener_release (source_t *source, client_t *client);
static int  source_client_read (client_t *client);
static int  source_client_shutdown (client_t *client);
static int  source_client_http_send (client_t *client);
static int  send_to_listener (client_t *client);
static int  send_listener (source_t *source, client_t *client);
static int  wait_for_restart (client_t *client);
static int  wait_for_other_listeners (client_t *client);

static int  http_source_listener (client_t *client);
static int  http_source_intro (client_t *client);
static int  http_source_introfile (client_t *client);
static int  locate_start_on_queue (source_t *source, client_t *client);
static int  listener_change_worker (client_t *client, source_t *source);
static int  source_change_worker (source_t *source, client_t *client);
static int  source_client_callback (client_t *client);
static int  source_set_override (mount_proxy *mountinfo, source_t *dest_source, format_type_t type);

#ifdef _WIN32
#define source_run_script(x,y)  WARN0("on [dis]connect scripts disabled");
#else
static void source_run_script (char *command, char *mountpoint);
#endif

struct _client_functions source_client_ops = 
{
    source_client_read,
    client_destroy
};

struct _client_functions source_client_halt_ops = 
{
    source_client_shutdown,
    source_client_release
};

struct _client_functions listener_client_ops = 
{
    send_to_listener,
    client_destroy
};

struct _client_functions listener_pause_ops = 
{
    wait_for_restart,
    client_destroy
};

struct _client_functions listener_wait_ops = 
{
    wait_for_other_listeners,
    client_destroy
};

struct _client_functions source_client_http_ops =
{
    source_client_http_send,
    source_client_release
};


/* Allocate a new source with the stated mountpoint, if one already
 * exists with that mountpoint in the global source tree then return
 * NULL.
 */
source_t *source_reserve (const char *mount, int flags)
{
    source_t *src = NULL;

    do
    {
        avl_tree_wlock (global.source_tree);
        src = source_find_mount_raw (mount);
        if (src)
        {
            if ((flags & 1) == 0)
                src = NULL;
            else if (src->flags & SOURCE_LISTENERS_SYNC)
                src = NULL;
            break;
        }

        src = calloc (1, sizeof(source_t));
        if (src == NULL)
            break;

        /* make duplicates for strings or similar */
        src->mount = strdup (mount);
        src->listener_send_trigger = 16000;
        src->format = calloc (1, sizeof(format_plugin_t));
        src->clients = avl_tree_new (client_compare, NULL);
        src->intro_file = -1;
        src->preroll_log_id = -1;

        thread_rwlock_create (&src->lock);
        thread_spin_create (&src->shrink_lock);
        src->flags |= SOURCE_RESERVED;

        avl_insert (global.source_tree, src);

    } while (0);

    if (src)
        thread_rwlock_wlock (&src->lock);
    avl_tree_unlock (global.source_tree);
    return src;
}


/* Find a mount with this raw name - ignoring fallbacks. You should have the
 * global source tree locked to call this.
 */
source_t *source_find_mount_raw(const char *mount)
{
    source_t *source;
    avl_node *node;
    int cmp;

    if (!mount) {
        return NULL;
    }
    /* get the root node */
    node = global.source_tree->root->right;
    
    while (node) {
        source = (source_t *)node->key;
        cmp = strcmp (mount, source->mount);
        if (cmp < 0) 
            node = node->left;
        else if (cmp > 0)
            node = node->right;
        else
            return source;
    }
    
    /* didn't find it */
    return NULL;
}


/* Search for mount, if the mount is there but not currently running then
 * check the fallback, and so on.  Must have a global source lock to call
 * this function.
 */
source_t *source_find_mount (const char *mount)
{
    source_t *source = NULL;
    ice_config_t *config;
    mount_proxy *mountinfo;
    int depth = 0;

    config = config_get_config();
    while (mount && depth < MAX_FALLBACK_DEPTH)
    {
        source = source_find_mount_raw (mount);

        if (source)
        {
            if (source_available (source))
                break;
        }

        /* we either have a source which is not active (relay) or no source
         * at all. Check the mounts list for fallback settings
         */
        mountinfo = config_find_mount (config, mount);
        source = NULL;

        if (mountinfo == NULL)
            break;
        mount = mountinfo->fallback_mount;
        depth++;
    }

    config_release_config();
    return source;
}


int source_compare_sources(void *arg, void *a, void *b)
{
    source_t *srca = (source_t *)a;
    source_t *srcb = (source_t *)b;

    return strcmp(srca->mount, srcb->mount);
}


void source_clear_source (source_t *source)
{
    DEBUG2 ("clearing source \"%s\" %p", source->mount, source);

    if (source->dumpfile)
    {
        INFO1 ("Closing dumpfile for %s", source->mount);
        fclose (source->dumpfile);
        source->dumpfile = NULL;
    }

    /* flush out the stream data, we don't want any left over */
    while (source->stream_data)
    {
        refbuf_t *to_go = source->stream_data;
        source->stream_data = to_go->next;
        to_go->next = NULL;
        if (source->format->detach_queue_block)
            source->format->detach_queue_block (source, to_go);
        refbuf_release (to_go);
    }
    source->min_queue_point = NULL;
    source->stream_data_tail = NULL;

    source->min_queue_size = 0;
    source->min_queue_offset = 0;
    source->default_burst_size = 0;
    source->queue_size = 0;
    source->queue_size_limit = 0;
    source->client_stats_update = 0;
    source->shrink_pos = 0;
    source->shrink_time = 0;
    util_dict_free (source->audio_info);
    source->audio_info = NULL;
    rate_free (source->out_bitrate);
    source->out_bitrate = NULL;
    rate_free (source->in_bitrate);
    source->in_bitrate = NULL;

    free(source->dumpfilename);
    source->dumpfilename = NULL;

    free (source->intro_filename);
    source->intro_filename = NULL;
    file_close (&source->intro_file);
    log_close (source->preroll_log_id);
    source->preroll_log_id = -1;
}


/* the internal free function. at this point we know the source is
 * not on the source tree */
static int _free_source (void *p)
{
    source_t *source = p;
    source_clear_source (source);

    /* make sure all YP entries have gone */
    yp_remove (source->mount);

    /* There should be no listeners on this mount */
    if (source->listeners)
        WARN3("active listeners on mountpoint %s (%ld, %ld)", source->mount, source->listeners, source->termination_count);
    avl_tree_free (source->clients, NULL);

    thread_rwlock_unlock (&source->lock);
    thread_rwlock_destroy (&source->lock);
    thread_spin_destroy (&source->shrink_lock);

    INFO1 ("freeing source \"%s\"", source->mount);
    format_plugin_clear (source->format, source->client);

    cached_prune (source->intro_ipcache);
    free (source->intro_ipcache);
    source->intro_ipcache = NULL;

    free (source->format);
    free (source->mount);
    free (source);
    return 1;
}


// drop source from tree, so it cannot be found by name. No lock on source on entry but
// lock still active on return (stats cleared)
static void drop_source_from_tree (source_t *source)
{
    if (source->flags & SOURCE_RESERVED)
    {
        avl_tree_wlock (global.source_tree);
        avl_delete (global.source_tree, source, NULL);

        source->flags &= ~SOURCE_RESERVED;
        // this is only called from the sources client processing
        if (source->stats)
        {
            DEBUG1 ("stats still referenced on %s", source->mount);
            stats_lock (source->stats, source->mount);
            stats_set (source->stats, NULL, NULL);
            source->stats = 0;
        }
        avl_tree_unlock (global.source_tree);
        DEBUG2 ("removed source %s (%p) from tree", source->mount, source);
    }
    thread_rwlock_wlock (&source->lock);
}


/* Remove the provided source from the global tree and free it */
void source_free_source (source_t *source)
{
    //INFO1 ("source %s to be freed", source->mount);
    drop_source_from_tree (source);
    _free_source (source);
}


client_t *source_find_client(source_t *source, uint64_t id)
{
    client_t fakeclient;
    void *result = NULL;

    fakeclient.connection.id = id;

    avl_get_by_key (source->clients, &fakeclient, &result);
    return result;
}

static void listener_skips_intro (cache_file_contents *cache, client_t *client, int allow)
{
    struct node_IP_time *result = calloc (1, sizeof (struct node_IP_time));

    snprintf (result->ip, sizeof (result->ip), "%s", client->connection.ip);
    result->a.timeout = client->worker->current_time.tv_sec + allow;
    avl_insert (cache->contents, result);
    DEBUG1 ("Added intro skip entry for %s", &result->ip[0]);
}


static int listener_check_intro (cache_file_contents *cache, client_t *client, int allow)
{
    int i, ret = 0;

    if (cache == NULL || cache->contents == NULL)
        return 0;
    cache->deletions_count = 0;
    do
    {
        struct node_IP_time *result;
        const char *ip = client->connection.ip;
        time_t now = client->worker->current_time.tv_sec;

        cache->file_recheck = now;
        if (avl_get_by_key (cache->contents, (char*)ip, (void*)&result) == 0)
        {
            ret = 1;
            if (result->a.timeout > now)
            {
                DEBUG1 ("skipping intro for %s", result->ip);
                client->intro_offset = -1;
                break;
            }
            DEBUG1 ("found intro skip entry for %s, refreshing", result->ip);
            result->a.timeout = now + allow;
        }
    } while (0);

    for (i = 0; i < cache->deletions_count; ++i)
    {
        struct node_IP_time *to_go = cache->deletions[i];

        INFO1 ("removing %s from intro list", &(to_go->ip[0]));
        avl_delete (cache->contents, &(to_go->ip[0]), cached_treenode_free);
    }
    return ret;
}


uint32_t source_convert_qvalue (source_t *source, uint32_t value)
{
    if (value & 0x80000000)
    {   // so in secs;
        value &= ~0x80000000;
        return source->incoming_rate * value;
    }
    return value;
}


/* Update stats from source processing, this should be called regulary (every
 * few seconds) to keep totals up to date.
 */
static void update_source_stats (source_t *source)
{
    unsigned long incoming_rate = (long)rate_avg (source->in_bitrate);
    unsigned long kbytes_sent = (source->format->sent_bytes - source->bytes_sent_at_update)/1024;
    unsigned long kbytes_read = source->bytes_read_since_update/1024;

    stats_lock (source->stats, source->mount);
    stats_set_args (source->stats, "outgoing_kbitrate", "%ld",
            (long)(8 * rate_avg (source->out_bitrate))/1024);
    stats_set_args (source->stats, "incoming_bitrate", "%ld", (8 * incoming_rate));
    stats_set_args (source->stats, "total_bytes_read", "%"PRIu64, source->format->read_bytes);
    stats_set_args (source->stats, "total_bytes_sent", "%"PRIu64, source->format->sent_bytes);
    stats_set_args (source->stats, "total_mbytes_sent",
            "%"PRIu64, source->format->sent_bytes/(1024*1024));
    stats_set_args (source->stats, "queue_size", "%u", source->queue_size);
    if (source->client->connection.con_time)
    {
        worker_t *worker = source->client->worker;
        stats_set_args (source->stats, "connected", "%"PRIu64,
                (uint64_t)(worker->current_time.tv_sec - source->client->connection.con_time));
    }
    stats_release (source->stats);
    stats_event_add (NULL, "stream_kbytes_sent", kbytes_sent);
    stats_event_add (NULL, "stream_kbytes_read", kbytes_read);
    if (incoming_rate)
    {
        int log = 0;
        uint32_t qlen = (float)source_convert_qvalue (source, source->queue_len_value);
        if (qlen > 0)
        {
            float ratio = source->queue_size_limit / (float)qlen;
            if (ratio < 0.85 || ratio > 1.15)
                log = 1;    // sizeable change in result so log it
        }
        source->queue_size_limit = qlen;
        source->min_queue_size = source_convert_qvalue (source, source->min_queue_len_value);
        source->default_burst_size = source_convert_qvalue (source, source->default_burst_value);
        //DEBUG3 ("%s, burst %d, %d", source->mount, (source->default_burst_value&(1<<31))?1:0, source->default_burst_value&(~(1<<31)));

        // sanity checks
        if (source->default_burst_size > 50000000)
            source->default_burst_size = 100000;
        if (source->queue_size_limit > 1000000000)
            source->queue_size_limit = 1000000;
        if (source->min_queue_size > 50000000 || source->min_queue_size < source->default_burst_size)
            source->min_queue_size = source->default_burst_size;
        if (source->min_queue_size + (incoming_rate<<2) > source->queue_size_limit)
        {
            source->queue_size_limit = source->min_queue_size + (incoming_rate<<2);
            INFO1 ("Adjusting queue size limit higher to allow for a minimum on %s", source->mount);
            source->queue_len_value = source->queue_size_limit;
        }

        if (log)
        {
            DEBUG2 ("%s queue size set to %u", source->mount, source->queue_size_limit);
            DEBUG2 ("%s min queue size set to %u", source->mount, source->min_queue_size);
            DEBUG2 ("%s burst size set to %u", source->mount, source->default_burst_size);
        }
    }

    source->bytes_sent_at_update = source->format->sent_bytes;
    source->bytes_read_since_update %= 1024;
    source->listener_send_trigger = incoming_rate < 8000 ? 8000 : (8000 + (incoming_rate>>4));
    if (incoming_rate)
        source->incoming_adj = 2000000/incoming_rate;
    else
        source->incoming_adj = 20;
    source->stats_interval = 5 + (global.sources >> 10);
}


void source_add_queue_buffer (source_t *source, refbuf_t *r)
{
    source->bytes_read_since_update += r->len;

    r->flags |= SOURCE_QUEUE_BLOCK;

    /* append buffer to the in-flight data queue,  */
    if (source->stream_data == NULL)
    {
        mount_proxy *mountinfo = config_find_mount (config_get_config(), source->mount);
        if (mountinfo)
        {
            source_set_intro (source, mountinfo->intro_filename);
            source_set_override (mountinfo, source, source->format->type);
        }
        config_release_config();

        source->stream_data = r;
        source->min_queue_point = r;
        source->min_queue_offset = 0;
    }
    if (source->stream_data_tail)
        source->stream_data_tail->next = r;
    source->buffer_count++;

    source->stream_data_tail = r;
    source->queue_size += r->len;
    source->wakeup = 1;

    /* move the starting point for new listeners */
    source->min_queue_offset += r->len;

    if ((source->buffer_count & 3) == 3)
        source->incoming_rate = (long)rate_avg (source->in_bitrate);

    /* save stream to file */
    if (source->dumpfile && source->format->write_buf_to_file)
        source->format->write_buf_to_file (source, r);

    if (source->shrink_time == 0 && (source->buffer_count & 31) == 31)
    {
        // kick off timed response to find oldest buffer. Every so many buffers
        source->shrink_pos = source->client->queue_pos - source->min_queue_offset;
        source->shrink_time = source->client->worker->time_ms + 600;
    }
}


/* get some data from the source. The stream data is placed in a refbuf
 * and sent back, however NULL is also valid as in the case of a short
 * timeout and there's no data pending.
 */
int source_read (source_t *source)
{
    client_t *client = source->client;
    refbuf_t *refbuf = NULL;
    int skip = 1, loop = 1;
    time_t current = client->worker->current_time.tv_sec;
    unsigned long queue_size_target = 0;
    int fds = 0;

    if (global.running != ICE_RUNNING)
        source->flags &= ~SOURCE_RUNNING;
    do
    {
        source->wakeup = 0;
        client->schedule_ms = client->worker->time_ms;
        if (source->flags & SOURCE_LISTENERS_SYNC)
        {
            if (source->termination_count > 0)
            {
                if (client->timer_start + 1000 < client->worker->time_ms)
                {
                    source->flags &= ~(SOURCE_RUNNING|SOURCE_LISTENERS_SYNC);
                    WARN1 ("stopping %s as sync mode lasted too long", source->mount);
                }
                client->schedule_ms += 30;
                return 0;
            }
            if (source->fallback.mount)
            {
                DEBUG1 ("listeners have now moved to %s", source->fallback.mount);
                free (source->fallback.mount);
                source->fallback.mount = NULL;
            }
            source->flags &= ~SOURCE_LISTENERS_SYNC;
        }
        rate_add (source->out_bitrate, 0, client->worker->time_ms);
        global_add_bitrates (global.out_bitrate, 0, client->worker->time_ms);

        if (source->prev_listeners != source->listeners)
        {
            INFO2("listener count on %s now %lu", source->mount, source->listeners);
            source->prev_listeners = source->listeners;
            stats_lock (source->stats, source->mount);
            stats_set_args (source->stats, "listeners", "%lu", source->listeners);
            if (source->listeners > source->peak_listeners)
            {
                source->peak_listeners = source->listeners;
                stats_set_args (source->stats, "listener_peak", "%lu", source->peak_listeners);
            }
            stats_release (source->stats);
        }
        if (current >= source->client_stats_update)
        {
            update_source_stats (source);
            if (current - client->connection.con_time < source->stats_interval)
                source->client_stats_update = current + 1;
            else
                source->client_stats_update = current + source->stats_interval;
            if (source_change_worker (source, client))
                return 1;
        }

        fds = util_timed_wait_for_fd (client->connection.sock, 0);
        if (fds < 0)
        {
            if (! sock_recoverable (sock_error()))
            {
                WARN0 ("Error while waiting on socket, Disconnecting source");
                source->flags &= ~SOURCE_RUNNING;
                return 0;
            }
            break;
        }
        if (fds == 0)
        {
            if (source->last_read + (time_t)3 == current)
                WARN1 ("Nothing received on %s for 3 seconds", source->mount);
            if (source->last_read + (time_t)source->timeout < current)
            {
                DEBUG3 ("last %ld, timeout %d, now %ld", (long)source->last_read,
                        source->timeout, (long)current);
                WARN1 ("Disconnecting %s due to socket timeout", source->mount);
                source->flags &= ~SOURCE_RUNNING;
                source->flags |= SOURCE_TIMEOUT;
                return 0;
            }
            source->skip_duration = (int)((source->skip_duration + 12) * 1.1);
            if (source->skip_duration > 400)
                source->skip_duration = 400;
            break;
        }

        source->last_read = current;
        unsigned int prev_qsize = source->queue_size;
        do
        {
            refbuf = source->format->get_buffer (source);
            if (refbuf)
                source_add_queue_buffer (source, refbuf);

            skip = 0;

            if (client->connection.error)
            {
                INFO1 ("End of Stream %s", source->mount);
                source->flags &= ~SOURCE_RUNNING;
                return 0;
            }
            loop--;
        } while (loop);

        if (source->queue_size != prev_qsize)
        {
            uint64_t sync_off = source->min_queue_offset, off = sync_off;
            refbuf_t *sync_point = source->min_queue_point, *ref = sync_point;
            while (off > source->min_queue_size)
            {
                refbuf_t *to_release = ref;
                if (to_release && to_release->next)
                {
                    if (to_release->flags & SOURCE_BLOCK_SYNC)
                    {
                        sync_off = off;
                        sync_point = ref;
                    }
                    off -= to_release->len;
                    ref = to_release->next;
                    continue;
                }
                break;
            }
            source->min_queue_offset = sync_off;
            source->min_queue_point = sync_point;
            source->skip_duration = (long)(source->skip_duration * 0.9);
        }

        if (source->shrink_time)
        {
            if (source->shrink_time > client->worker->time_ms)
                break;      // not time yet to consider the purging point
            queue_size_target = (source->client->queue_pos - source->shrink_pos);
            source->shrink_pos = 0;
            source->shrink_time = 0;
        }
        /* lets see if we have too much/little data in the queue */
        if ((queue_size_target < source->min_queue_size) || (queue_size_target > source->queue_size_limit))
            queue_size_target = (source->listeners) ? source->queue_size_limit : source->min_queue_size;

        loop = 48 + (source->incoming_rate >> 13); // scale max on high bitrates
        queue_size_target += 8000; // lets not be too tight to the limit
        while (source->queue_size > queue_size_target && loop)
        {
            refbuf_t *to_go = source->stream_data;
            if (to_go == NULL || to_go->next == NULL) // always leave at least one on the queue
                break;
            source->stream_data = to_go->next;
            source->queue_size -= to_go->len;
            if (source->min_queue_point == to_go)
            {
                // adjust min queue in line with expectations
                source->min_queue_offset -= to_go->len;
                source->min_queue_point = to_go->next;
            }
            to_go->next = NULL;
            if (source->format->detach_queue_block)
                source->format->detach_queue_block (source, to_go);
            refbuf_release (to_go);
            loop--;
        }
    } while (0);

    if (skip)
        client->schedule_ms += source->skip_duration;
    return 0;
}


void source_listeners_wakeup (source_t *source)
{
    client_t *s = source->client;
    avl_node *node = avl_get_first (source->clients);
    while (node)
    {
        client_t *client = (client_t *)node->key;
        if (s->schedule_ms + 100 < client->schedule_ms)
            DEBUG2 ("listener on %s was ahead by %ld", source->mount, (long)(client->schedule_ms - s->schedule_ms));
        client->schedule_ms = 0;
        node = avl_get_next (node);
    }
}


static int source_client_read (client_t *client)
{
    source_t *source = client->shared_data;

    if (source == NULL)
    {
        INFO1 ("source client from %s hijacked", client->connection.ip);
        return -1;
    }

    thread_rwlock_wlock (&source->lock);
    if (client->connection.discon.time &&
            client->connection.discon.time <= client->worker->current_time.tv_sec)
    {
        source->flags &= ~SOURCE_RUNNING;
        INFO1 ("streaming duration expired on %s", source->mount);
    }
    if (source_running (source))
    {
        if (source->limit_rate)
        {
            if (source->limit_rate < (8 * source->incoming_rate) && global.running == ICE_RUNNING)
            {
                rate_add (source->in_bitrate, 0, client->worker->current_time.tv_sec);
                source->incoming_rate = (long)rate_avg (source->in_bitrate);
                thread_rwlock_unlock (&source->lock);
                client->schedule_ms += 310;
                return 0;
            }
        }
        if (source_read (source) > 0)
            return 1;
        if (source_running (source))
        {
            thread_rwlock_unlock (&source->lock);
            return 0;
        }
    }
    if ((source->flags & SOURCE_TERMINATING) == 0)
    {
        source_shutdown (source, 1);

        if (source->wait_time == 0)
        {
            thread_rwlock_unlock (&source->lock);
            drop_source_from_tree (source);
        }
    }

    if (source->termination_count && source->termination_count <= (long)source->listeners)
    {
        if (client->timer_start + 1000 < client->worker->time_ms)
        {
            WARN2 ("%ld listeners still to process in terminating %s", source->termination_count, source->mount); 
            if (source->listeners != source->clients->length)
            {
                WARN3 ("source %s has inconsistent listeners (%ld, %u)", source->mount, source->listeners, source->clients->length);
                source->listeners = source->clients->length;
            }
            source->flags &= ~SOURCE_TERMINATING;
        }
        else
            DEBUG4 ("%p %s waiting (%lu, %lu)", source, source->mount, source->termination_count, source->listeners);
        client->schedule_ms = client->worker->time_ms + 50;
    }
    else
    {
        if (source->listeners)
        {
            INFO1 ("listeners on terminating source %s, rechecking", source->mount);
            source->termination_count = source->listeners;
            client->timer_start = client->worker->time_ms;
            source->flags &= ~SOURCE_PAUSE_LISTENERS;
            source->flags |= (SOURCE_TERMINATING|SOURCE_LISTENERS_SYNC);
            source_listeners_wakeup (source);
            thread_rwlock_unlock (&source->lock);
            return 0;
        }
        free (source->fallback.mount);
        source->fallback.mount = NULL;
        source->flags &= ~SOURCE_LISTENERS_SYNC;
        client->connection.discon.time = 0;
        client->ops = &source_client_halt_ops;
        global_lock();
        global.sources--;
        stats_event_args (NULL, "sources", "%d", global.sources);
        global_unlock();
        if (source->wait_time == 0 || global.running != ICE_RUNNING)
        {
            INFO1 ("no more listeners on %s", source->mount);
            return -1;   // don't unlock source as the release is called which requires it
        }
        /* set a wait time for leaving the source reserved */
        client->connection.discon.time = client->worker->current_time.tv_sec + source->wait_time;
        client->schedule_ms = client->worker->time_ms + (1000 * source->wait_time);
        INFO2 ("listeners gone, keeping %s reserved for %ld seconds", source->mount, (long)source->wait_time);
    }
    thread_rwlock_unlock (&source->lock);
    return 0;
}


void source_add_bytes_sent (struct rate_calc *out_bitrate, unsigned long written, uint64_t milli, uint64_t *sent_bytes)
{
    rate_add_sum (out_bitrate, written, milli, sent_bytes);
    global_add_bitrates (global.out_bitrate, written, milli);
}


static int source_queue_advance (client_t *client)
{
    static unsigned char offset = 0;
    unsigned long written = 0;
    source_t *source = client->shared_data;
    refbuf_t *refbuf;
    uint64_t lag;

    if (client->refbuf == NULL && locate_start_on_queue (source, client) < 0)
        return -1;

    lag = source->client->queue_pos - client->queue_pos;

    if (client->flags & CLIENT_HAS_INTRO_CONTENT) abort(); // trap

    if (lag == 0)
    {
        // most listeners will be through here, so a minor spread should limit a wave of sends
        int ret = (offset & 31);
        offset++;   // this can be a race as it helps for randomizing
        client->schedule_ms += 5 + ((source->incoming_adj>>1) + ret);
        client->wakeup = &source->wakeup; // allow for quick wakeup
        return -1;
    }
    client->wakeup = NULL;
    if (lag > source->queue_size || (lag == source->queue_size && client->pos))
    {
        INFO4 ("Client %" PRIu64 " (%s) has fallen too far behind (%"PRIu64") on %s, removing",
                client->connection.id, client->connection.ip, client->queue_pos, source->mount);
        stats_lock (source->stats, source->mount);
        stats_set_inc (source->stats, "slow_listeners");
        stats_release (source->stats);
        client->refbuf = NULL;
        client->connection.error = 1;
        return -1;
    }
    if ((lag+source->incoming_rate) > source->queue_size_limit && client->connection.error == 0)
    {
        // if the listener is really lagging but has been received a decent
        // amount of data then allow a requeue, else allow the drop
        if (client->counter > (source->queue_size_limit << 1))
        {
            const char *p = httpp_get_query_param (client->parser, "norequeue");
            if (p == NULL)
            {
                // we may need to copy the complete frame for private use
                if (client->pos < client->refbuf->len)
                {
                    refbuf_t *copy = source->format->qblock_copy (client->refbuf);
                    client->refbuf = copy;
                    client->flags |= CLIENT_HAS_INTRO_CONTENT;
                    DEBUG2 ("client %s requeued copy on %s", client->connection.ip, source->mount);
                }
                else
                {
                    client->refbuf = NULL;
                    client->pos = 0;
                }
                client->timer_start = 0;
                client->check_buffer = http_source_introfile;
                // do not be too eager to refill socket buffer
                client->schedule_ms += source->incoming_rate < 16000 ? source->incoming_rate/16 : 800;
                return -1;
            }
        }
    }
    int loop = 50;
    while (--loop)
    {
        refbuf = client->refbuf;
        if ((refbuf->flags & SOURCE_QUEUE_BLOCK) == 0 || refbuf->len > 66000)  abort();

        int ret = 0;

        if (client->pos < refbuf->len)
            ret = source->format->write_buf_to_client (client);
        if (ret > 0)
            written += ret;
        if (client->pos >= refbuf->len)
        {
            if (refbuf->next)
            {
                client->refbuf = refbuf->next;
                client->pos = 0;
                continue;
            }
        }
        break;
    }
    if (written)
        source_add_bytes_sent (source->out_bitrate, written, client->worker->time_ms, &source->format->sent_bytes);
    return -1;
}


static int locate_start_on_queue (source_t *source, client_t *client)
{
    refbuf_t *refbuf;
    long lag = 0;

    /* we only want to attempt a burst at connection time, not midstream
     * however streams like theora may not have the most recent page marked as
     * a starting point, so look for one from the burst point */
    if (client->connection.error || source->stream_data_tail == NULL)
        return -1;
    refbuf = source->stream_data_tail;
    if (client->connection.sent_bytes > source->min_queue_offset && (refbuf->flags & SOURCE_BLOCK_SYNC))
    {
        lag = refbuf->len;
    }
    else
    {
        size_t size = source->min_queue_size;
        uint32_t v = -1;
        const char *param = httpp_getvar (client->parser, "initial-burst");

        if (param)
            config_qsizing_conv_a2n (param, &v);
        else
        {
            param = httpp_get_query_param (client->parser, "burst");
            if (param)
                config_qsizing_conv_a2n (param, &v);
        }
        if (param)
        {
            v = source_convert_qvalue (source, (uint32_t)v);
            DEBUG4 ("listener from %s (on %s) requested burst (%s, %u)", &client->connection.ip[0], source->mount, param, v);
        }
        else
            v = source->default_burst_size;

        if (v > client->connection.sent_bytes)
        {
            v -= client->connection.sent_bytes; /* have we sent data already */
            refbuf = source->min_queue_point;
            lag = source->min_queue_offset;
            // DEBUG3 ("size %lld, v %lld, lag %ld", size, v, lag);
            while (size > v && refbuf && refbuf->next)
            {
                size -= refbuf->len;
                lag -= refbuf->len;
                refbuf = refbuf->next;
            }
            if (lag < 0)
                ERROR1 ("Odd, lag is negative %ld", lag);
        }
        else
            lag = refbuf->len;
    }

    while (refbuf)
    {
        if (refbuf->flags & SOURCE_BLOCK_SYNC)
        {
            client_set_queue (client, NULL);
            client->refbuf = refbuf;
            client->intro_offset = -1;
            client->pos = 0;
            client->counter = 0;
            client->queue_pos = source->client->queue_pos - lag;
            client->flags &= ~CLIENT_HAS_INTRO_CONTENT;
            DEBUG4 ("%s Joining queue on %s (%"PRIu64 ", %"PRIu64 ")", &client->connection.ip[0], source->mount, source->client->queue_pos, client->queue_pos);
            return 0;
        }
        lag -= refbuf->len;
        refbuf = refbuf->next;
    }
    client->schedule_ms += 150;
    return -1;
}

static void source_preroll_logging (source_t *source, client_t *client)
{
    if (source->intro_filename == NULL || client->intro_offset < 0 || (client->flags & CLIENT_HAS_INTRO_CONTENT))
        return; // content provided separately, auth or queue block copy
    if (source->preroll_log_id < 0)
    {
        ice_config_t *config = config_get_config();
        if (config->preroll_log.logid >= 0)
            logging_preroll (config->preroll_log.logid, source->intro_filename, client);
        config_release_config();
    }
    else
        logging_preroll (source->preroll_log_id, source->intro_filename, client);
}


static int http_source_introfile (client_t *client)
{
    source_t *source = client->shared_data;
    long duration, rate = source->incoming_rate, incoming_rate;
    int assumed = 0;

    //DEBUG2 ("client intro_pos is %ld, sent bytes is %ld", client->intro_offset, client->connection.sent_bytes);
    if (format_file_read (client, source->format, source->intro_file) < 0)
    {
        source_preroll_logging (source, client);
        if (source->stream_data_tail)
        {
            if (source->intro_skip_replay)
                listener_skips_intro (source->intro_ipcache, client, source->intro_skip_replay);
            /* better find the right place in queue for this client */
            if (source->format->detach_queue_block)
                source->format->detach_queue_block (source, client->refbuf); // in case of private queue
            client_set_queue (client, NULL);
            client->check_buffer = source_queue_advance;
            client->intro_offset = -1;
            return source_queue_advance (client);
        }
        client->schedule_ms += 100;
        client->intro_offset = source->intro_start;  /* replay intro file */
        return -1;
    }

    if (rate == 0) // stream must of just started, make an assumption, re-evaluate next time
    {
        rate = 32000;
        assumed = 1;
    }
    if (client->timer_start == 0)
    {
        long to_send = 0;
        if (client->connection.sent_bytes < source->default_burst_size)
            to_send = source->default_burst_size - client->connection.sent_bytes;
        duration = (long)((float)to_send / rate);
        client->aux_data = duration + 8;
        client->timer_start = client->worker->current_time.tv_sec - client->aux_data;
        client->counter = 8 * rate;
    }
    incoming_rate = rate;
    duration = (client->worker->current_time.tv_sec - client->timer_start);
    if (duration)
        rate = (long)((float)client->counter / duration);
    // DEBUG4 ("duration %lu, counter %ld, rate %ld, bytes %ld", duration, client->counter, rate, client->connection.sent_bytes);

    if (assumed)
        client->timer_start = 0;  // force a reset for next time around, ignore rate checks this time

    if (rate > incoming_rate)
    {
        //DEBUG1 ("rate too high %lu, delaying", rate);
        client->schedule_ms += 40;
        rate_add (source->in_bitrate, 0, client->worker->current_time.tv_sec);
        return -1;
    }
    if (source->format->sent_bytes > (incoming_rate << 5) && // allow at least 30+ seconds on the stream
            (duration - client->aux_data) > 15 &&
            rate < (incoming_rate>>1))
    {
        INFO3 ("Dropped listener %s (%" PRIu64 "), running too slow on %s", &client->connection.ip[0], client->connection.id, source->mount);
        source_preroll_logging (source, client);
        client->connection.error = 1;
        client_set_queue (client, NULL);
        return -1; // assume a slow/stalled connection so drop
    }

    int ret = source->format->write_buf_to_client (client);
    if (client->connection.error)
        source_preroll_logging (source, client);
    return ret;
}


static int http_source_intro (client_t *client)
{
    /* we only need to send the intro if nothing else has been sent */
    if (client->intro_offset < 0)
    {
        client_set_queue (client, NULL);
        client->check_buffer = source_queue_advance;
        return source_queue_advance (client);
    }
    source_t *source = client->shared_data;
    refbuf_t *n = client->refbuf ? client->refbuf->next : NULL;
    if (n)
        client->refbuf->next = NULL;
    refbuf_release (client->refbuf);
    client->refbuf = n;
    client->pos = 0;
    client->intro_offset = source->intro_start;
    client->check_buffer = http_source_introfile;
    return http_source_introfile (client);
}


static int http_source_listener (client_t *client)
{
    refbuf_t *refbuf = client->refbuf;
    source_t *source = client->shared_data;
    int ret;

    if (refbuf == NULL || client->pos == refbuf->len)
    {
        client->check_buffer = http_source_intro;
        return http_source_intro (client);
    }
    if (source->queue_size == 0)
    {
        client->schedule_ms += 500;
        return -1;  /* postpone processing until data on queue */
    }

    if (client->respcode == 0)
    {
        int (*build_headers)(format_plugin_t *, client_t *) = format_general_headers;

        if (source_running (source) == 0)
        {
            client->schedule_ms += 200;
            return -1;
        }
        if (source->format->create_client_data)
            build_headers = source->format->create_client_data;

        refbuf->len = 0;
        if (build_headers (source->format, client) < 0)
        {
            ERROR1 ("internal problem, dropping client %" PRIu64, client->connection.id);
            return -1;
        }
        stats_lock (source->stats, source->mount);
        stats_set_inc (source->stats, "listener_connections");
        stats_release (source->stats);
    }
    ret = format_generic_write_to_client (client);
    if (client->pos == refbuf->len)
    {
        if (client->flags & CLIENT_AUTHENTICATED)
        {
            client->check_buffer = http_source_intro;
            client->connection.sent_bytes = 0;
            return ret;
        }
        client->connection.error = 1;
        return -1;
    }
    client->schedule_ms += 200;
    return ret;
}


// detach client from the source, enter with lock (probably read) and exit with write lock.
void source_listener_detach (source_t *source, client_t *client)
{
    client->wakeup = NULL;
    if (client->check_buffer != http_source_listener) // not in http headers
    {
        refbuf_t *ref = client->refbuf;

        if (ref)
        {
            if (ref->flags & REFBUF_SHARED)  // on the queue
            {
                if (client->connection.error == 0 && client->pos < ref->len && source->fallback.mount)
                {
                    /* make a private copy so that a write can complete later */
                    refbuf_t *copy = source->format->qblock_copy (client->refbuf);

                    client->refbuf = copy;
                    client->flags |= CLIENT_HAS_INTRO_CONTENT;
                }
                else
                    client->refbuf = NULL;
            }
        }
        client->check_buffer = source->format->write_buf_to_client;
    }
    else
        client->check_buffer = NULL;
    thread_rwlock_unlock (&source->lock);   // read lock in use!
    thread_rwlock_wlock (&source->lock);
    avl_delete (source->clients, client, NULL);
}


/* used to hold listeners in waiting over a relay restart. Handling of a failed relay also
 * needs to occur.
 */
static int wait_for_restart (client_t *client)
{
    source_t *source = client->shared_data;

    if (client->timer_start && client->worker->current_time.tv_sec - client->timer_start > 15)
    {
        INFO1 ("Dropping listener, stuck in %s too long", source->mount);
        client->connection.error = 1; // in here too long, drop client
    }

    if (source_running (source) || client->connection.error ||
            (source->flags & SOURCE_PAUSE_LISTENERS) == 0 ||
            (source->flags & (SOURCE_TERMINATING|SOURCE_LISTENERS_SYNC)))
    {
        client->ops = &listener_client_ops;
        return 0;
    }

    if (source->flags & SOURCE_LISTENERS_SYNC)
        client->schedule_ms = client->worker->time_ms + 100;
    else
        client->schedule_ms = client->worker->time_ms + 300;
    return 0;
}


/* used to hold listeners that have already been processed while other listeners
 * are still to be done
 */
static int wait_for_other_listeners (client_t *client)
{
    source_t *source = client->shared_data;

    if ((source->flags & (SOURCE_TERMINATING|SOURCE_LISTENERS_SYNC)) == SOURCE_LISTENERS_SYNC)
    {
        client->schedule_ms = client->worker->time_ms + 150;
        return 0;
    }
    client->ops = &listener_client_ops;
    return 0;
}


/* general send routine per listener.
 */
static int send_to_listener (client_t *client)
{
    source_t *source = client->shared_data;
    int ret;

    if (source == NULL)
        return -1;
    if (thread_rwlock_tryrlock (&source->lock) != 0)
    {
        client->schedule_ms = client->worker->time_ms + 4;
        return 0; // probably busy, check next client, come back to this
    }
    ret = send_listener (source, client);
    if (ret == 1)
        return 1; // client moved, and source unlocked
    if (ret < 0)
        ret = source_listener_release (source, client);
    thread_rwlock_unlock (&source->lock);
    return ret;
}


int listener_waiting_on_source (source_t *source, client_t *client)
{
    int read_lock = 1, ret = 0;
    while (1)
    {
        if (client->connection.error)
        {
            source_listener_detach (source, client);    // return with write lock
            read_lock = 0;  // skip the possible reacquiring of the lock later.
            source->listeners--;
            client->shared_data = NULL;
            ret = -1;
            break;
        }
        if (source->fallback.mount)
        {
            source_listener_detach (source, client);
            source->listeners--;
            thread_rwlock_unlock (&source->lock);
            client->shared_data = NULL;
            ret = move_listener (client, &source->fallback);
            thread_rwlock_wlock (&source->lock);
            if (ret <= 0)
            {
                source->termination_count--;
                return ret;
            }
            read_lock = 0;
            source->listeners++;
            source_setup_listener (source, client);
            ret = 0;
        }
        if (source->flags & SOURCE_TERMINATING)
        {
            if ((source->flags & SOURCE_PAUSE_LISTENERS) && global.running == ICE_RUNNING)
            {
                if (client->refbuf && (client->refbuf->flags & SOURCE_QUEUE_BLOCK))
                    client->refbuf = NULL;
                client->ops = &listener_pause_ops;
                client->flags |= CLIENT_HAS_MOVED;
                client->schedule_ms = client->worker->time_ms + 60;
                client->timer_start = client->worker->current_time.tv_sec;
                break;
            }
            ret = -1;
            break;
        }
        client->ops = &listener_wait_ops;
        client->schedule_ms = client->worker->time_ms + 100;
        break;
    }
    if (read_lock) // acquire write lock if still with read lock
    {
        thread_rwlock_unlock (&source->lock);
        thread_rwlock_wlock (&source->lock);
    }
    source->termination_count--;
    return ret;
}


static int send_listener (source_t *source, client_t *client)
{
    int bytes;
    int loop = 40;   /* max number of iterations in one go */
    long total_written = 0, limiter = source->listener_send_trigger;
    int ret = 0, lag;
    worker_t *worker = client->worker;
    time_t now = worker->current_time.tv_sec;

    client->schedule_ms = worker->time_ms;

    if (source->flags & SOURCE_LISTENERS_SYNC)
        return listener_waiting_on_source (source, client);

    /* check for limited listener time */
    if (client->flags & CLIENT_RANGE_END)
    {
        if (client->connection.discon.offset <= client->connection.sent_bytes)
            return -1;
    }
    else if (client->connection.discon.time && now >= client->connection.discon.time)
    {
        INFO1 ("time limit reached for client #%" PRIu64, client->connection.id);
        client->connection.error = 1;
        return -1;
    }
    if (source_running (source) == 0)
    {
        DEBUG0 ("source not running, listener will wait");
        client->schedule_ms += 100;
        return 0;
    }

    // do we migrate this listener to the same handler as the source client
    if (listener_change_worker (client, source))
        return 1;

    lag = source->client->queue_pos - client->queue_pos;

    /* progessive slowdown if nearing max bandwidth.  */
    if (global.max_rate)
    {
        if (throttle_sends > 2) /* exceeded limit, skip */
        {
            client->schedule_ms += 40 + (client->throttle * 3);
            return 0;
        }
        if (throttle_sends > 1) /* slow down any multiple sends */
        {
            loop = 3;
            client->schedule_ms += (client->throttle * 4);
        }
        if (throttle_sends > 0)
        {
            /* make lagging listeners, lag further on high server bandwidth use */
            if (lag > (source->incoming_rate*2))
                client->schedule_ms += 100 + (client->throttle * 3);
        }
    }
    // set between 1 and 25
    client->throttle = source->incoming_adj > 25 ? 25 : (source->incoming_adj > 0 ? source->incoming_adj : 1);
    while (1)
    {
        /* lets not send too much to one client in one go, but don't
           sleep for too long if more data can be sent */
        if (loop == 0 || total_written > limiter)
        {
            client->schedule_ms += 25;
            break;
        }
        bytes = client->check_buffer (client);
        if (bytes < 0)
        {
            if (client->connection.error || (total_written == 0 && connection_unreadable (&client->connection)))
            {
                ret = -1;
                break;
            }
            client->schedule_ms += 15;
            break;  /* can't write any more */
        }

        total_written += bytes;
        loop--;
    }
    if (total_written)
    {
        rate_add_sum (source->out_bitrate, total_written, worker->time_ms, &source->format->sent_bytes);
        global_add_bitrates (global.out_bitrate, total_written, worker->time_ms);
    }

    if (source->shrink_time && client->connection.error == 0)
    {
        lag = source->client->queue_pos - client->queue_pos;
        if (lag > source->queue_size_limit)
            lag = source->queue_size_limit; // impose a higher lag value
        thread_spin_lock (&source->shrink_lock);
        if (client->queue_pos < source->shrink_pos)
            source->shrink_pos = source->client->queue_pos - lag;
        thread_spin_unlock (&source->shrink_lock);
    }
    return ret;
}


/* Perform any initialisation before the stream data is processed, the header
 * info is processed by now and the format details are setup
 */
void source_init (source_t *source)
{
    mount_proxy *mountinfo;

    if (source->dumpfilename != NULL)
    {
        unsigned int len;
        char buffer [4096];

        len = sizeof buffer;
        if (util_expand_pattern (source->mount, source->dumpfilename, buffer, &len) == 0)
        {
            INFO2 ("dumpfile \"%s\" for %s", buffer, source->mount);
            source->dumpfile = fopen (buffer, "ab");
            if (source->dumpfile == NULL)
            {
                WARN2("Cannot open dump file \"%s\" for appending: %s, disabling.",
                        buffer, strerror(errno));
            }
        }
    }

    /* start off the statistics */
    stats_event_inc (NULL, "source_total_connections");
    source->stats = stats_lock (source->stats, source->mount);
    stats_set_flags (source->stats, "slow_listeners", "0", STATS_COUNTERS);
    stats_set (source->stats, "server_type", source->format->contenttype);
    stats_set_flags (source->stats, "listener_peak", "0", STATS_COUNTERS);
    stats_set_args (source->stats, "listener_peak", "%lu", source->peak_listeners);
    stats_set_flags (source->stats, "listener_connections", "0", STATS_COUNTERS);
    stats_set_time (source->stats, "stream_start", STATS_COUNTERS, source->client->worker->current_time.tv_sec);
    stats_set_flags (source->stats, "total_mbytes_sent", "0", STATS_COUNTERS);
    stats_set_flags (source->stats, "total_bytes_sent", "0", STATS_COUNTERS);
    stats_set_flags (source->stats, "total_bytes_read", "0", STATS_COUNTERS);
    stats_set_flags (source->stats, "outgoing_kbitrate", "0", STATS_COUNTERS);
    stats_set_flags (source->stats, "incoming_bitrate", "0", STATS_COUNTERS);
    stats_set_flags (source->stats, "queue_size", "0", STATS_COUNTERS);
    stats_set_flags (source->stats, "connected", "0", STATS_COUNTERS);
    stats_set_flags (source->stats, "source_ip", source->client->connection.ip, STATS_COUNTERS);

    source->last_read = time(NULL);
    source->prev_listeners = -1;
    source->bytes_sent_at_update = 0;
    source->stats_interval = 5;
    /* so the first set of average stats after 4 seconds */
    source->client_stats_update = source->last_read + 4;
    source->skip_duration = 40;
    source->buffer_count = 0;
    source->queue_size_limit = 200000000; // initial sizing
    source->default_burst_size = 300000;
    source->min_queue_size = 600000;

    util_dict_free (source->audio_info);
    source->audio_info = util_dict_new();
    if (source->client)
    {
        const char *str = httpp_getvar(source->client->parser, "ice-audio-info");
        if (str)
        {
            _parse_audio_info (source, str);
            stats_set_flags (source->stats, "audio_info", str, STATS_GENERAL);
        }
        source->client->queue_pos = 0;
    }
    stats_release (source->stats);
    rate_free (source->in_bitrate);
    source->in_bitrate = rate_setup (60, 1);
    rate_free (source->out_bitrate);
    source->out_bitrate = rate_setup (9000, 1000);

    source->flags |= SOURCE_RUNNING;

    mountinfo = config_find_mount (config_get_config(), source->mount);
    if (mountinfo)
    {
        if (mountinfo->max_stream_duration)
            source->client->connection.discon.time = source->client->worker->current_time.tv_sec + mountinfo->max_stream_duration;
        if (mountinfo->on_connect)
            source_run_script (mountinfo->on_connect, source->mount);
        auth_stream_start (mountinfo, source);
    }
    config_release_config();

    INFO1 ("Source %s initialised", source->mount);

    /* on demand relays should of already called this */
    if ((source->flags & SOURCE_ON_DEMAND) == 0)
        slave_update_mounts();
    source->flags &= ~SOURCE_ON_DEMAND;
}


static int source_set_override (mount_proxy *mountinfo, source_t *dest_source, format_type_t type)
{
    source_t *source;
    const char *dest = dest_source->mount;
    int ret = 0, loop = 15;
    ice_config_t *config = config_get_config_unlocked();
    unsigned int len;
    char *mount = dest_source->mount, buffer [4096];

    if (mountinfo == NULL || mountinfo->fallback_mount == NULL || mountinfo->fallback_override == 0)
    {
        INFO1 ("no override for %s set", dest_source->mount);
        return 0;
    }
    INFO2 ("for %s set to %s", dest_source->mount, mountinfo->fallback_mount);
    avl_tree_rlock (global.source_tree);
    while (loop--)
    {
        len = sizeof buffer;
        if (util_expand_pattern (mount, mountinfo->fallback_mount, buffer, &len) < 0)
        {
            avl_tree_unlock (global.source_tree);
            break;
        }
        mount = buffer;

        DEBUG2 ("checking for %s on %s", mount, dest);
        source = source_find_mount_raw (mount);
        if (source)
        {
            if (strcmp (source->mount, dest) == 0) // back where we started, drop out
            {
                avl_tree_unlock (global.source_tree);
                break;
            }
            thread_rwlock_wlock (&source->lock);
            if (source_running (source))
            {
                avl_tree_unlock (global.source_tree);
                if (source->format->type == type)
                {
                    if (source->listeners && source->fallback.mount == NULL)
                    {
                        source->fallback.limit = 0;
                        source->fallback.mount = strdup (dest);
                        source->fallback.flags = FS_FALLBACK;
                        source->fallback.type = type;
                        source->termination_count = source->listeners;
                        source->client->timer_start = dest_source->client->worker->time_ms;
                        source->flags |= SOURCE_LISTENERS_SYNC;
                        source_listeners_wakeup (source);
                        ret = 1;
                    }
                }
                else
                    ERROR4("%s (%d) and %s(%d) are different formats", dest, type, mount, source->format->type);
                thread_rwlock_unlock (&source->lock);
                break;
            }
            thread_rwlock_unlock (&source->lock);
        }
        mountinfo = config_find_mount (config, mount);
        if (mountinfo == NULL || mountinfo->fallback_mount == NULL || mountinfo->fallback_override == 0)
        {
            avl_tree_unlock (global.source_tree);
            if (mount)
                ret = fserve_set_override (mount, dest, type);
            break;
        }
    }
    return ret;
}


void source_set_fallback (source_t *source, const char *dest_mount)
{
    int rate = 0;
    client_t *client = source->client;
    time_t connected;

    if (dest_mount == NULL)
    {
        INFO1 ("No fallback on %s", source->mount);
        return;
    }
    if (dest_mount[0] != '/')
    {
        WARN2 ("invalid fallback on \"%s\", ignoring \"%s\"", source->mount, dest_mount);
        return;
    }
    if (source->listeners == 0)
    {
        INFO2 ("fallback on %s to %s, but no listeners", source->mount, dest_mount);
        return;
    }

    connected = client->worker->current_time.tv_sec - client->connection.con_time;
    if (connected > 40)
    {
        if (source->flags & SOURCE_TIMEOUT)
            rate = (int)rate_avg_shorten (source->in_bitrate, source->timeout);
        else
            rate = (int)rate_avg (source->in_bitrate);
        rate = (int)((rate / 1000) + 0.5) * 1000;
    }
    if (rate == 0 && source->limit_rate)
        rate = source->limit_rate;

    source->fallback.mount = strdup (dest_mount);
    source->fallback.fallback = source->mount;
    source->fallback.flags = FS_FALLBACK;
    source->fallback.limit = rate;
    source->fallback.type = source->format->type;
    INFO4 ("fallback set on %s to %s(%d) with %ld listeners", source->mount, dest_mount,
            source->fallback.limit, source->listeners);
}


int source_set_intro (source_t *source, const char *file_pattern)
{
    if (file_pattern == NULL || source == NULL)
        return -1;

    ice_config_t *config = config_get_config_unlocked ();
    char buffer[4096];
    unsigned int len = sizeof buffer;
    int ret = snprintf (buffer, len, "%s" PATH_SEPARATOR, config->webroot_dir);

    do
    {
        if (ret < 1 && ret >= len)
            break;
        len -= ret;
        if (util_expand_pattern (source->mount, file_pattern, buffer + ret, &len) < 0)
            break;

        icefile_handle intro_file;
        if (file_open (&intro_file, buffer) < 0)
        {
            WARN3 ("Cannot open intro for %s \"%s\": %s", source->mount, buffer, strerror(errno));
            break;
        }
        format_check_t intro;
        intro.fd = intro_file;
        intro.desc = buffer;
        if (format_check_frames (&intro) < 0 || intro.type == FORMAT_TYPE_UNDEFINED)
        {
            WARN2 ("Failed to read intro for %s (%s)", source->mount, buffer);
            file_close (&intro_file);
            break;
        }
        if (intro.type != source->format->type)
        {
            WARN2 ("intro file seems to be a different format to %s (%s)", source->mount, buffer);
            file_close (&intro_file);
            break;
        }
        // maybe a bitrate check later.
        INFO3 ("intro file for %s is %s (%s)", source->mount, file_pattern, buffer);
        file_close (&source->intro_file);
        source->intro_file = intro_file;
        free (source->intro_filename);
        source->intro_filename = strdup (buffer + ret);
        return 0;
    } while (0);
    return -1;
}


void source_shutdown (source_t *source, int with_fallback)
{
    mount_proxy *mountinfo;
    client_t *src_client = source->client;

    INFO1("Source \"%s\" exiting", source->mount);

    source->flags &= ~(SOURCE_ON_DEMAND);
    source->termination_count = source->listeners;
    source->client->timer_start = source->client->worker->time_ms;
    source->flags |= (SOURCE_TERMINATING | SOURCE_LISTENERS_SYNC);
    source_listeners_wakeup (source);
    mountinfo = config_find_mount (config_get_config(), source->mount);
    if (src_client->connection.con_time && src_client->parser)
    {
        /* only do these if source has been running */
        if (source->stats)
            update_source_stats (source);
        if (mountinfo)
        {
            if (mountinfo->on_disconnect)
                source_run_script (mountinfo->on_disconnect, source->mount);
            auth_stream_end (mountinfo, source);
        }
    }
    if (mountinfo && with_fallback && global.running == ICE_RUNNING)
        source_set_fallback (source, mountinfo->fallback_mount);
    source->flags &= ~(SOURCE_TIMEOUT);
    config_release_config();
}


static void _parse_audio_info (source_t *source, const char *s)
{
    const char *start = s;
    unsigned int len;

    while (start != NULL && *start != '\0')
    {
        if ((s = strchr (start, ';')) == NULL)
            len = strlen (start);
        else
        {
            len = (int)(s - start);
            s++; /* skip passed the ';' */
        }
        if (len)
        {
            char name[100], value[200];
            int n = sscanf (start, "%99[^=]=%199[^;\r\n]", name, value);

            if (n == 2 && (strncmp (name, "ice-", 4) == 0 || strncmp (name, "bitrate=", 7) == 0))
            {
                char *esc = util_url_unescape (value);
                if (esc)
                {
                    util_dict_set (source->audio_info, name, esc);
                    stats_set_flags (source->stats, name, esc, STATS_COUNTERS);
                }
                free (esc);
            }
        }
        start = s;
    }
}


static int compare_intro_ipcache (void *arg, void *a, void *b)
{
    struct node_IP_time *this = (struct node_IP_time *)a;
    struct node_IP_time *that = (struct node_IP_time *)b;
    int ret = strcmp (&this->ip[0], &that->ip[0]);

    if (ret && that->a.timeout)
    {
        cache_file_contents *c = arg;
        time_t threshold = c->file_recheck;

        if (c->deletions_count < 9 && that->a.timeout < threshold)
        {
            c->deletions [c->deletions_count] = that;
            c->deletions_count++;
        }
    }
    return ret;
}


int source_apply_preroll (mount_proxy *mountinfo, source_t *source)
{
    do
    {
        if (mountinfo == NULL || mountinfo->preroll_log.name == NULL)
            break;

        ice_config_t *config = config_get_config_unlocked ();
        struct error_log *preroll = &mountinfo->preroll_log;
        unsigned int len = 4096;
        int ret;
        char buffer [len];

        ret = snprintf (buffer, len, "%s" PATH_SEPARATOR, config->log_dir);
        if (ret < 0 || ret >= len)
            break;
        len -= ret;
        if (util_expand_pattern (source->mount, mountinfo->preroll_log.name, buffer + ret, &len) < 0)
            break;
        if (source->preroll_log_id < 0)
            source->preroll_log_id = log_open (buffer);
        if (source->preroll_log_id < 0)
            break;
        INFO3 ("using pre-roll log file %s (%s) for %s", preroll->name, buffer, source->mount);
        // log_set_filename (source->preroll_log_id, buffer);
        long max_size = (preroll->size > 10000) ? preroll->size : config->preroll_log.size;
        log_set_trigger (source->preroll_log_id, max_size);
        log_set_reopen_after (source->preroll_log_id, preroll->duration);
        log_set_lines_kept (source->preroll_log_id, preroll->display);
        int archive = (preroll->archive == -1) ? config->preroll_log.archive : preroll->archive;
        log_set_archive_timestamp (source->preroll_log_id, archive);
        //DEBUG4 ("log %s, size %ld, duration %u, archive %d", preroll->name, max_size, preroll->duration, archive);
        log_reopen (source->preroll_log_id);
        return 0;
    } while (0);

    log_close (source->preroll_log_id);
    source->preroll_log_id = -1;
    return -1;
}


/* Apply the mountinfo details to the source */
static void source_apply_mount (source_t *source, mount_proxy *mountinfo)
{
    const char *str;
    int val;
    http_parser_t *parser = NULL;

    if (mountinfo == NULL || strcmp (mountinfo->mountname, source->mount) == 0)
        INFO1 ("Applying mount information for \"%s\"", source->mount);
    else
        INFO2 ("Applying mount information for \"%s\" from \"%s\"",
                source->mount, mountinfo->mountname);

    stats_set_args (source->stats, "listener_peak", "%lu", source->peak_listeners);

    /* if a setting is available in the mount details then use it, else
     * check the parser details. */

    if (source->client)
        parser = source->client->parser;

    /* to be done before possible non-utf8 stats */
    if (source->format && source->format->apply_settings)
        source->format->apply_settings (source->format, mountinfo);

    /* public */
    if (mountinfo && mountinfo->yp_public >= 0)
        val = mountinfo->yp_public;
    else
    {
        do {
            str = httpp_getvar (parser, "ice-public");
            if (str) break;
            str = httpp_getvar (parser, "icy-pub");
            if (str) break;
            str = httpp_getvar (parser, "x-audiocast-public");
            if (str) break;
            /* handle header from icecast v2 release */
            str = httpp_getvar (parser, "icy-public");
            if (str) break;
            str = source->yp_public > 0 ? "1" : "0";
        } while (0);
        val = atoi (str);
    }
    stats_set_args (source->stats, "public", "%d", val);
    if (source->yp_public != val)
    {
        DEBUG1 ("YP changed to %d", val);
        if (val)
            yp_add (source->mount);
        else
            yp_remove (source->mount);
        source->yp_public = val;
    }

    /* stream name */
    if (mountinfo && mountinfo->stream_name)
        stats_set (source->stats, "server_name", mountinfo->stream_name);
    else
    {
        do {
            str = httpp_getvar (parser, "ice-name");
            if (str) break;
            str = httpp_getvar (parser, "icy-name");
            if (str) break;
            str = httpp_getvar (parser, "x-audiocast-name");
            if (str) break;
            str = "Unspecified name";
        } while (0);
        if (source->format)
            stats_set_conv (source->stats, "server_name", str, source->format->charset);
    }

    /* stream description */
    if (mountinfo && mountinfo->stream_description)
        stats_set (source->stats, "server_description", mountinfo->stream_description);
    else
    {
        do {
            str = httpp_getvar (parser, "ice-description");
            if (str) break;
            str = httpp_getvar (parser, "icy-description");
            if (str) break;
            str = httpp_getvar (parser, "x-audiocast-description");
            if (str) break;
        } while (0);
        if (str && source->format)
            stats_set_conv (source->stats, "server_description", str, source->format->charset);
    }

    /* stream URL */
    if (mountinfo && mountinfo->stream_url)
        stats_set (source->stats, "server_url", mountinfo->stream_url);
    else
    {
        do {
            str = httpp_getvar (parser, "ice-url");
            if (str) break;
            str = httpp_getvar (parser, "icy-url");
            if (str) break;
            str = httpp_getvar (parser, "x-audiocast-url");
            if (str) break;
        } while (0);
        if (str && source->format)
            stats_set_conv (source->stats, "server_url", str, source->format->charset);
    }

    /* stream genre */
    if (mountinfo && mountinfo->stream_genre)
        stats_set (source->stats, "genre", mountinfo->stream_genre);
    else
    {
        do {
            str = httpp_getvar (parser, "ice-genre");
            if (str) break;
            str = httpp_getvar (parser, "icy-genre");
            if (str) break;
            str = httpp_getvar (parser, "x-audiocast-genre");
            if (str) break;
            str = "various";
        } while (0);
        if (source->format)
            stats_set_conv (source->stats, "genre", str, source->format->charset);
    }

    /* stream bitrate */
    if (mountinfo && mountinfo->bitrate)
    {
        str = mountinfo->bitrate;
        stats_set (source->stats, "bitrate", str);
    }
    else
    {
        do {
            str = httpp_getvar (parser, "ice-bitrate");
            if (str) break;
            str = httpp_getvar (parser, "icy-br");
            if (str) break;
            str = httpp_getvar (parser, "x-audiocast-bitrate");
        } while (0);
        if (str)
            stats_set (source->stats, "bitrate", str);
    }

    /* handle MIME-type */
    if (mountinfo && mountinfo->type)
    {
        if (source->format)
        {
            format_type_t type = format_get_type (mountinfo->type);
            if (type == FORMAT_TYPE_UNDEFINED)
                WARN2 ("type specified for %s is unrecognised (%s)", source->mount, mountinfo->type);
            else
                source->format->type = format_get_type (mountinfo->type);
            free (source->format->contenttype);
            source->format->contenttype = strdup (mountinfo->type);
        }
        stats_set (source->stats, "server_type", mountinfo->type);
    }
    else
        if (source->format && source->format->contenttype)
            stats_set (source->stats, "server_type", source->format->contenttype);

    if (mountinfo && mountinfo->subtype)
        stats_set (source->stats, "subtype", mountinfo->subtype);

    if (mountinfo && mountinfo->auth)
        stats_set (source->stats, "authenticator", mountinfo->auth->type);
    else
        stats_set (source->stats, "authenticator", NULL);

    source->limit_rate = 0;
    if (mountinfo && mountinfo->limit_rate)
        source->limit_rate = mountinfo->limit_rate;

    /* needs a better mechanism, probably via a client_t handle */
    free (source->dumpfilename);
    source->dumpfilename = NULL;
    if (mountinfo && mountinfo->dumpfile)
    {
        time_t now = time(NULL);
        struct tm local;
        char buffer[PATH_MAX];

        localtime_r (&now, &local);
        if (strftime (buffer, sizeof (buffer), mountinfo->dumpfile, &local) == 0)
        {
            WARN3 ("had problem on %s expanding dumpfile %s (%s)", source->mount, mountinfo->dumpfile, strerror(errno));
            errno = 0;
        }
        else
            source->dumpfilename = strdup (buffer);
    }
    source_apply_preroll (mountinfo, source);

    /* handle changes in intro file setting */
    file_close (&source->intro_file);
    free (source->intro_filename);
    source->intro_filename = NULL;
    cached_prune (source->intro_ipcache);
    free (source->intro_ipcache);
    source->intro_ipcache = NULL;
    source->intro_skip_replay = 0;
    if (mountinfo && mountinfo->intro_filename)
    {
        // only set here if there is data present, for type verification
        if (source->stream_data)
           source_set_intro (source, mountinfo->intro_filename);

        if (mountinfo->intro_skip_replay)
        {
            cache_file_contents *c = calloc (1, sizeof (cache_file_contents));

            source->intro_ipcache = c;
            c->contents = avl_tree_new (compare_intro_ipcache, c);
            source->intro_skip_replay = mountinfo->intro_skip_replay;
        }
    }

    if (mountinfo && mountinfo->source_timeout)
        source->timeout = mountinfo->source_timeout;

    if (mountinfo && mountinfo->queue_size_limit)
        source->queue_len_value = mountinfo->queue_size_limit;

    if (mountinfo && mountinfo->burst_size)
        source->default_burst_value = (unsigned int)mountinfo->burst_size;

    if (mountinfo && mountinfo->min_queue_size)
        source->min_queue_len_value = mountinfo->min_queue_size;

    source->wait_time = 0;
    if (mountinfo && mountinfo->wait_time)
        source->wait_time = (time_t)mountinfo->wait_time;
}


/* update the specified source with details from the config or mount.
 * mountinfo can be NULL in which case default settings should be taken
 */
void source_update_settings (ice_config_t *config, source_t *source, mount_proxy *mountinfo)
{
    char *listen_url;
    int len;

    /* set global settings first */
    if (mountinfo == NULL)
    {
        source->queue_len_value = config->queue_size_limit;
        source->min_queue_len_value = config->min_queue_size;
        source->timeout = config->source_timeout;
        source->default_burst_value = config->burst_size;
    }
    stats_lock (source->stats, source->mount);

    len = strlen (config->hostname) + strlen(source->mount) + 16;
    listen_url = alloca (len);
    snprintf (listen_url, len, "http://%s:%d%s", config->hostname, config->port, source->mount);
    stats_set_flags (source->stats, "listenurl", listen_url, STATS_COUNTERS);

    source_apply_mount (source, mountinfo);

    if (source->dumpfilename)
        DEBUG1 ("Dumping stream to %s", source->dumpfilename);
    if (source->flags & SOURCE_ON_DEMAND)
    {
        DEBUG0 ("on_demand set");
        stats_set (source->stats, "on_demand", "1");
        stats_set_args (source->stats, "listeners", "%ld", source->listeners);
    }
    else
        stats_set (source->stats, "on_demand", NULL);

    if (mountinfo)
    {
        if (mountinfo->on_connect)
            DEBUG1 ("connect script \"%s\"", mountinfo->on_connect);
        if (mountinfo->on_disconnect)
            DEBUG1 ("disconnect script \"%s\"", mountinfo->on_disconnect);
        if (mountinfo->fallback_when_full)
            DEBUG1 ("fallback_when_full to %u", mountinfo->fallback_when_full);
        DEBUG1 ("max listeners to %d", mountinfo->max_listeners);
        stats_set_args (source->stats, "max_listeners", "%d", mountinfo->max_listeners);
        stats_set_flags (source->stats, "cluster_password", mountinfo->cluster_password, STATS_SLAVE|STATS_HIDDEN);
        if (mountinfo->hidden)
        {
            stats_set_flags (source->stats, NULL, NULL, STATS_HIDDEN);
            DEBUG0 ("hidden from public");
        }
        else
            stats_set_flags (source->stats, NULL, NULL, 0);
    }
    else
    {
        DEBUG0 ("max listeners is not specified");
        stats_set (source->stats, "max_listeners", "unlimited");
        stats_set_flags (source->stats, "cluster_password", NULL, STATS_SLAVE);
        stats_set_flags (source->stats, NULL, NULL, STATS_PUBLIC);
    }
    stats_release (source->stats);
    DEBUG1 ("public set to %d", source->yp_public);
    DEBUG1 ("source timeout to %u", source->timeout);
}


static int source_client_callback (client_t *client)
{
    const char *agent;
    source_t *source = client->shared_data;

    stats_event_inc(NULL, "source_client_connections");

    client->ops = &source_client_ops;
    if (source_running (source))
        stats_event_inc (NULL, "source_total_connections");
    else
        source_init (source);
    agent = httpp_getvar (source->client->parser, "user-agent");
    thread_rwlock_unlock (&source->lock);
    if (agent)
    {
        stats_lock (source->stats, source->mount);
        stats_set_flags (source->stats, "user_agent", agent, STATS_COUNTERS);
        stats_release (source->stats);
    }
    return 0;
}


#ifndef _WIN32
static void source_run_script (char *command, char *mountpoint)
{
    pid_t pid, external_pid;
    char *p, *comm;
    int wstatus;

    comm = p = strdup (command);
#ifdef HAVE_STRSEP
    strsep (&p, " \t");
#else
    if (strchr (command, ' '))  // possible misconfiguration, but unlikely to occur.
        INFO1 ("arguments to command on %s not supported", mountpoint);
#endif
    if (access (comm, X_OK) != 0)
    {
        ERROR3 ("Unable to run command %s on %s (%s)", comm, mountpoint, strerror (errno));
        free (comm);
        return;
    }
    DEBUG2 ("Starting command %s on %s", comm, mountpoint);

    /* do a fork twice so that the command has init as parent */
    external_pid = fork();
    switch (external_pid)
    {
        case 0:     // child, don't log from here.
            switch (pid = fork ())
            {
                case -1:
                    break;
                case 0:  /* child */
#ifdef HAVE_STRSEP
#define MAX_SCRIPT_ARGS          20
                    {
                        int i = 1;
                        char *args [MAX_SCRIPT_ARGS+1], *tmp;

                        // default set unless overridden
                        args[0] = comm;
                        args[1] = mountpoint;
                        args[2] = NULL;
                        while (i < MAX_SCRIPT_ARGS && (tmp = strsep (&p, " \t")))
                        {
                            unsigned len = 4096;
                            char *str = malloc (len);
                            if (util_expand_pattern (mountpoint, tmp, str, &len) == 0)
                                args[i] = str;
                            i++;
                        }
                        close (0);
                        close (1);
                        close (2);
                        execvp ((const char *)args[0], args);
                    }
#else
                    close (0);
                    close (1);
                    close (2);
                    execl (command, command, mountpoint, (char *)NULL);
#endif
                    exit(1);
                default: /* parent */
                    break;
            }
            exit (0);
        case -1:    // ok, in parent context, no lock clash.
            ERROR1 ("Unable to fork %s", strerror (errno));
            break;
        default: /* parent */
            do
            {
                if (waitpid (external_pid, &wstatus, 0) < 0)
                    break;
            } while (WIFEXITED(wstatus) == 0 && WIFSIGNALED(wstatus) == 0);
            break;
    }
    free (comm);
}
#endif


/* rescan the mount list, so that xsl files are updated to show
 * unconnected but active fallback mountpoints
 */
void source_recheck_mounts (int update_all)
{
    ice_config_t *config;
    time_t mark = time (NULL);
    long count = 0;

    avl_tree_rlock (global.source_tree);

    if (update_all)
    {
        avl_node *node = avl_get_first (global.source_tree);
        while (node)
        {
            source_t *source = (source_t*)node->key;

            thread_rwlock_wlock (&source->lock);
            config = config_get_config();
            if (source_available (source))
                source_update_settings (config, source, config_find_mount (config, source->mount));
            config_release_config();
            thread_rwlock_unlock (&source->lock);
            node = avl_get_next (node);
        }
    }

    config = config_get_config();
    avl_node *node = avl_get_first (config->mounts_tree);
    while (node)
    {
        source_t *source;
        mount_proxy *mount = (mount_proxy*)node->key;

        node = avl_get_next (node);

        ++count;
        if ((count & 63) == 0)  // lets give others access to this every so often
        {
            avl_tree_unlock (global.source_tree);
            avl_tree_rlock (global.source_tree);
        }

        source = source_find_mount_raw (mount->mountname);
        if ((source == NULL || source_available (source) == 0) && mount->fallback_mount)
        {
            int count = -1;
            unsigned int len;
            char buffer [4096];

            len = sizeof buffer;
            if (util_expand_pattern (mount->mountname, mount->fallback_mount, buffer, &len) == 0)
                count = fallback_count (config, buffer);

            DEBUG2 ("fallback checking %s (fallback has %d)", mount->mountname, count);
            if (count >= 0)
            {
                stats_handle_t stats = stats_handle (mount->mountname);
                if (source == NULL) // mark for purge if there is no source at all
                    stats_set_expire (stats, mark);
                stats_set_flags (stats, NULL, NULL, mount->hidden?STATS_HIDDEN:0);
                stats_set_args (stats, "listenurl", "http://%s:%d%s",
                        config->hostname, config->port, mount->mountname);
                stats_set (stats, "listeners", "0");
                if (mount->max_listeners < 0)
                    stats_set (stats, "max_listeners", "unlimited");
                else
                    stats_set_args (stats, "max_listeners", "%d", mount->max_listeners);
                stats_release (stats);
            }
        }
    }
    stats_purge (mark);
    avl_tree_unlock (global.source_tree);
    config_release_config();
}


/* Check whether this listener is on this source. This is only called when
 * there is auth. This may flag an existing listener to terminate.
 * return 1 if ok to add or 0 to prevent
 */
int check_duplicate_logins (const char *mount, avl_tree *tree, client_t *client, auth_t *auth)
{
    avl_node *node;

    if (auth == NULL || (auth->flags & AUTH_ALLOW_LISTENER_DUP))
        return 1;

    /* allow multiple authenticated relays */
    if (client->username == NULL || client->flags & CLIENT_IS_SLAVE)
        return 1;

    node = avl_get_first (tree);
    while (node)
    {
        client_t *existing_client = (client_t *)node->key;
        if (existing_client->username && 
                strcmp (existing_client->username, client->username) == 0)
        {
            if (auth->flags & AUTH_DEL_EXISTING_LISTENER)
            {
                INFO2 ("Found %s on %s, dropping previous account", existing_client->username, mount);
                existing_client->connection.error = 1;
                return 1;
            }
            else
                return 0;
        }
        node = avl_get_next (node);
    }       
    return 1;
}


/* source required to stay around for a short while
 */
static int source_client_shutdown (client_t *client)
{
    if (global.running == ICE_RUNNING && client->connection.discon.time)
    {
        if (client->connection.discon.time >= client->worker->current_time.tv_sec)
        {
            client->schedule_ms = client->worker->time_ms + 50;
            return 0;
        }
    }
    drop_source_from_tree ((source_t*)client->shared_data);
    // source locked but exit function will want it locked
    return -1;
}


/* clean up what is left from the source. */
void source_client_release (client_t *client)
{
    source_t *source = client->shared_data;

    source->flags &= ~(SOURCE_RUNNING|SOURCE_ON_DEMAND);
    client->flags &= ~CLIENT_AUTHENTICATED;
    /* log bytes read in access log */
    if (source->format)
        client->connection.sent_bytes = source->format->read_bytes;

    _free_source (source);
    slave_update_mounts();
    client_destroy (client);
    global_reduce_bitrate_sampling (global.out_bitrate);
}


static int source_listener_release (source_t *source, client_t *client)
{
    int ret;
    ice_config_t *config;
    mount_proxy *mountinfo;

    if (client->shared_data == source) // still attached to source?
    {
        while (1)
        {
            refbuf_t *r = client->refbuf;
            if (r == NULL || (r->flags & REFBUF_SHARED))
                break;
            client->refbuf = r->next;
            r->next = NULL;
            if (source->format->detach_queue_block)
                source->format->detach_queue_block (source, r);
            refbuf_release (r);
        }
        /* search through sources client list to find previous link in list */
        source_listener_detach (source, client);
        source->listeners--;
        client->shared_data = NULL;
        client_set_queue (client, NULL);
        if (source->listeners == 0)
            rate_reduce (source->out_bitrate, 1000);
    }

    /* change of listener numbers, so reduce scope of global sampling */
    global_reduce_bitrate_sampling (global.out_bitrate);
    DEBUG2 ("Listener %" PRIu64 " leaving %s", client->connection.id, source->mount);
    // reduce from global count
    global_lock();
    global.listeners--;
    global_unlock();

    config = config_get_config ();
    mountinfo = config_find_mount (config, source->mount);

    if (mountinfo && mountinfo->access_log.name)
        logging_access_id (&mountinfo->access_log, client);

    ret = auth_release_listener (client, source->mount, mountinfo);
    config_release_config();
    return ret;
}


int source_add_listener (const char *mount, mount_proxy *mountinfo, client_t *client)
{
    int loop = 10, rate = 0, do_process = 0;
    int within_limits;
    source_t *source;
    mount_proxy *minfo = mountinfo;
    const char *passed_mount = mount;
    ice_config_t *config = config_get_config_unlocked();
    unsigned int len;
    char buffer[4096];

    do
    {
        int64_t stream_bitrate = 0;
        int flags = 0;

        do
        {
            if (loop == 0)
            {
                WARN0 ("preventing a fallback loop");
                return client_send_403 (client, "Fallback through too many mountpoints");
            }
            avl_tree_rlock (global.source_tree);
            source = source_find_mount_raw (mount);
            if (source)
            {
                thread_rwlock_wlock (&source->lock);
                if (source_available (source))
                    break;
                thread_rwlock_unlock (&source->lock);
            }
            avl_tree_unlock (global.source_tree);
            if (minfo && minfo->limit_rate)
                rate = minfo->limit_rate/8;
            if (minfo == NULL || minfo->fallback_mount == NULL)
            {
                int ret = -2;
                if (rate == 0)
                    if (sscanf (mount, "%*[^[][%d]", &rate) == 1)
                        rate = rate * 1000 / 8;
                if (rate)
                {
                    fbinfo f;
                    f.flags = flags;
                    f.mount = (char *)mount;
                    f.fallback = NULL;
                    f.limit = rate;
                    f.type = FORMAT_TYPE_UNDEFINED;
                    if (move_listener (client, &f) == 0)
                    {
                        /* source dead but fallback to file found */
                        stats_event_inc (NULL, "listener_connections");
                        return 0;
                    }
                    ret = -1;
                }
                return ret;
            }
            len = sizeof buffer;
            if (util_expand_pattern (mount, minfo->fallback_mount, buffer, &len) < 0)
                mount = minfo->fallback_mount;
            else
                mount = buffer;
            minfo = config_find_mount (config_get_config_unlocked(), mount);
            flags = FS_FALLBACK;
            loop--;
        } while (1);

        /* ok, we found a source and it is locked */
        avl_tree_unlock (global.source_tree);

        if (client->flags & CLIENT_IS_SLAVE)
        {
            INFO1 ("client %" PRIu64 " is from a slave, bypassing limits", client->connection.id);
            break;
        }
        if (source->format)
        {
            stream_bitrate  = 8 * rate_avg (source->in_bitrate);

            if (config->max_bandwidth)
            {
                int64_t global_rate = (int64_t)8 * global_getrate_avg (global.out_bitrate);

                DEBUG1 ("server outgoing bitrate is %" PRId64, global_rate);
                if (global_rate + stream_bitrate > config->max_bandwidth)
                {
                    thread_rwlock_unlock (&source->lock);
                    INFO0 ("server-wide outgoing bandwidth limit reached");
                    return client_send_403redirect (client, passed_mount, "server bandwidth reached");
                }
            }
            if ((client->flags & CLIENT_AUTHENTICATED) == 0 || httpp_getvar (client->parser, "range"))
            {
                int ret;
                int (*build_headers)(format_plugin_t *, client_t *) = format_general_headers;

                if (source->format->create_client_data)
                    build_headers = source->format->create_client_data;

                client->refbuf->len = 0;
                ret = build_headers (source->format, client);

                if (ret < 0)
                {
                    thread_rwlock_unlock (&source->lock);
                    return ret;
                }
                if (client->parser->req_type == httpp_req_head)
                    break;
                if ((client->flags & CLIENT_HAS_INTRO_CONTENT) == 0 && client->refbuf->next)
                    break;
                if ((source->flags & (SOURCE_RUNNING|SOURCE_ON_DEMAND)) == SOURCE_ON_DEMAND)
                {
                    // inactive ondemand relay to kick off, reset client, try headers later
                    client->respcode = 0;
                    client->pos = 0;
                }
                stats_lock (source->stats, source->mount);
                stats_set_inc (source->stats, "listener_connections");
                stats_release (source->stats);
            }
        }

        if (mountinfo == NULL)
            break; /* allow adding listeners, no mount limits imposed */

        if (mountinfo->intro_skip_replay)
            listener_check_intro (source->intro_ipcache, client, mountinfo->intro_skip_replay);

        if (check_duplicate_logins (source->mount, source->clients, client, mountinfo->auth) == 0)
        {
            thread_rwlock_unlock (&source->lock);
            return client_send_403 (client, "Account already in use");
        }

        /* set a per-mount disconnect time if auth hasn't set one already */
        if (mountinfo->max_listener_duration && client->connection.discon.time == 0)
            client->connection.discon.time = time(NULL) + mountinfo->max_listener_duration;

        INFO3 ("max on %s is %d (cur %lu)", source->mount,
                mountinfo->max_listeners, source->listeners);
        within_limits = 1;
        if (mountinfo->max_bandwidth > -1 && stream_bitrate)
        {
            DEBUG3 ("checking bandwidth limits for %s (%" PRId64 ", %" PRId64 ")",
                    mountinfo->mountname, stream_bitrate, mountinfo->max_bandwidth);
            if ((source->listeners+1) * stream_bitrate > mountinfo->max_bandwidth)
            {
                INFO1 ("bandwidth limit reached on %s", source->mount);
                within_limits = 0;
            }
        }
        if (within_limits)
        {
            if (mountinfo->max_listeners == -1)
                break;

            if (source->listeners < (unsigned long)mountinfo->max_listeners)
                break;
            INFO1 ("max listener count reached on %s", source->mount);
        }
        /* minfo starts off as mountinfo put cascades through fallbacks */
        if (minfo && minfo->fallback_when_full && minfo->fallback_mount)
        {
            thread_rwlock_unlock (&source->lock);
            len = sizeof buffer;
            if (util_expand_pattern (mount, minfo->fallback_mount, buffer, &len) < 0)
                mount = minfo->fallback_mount;
            else
                mount = buffer;
            INFO1 ("stream full trying %s", mount);
            loop--;
            continue;
        }

        /* now we fail the client */
        thread_rwlock_unlock (&source->lock);
        return client_send_403redirect (client, passed_mount, "max listeners reached");

    } while (1);

    client->connection.sent_bytes = 0;

    if ((client->flags & CLIENT_AUTHENTICATED) == 0)
    {
        thread_rwlock_unlock (&source->lock);
        return fserve_setup_client (client);
    }

    if (client->respcode == 0)
    {
        client->refbuf->len = PER_CLIENT_REFBUF_SIZE;
        memset (client->refbuf->data, 0, PER_CLIENT_REFBUF_SIZE);
    }

    global_lock();
    if (config->max_listeners)
    {
        if (config->max_listeners <= global.listeners)
        {
            global_unlock();
            thread_rwlock_unlock (&source->lock);
            return client_send_403redirect (client, passed_mount, "max listeners reached");
        }
    }
    global.listeners++;
    global_unlock();

    httpp_deletevar (client->parser, "range");
    if (client->flags & CLIENT_RANGE_END)
    {
        // range given on a stream, impose a length limit
        if ((off_t)client->connection.discon.offset > client->intro_offset)
        {
            client->connection.discon.offset -= client->intro_offset;
            client->intro_offset = 0;
        }
        else
        {
            client->flags &= ~CLIENT_RANGE_END;
        }
    }
    source_setup_listener (source, client);
    source->listeners++;

    if ((client->flags & CLIENT_ACTIVE) && (source->flags & SOURCE_RUNNING))
        do_process = 1;
    else
    {
        client->flags |= CLIENT_ACTIVE; // from an auth thread context
        worker_wakeup (client->worker);
    }
    thread_rwlock_unlock (&source->lock);
    global_reduce_bitrate_sampling (global.out_bitrate);

    stats_event_inc (NULL, "listener_connections");

    if (do_process) // send something back quickly
        return client->ops->process (client);
    return 0;
}


/* call with the source lock held, but expect the lock released on exit
 * as the listener may of changed threads and therefore lock needed to be
 * released
 */
void source_setup_listener (source_t *source, client_t *client)
{
    if (source->flags & SOURCE_LISTENERS_SYNC)
        client->ops = &listener_wait_ops;
    else if ((source->flags & (SOURCE_RUNNING|SOURCE_ON_DEMAND)) == SOURCE_ON_DEMAND)
        client->ops = &listener_pause_ops;
    else
        client->ops = &listener_client_ops;
    client->shared_data = source;
    client->queue_pos = 0;
    client->mount = source->mount;
    client->flags &= ~CLIENT_IN_FSERVE;

    if (client->connection.sent_bytes > 0)
        client->check_buffer = http_source_introfile; // may need incomplete data sending
    else
        client->check_buffer = http_source_listener; // special case for headers
    // add client to the source
    avl_insert (source->clients, client);
    if (source->flags & SOURCE_ON_DEMAND)
        source->client->connection.discon.time = 0; // a run-over with on-demand relays needs resetting

    if ((source->flags & (SOURCE_ON_DEMAND|SOURCE_RUNNING)) == SOURCE_ON_DEMAND)
    {
        source->client->schedule_ms = 0;
        client->schedule_ms += 300;
        worker_wakeup (source->client->worker);
        DEBUG1 ("woke up relay on %s", source->mount);
    }
}


static int source_client_http_send (client_t *client)
{
    refbuf_t *stream;
    source_t *source = client->shared_data;

    while (client->pos < client->refbuf->len)
    {
        if (client->connection.error || format_generic_write_to_client (client) < 0)
        {
            client->schedule_ms = client->worker->time_ms + 40;
            if (client->connection.error == 0)
                return 0; /* trap for short writes */
            global_lock();
            global.sources--;
            stats_event_args (NULL, "sources", "%d", global.sources);
            global_unlock();
            drop_source_from_tree (source);
            WARN1 ("failed to send OK response to source client for %s", source->mount);
            return -1;
        }
    }
    stream = client->refbuf->associated;
    client->refbuf->associated = NULL;
    refbuf_release (client->refbuf);
    client->refbuf = stream;
    client->pos = client->intro_offset;
    client->intro_offset = 0;
    thread_rwlock_wlock (&source->lock);
    return source_client_callback (client);
}


int source_format_init (source_t *source)
{
    client_t *client = source->client;
    format_plugin_t *format = source->format;

    if (format->mount == NULL)
    {
        if (format->type == FORMAT_TYPE_UNDEFINED)
        {
            format_type_t format_type = FORMAT_TYPE_MPEG;
            const char *contenttype;

            DEBUG2 ("%sparser found for %s", client->parser ? "":"no ", source->mount);
            if (client->parser == NULL)
                return 0;
            contenttype = httpp_getvar (client->parser, "content-type");
            if (contenttype)
            {
                if (strcmp (contenttype, "application/octet-stream") != 0)
                    format_type = format_get_type (contenttype);
                if (format_type == FORMAT_TYPE_UNDEFINED)
                {
                    WARN1("Content-type \"%s\" not supported, assuming mpeg", contenttype);
                    format_type = FORMAT_TYPE_MPEG;
                }
            }
            else
                WARN1("No content-type for %s, Assuming content is mpeg.", source->mount);
            format->type = format_type;
        }
        format->mount = source->mount;
        if (format_get_plugin (format) < 0)
        {
            WARN1 ("plugin format failed for \"%s\"", source->mount);
            return -1;
        }
    }
    format_apply_client (format, client);
    return 0;
}


static void source_swap_client (source_t *source, client_t *client)
{
    client_t *old_client = source->client;

    INFO2 ("source %s hijacked by another client, terminating previous (at %"PRIu64")", source->mount, old_client->queue_pos);
    client->shared_data = source;
    source->client = client;

    old_client->schedule_ms = client->worker->time_ms;
    old_client->shared_data = NULL;
    old_client->flags &= ~CLIENT_AUTHENTICATED;
    old_client->connection.sent_bytes = source->format->read_bytes;
    client->queue_pos = old_client->queue_pos;

    source->format->read_bytes = 0;
    source->format->parser = source->client->parser;
    if (source->format->swap_client)
        source->format->swap_client (client, old_client);

    worker_wakeup (old_client->worker);
}


int source_startup (client_t *client, const char *uri)
{
    source_t *source;
    ice_config_t *config = config_get_config();
    mount_proxy *mountinfo;
    int source_limit = config->source_limit;

    config_release_config();

    source = source_reserve (uri, (client->flags & CLIENT_HIJACKER) ? 1 : 0);
    if (source)
    {
        if ((client->flags & CLIENT_HIJACKER) && source_running (source))
        {
            source_swap_client (source, client);
        }
        else
        {
            global_lock();
            source->client = client;
            if (global.sources >= source_limit)
            {
                WARN1 ("Request to add source when maximum source limit reached %d", global.sources);
                global_unlock();
                thread_rwlock_unlock (&source->lock);
                source_free_source (source);
                return client_send_403 (client, "too many streams connected");
            }
            if (source_format_init (source) < 0)
            {
                global_unlock();
                source->client = NULL;
                thread_rwlock_unlock (&source->lock);
                source_free_source (source);
                return client_send_403 (client, "content type not supported");
            }
            ++global.sources;
            source->stats = stats_lock (source->stats, source->mount);
            stats_release (source->stats);
            INFO1 ("sources count is now %d", global.sources);
            stats_event_args (NULL, "sources", "%d", global.sources);
            global_unlock();
        }
        client->respcode = 200;
        client->shared_data = source;

        config = config_get_config();
        mountinfo = config_find_mount (config, source->mount);
        source_update_settings (config, source, mountinfo);
        INFO1 ("source %s is ready to start", source->mount);
        config_release_config();

        if (client->server_conn && client->server_conn->shoutcast_compat)
        {
            source->flags |= SOURCE_SHOUTCAST_COMPAT;
            source_client_callback (client);
        }
        else
        {
            refbuf_t *ok = refbuf_new (PER_CLIENT_REFBUF_SIZE);
            snprintf (ok->data, PER_CLIENT_REFBUF_SIZE,
                    "HTTP/1.0 200 OK\r\n\r\n");
            ok->len = strlen (ok->data);
            /* we may have unprocessed data read in, so don't overwrite it */
            ok->associated = client->refbuf;
            client->refbuf = ok;
            client->intro_offset = client->pos;
            client->pos = 0;
            client->ops = &source_client_http_ops;
            thread_rwlock_unlock (&source->lock);
        }
        if ((client->flags & CLIENT_ACTIVE) == 0)
        {
            client->flags |= CLIENT_ACTIVE;
            worker_wakeup (client->worker);
        }
        return 0;
    }
    WARN1 ("Mountpoint %s in use", uri);
    return client_send_403 (client, "Mountpoint in use");
}


/* check to see if the source client can be moved to a less busy worker thread.
 * we only move the source client, not the listeners, they will move later
 */
static int source_change_worker (source_t *source, client_t *client)
{
    worker_t *this_worker = client->worker, *worker;
    int ret = 0;

    thread_rwlock_rlock (&workers_lock);
    if (this_worker->move_allocations)
    {
        int bypass = is_worker_incoming (this_worker) ? 1 : 0;

        worker = worker_selected ();
        if (worker && worker != client->worker && (bypass || worker->count > 100))
        {
            long diff = bypass ? 2000000 : this_worker->count - worker->count;
            if (diff - (long)source->listeners < 10)
                diff = 0;   // lets not move the source in this case.
            int base = (client->connection.id & 7) << 5;
            if ((diff > 2000 && worker->count > 200) || (diff > (source->listeners>>4) + base))
            {
                char *mount = strdup (source->mount);
                thread_rwlock_unlock (&source->lock);

                thread_spin_lock (&this_worker->lock);
                if (this_worker->move_allocations < 1000000)
                    this_worker->move_allocations--;
                thread_spin_unlock (&this_worker->lock);

                ret = client_change_worker (client, worker);
                thread_rwlock_unlock (&workers_lock);
                if (ret)
                    DEBUG3 ("moving source %s from %p to %p", mount, this_worker, worker);
                else
                    thread_rwlock_wlock (&source->lock);
                free (mount);
                return ret;
            }
        }
    }
    thread_rwlock_unlock (&workers_lock);
    return 0;
}


/* move listener client to worker theread that the source is on. This will
 * help cache but prevent overloading a single worker with many listeners.
 */
int listener_change_worker (client_t *client, source_t *source)
{
    worker_t *this_worker = client->worker, *dest_worker = source->client->worker;
    int ret = 0, spin = 0, locked = 0;
    long diff = 0;

    do
    {
        if (is_worker_incoming (this_worker) == 0 && (this_worker->time_ms & 0x14))
            break;      // routine called frequently, but we do not need to reassess so frequently for normal workers
        if (thread_rwlock_tryrlock (&workers_lock) != 0)
            break;
        locked = 1;
        if (this_worker == dest_worker)
            dest_worker = worker_selected ();

        if (dest_worker && this_worker != dest_worker)
        {
            int move = 0;
            int adj = ((client->connection.id & 7) << 6) + 100;

            thread_spin_lock (&dest_worker->lock);
            int dest_count = dest_worker->count;
            thread_spin_unlock (&dest_worker->lock);

            thread_spin_lock (&this_worker->lock);
            spin = 1;
            if (this_worker->move_allocations == 0)
                break;      // already moved many, skip for now
            int this_alloc = this_worker->move_allocations;

            if (is_worker_incoming (this_worker) == 0)
            {
                this_worker->move_allocations--;
                diff = this_worker->count - dest_count;
                if (diff < adj)
                    break;      // ignore the move this time
            }
            move = 1;
            thread_spin_unlock (&this_worker->lock);
            spin = 0;
            DEBUG3 ("dest count is %d, %d, move %d", dest_count, this_alloc, move);

            if (move)
            {
                thread_rwlock_unlock (&source->lock);
                uint64_t  id = client->connection.id;
                ret = client_change_worker (client, dest_worker);
                if (ret)
                    DEBUG4 ("moving listener %" PRIu64 " on %s from %p to %p", id, source->mount, this_worker, dest_worker);
                else
                    thread_rwlock_rlock (&source->lock);
            }
        }
    } while (0);

    if (spin)
        thread_spin_unlock (&this_worker->lock);
    if (locked)
        thread_rwlock_unlock (&workers_lock);
    return ret;
}

