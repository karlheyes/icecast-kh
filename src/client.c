/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2013, Jack Moffitt <jack@xiph.org>,
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 *
 * Copyright 2000-2022, Karl Heyes <karl@kheyes.plus.com>
 *
 */

/* client.c
**
** client interface implementation
**
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>

#include "thread/thread.h"
#include "avl/avl.h"
#include "httpp/httpp.h"
#include "timing/timing.h"

#include "client.h"
#include "cfgfile.h"
#include "connection.h"
#include "refbuf.h"
#include "format.h"
#include "stats.h"
#include "fserve.h"

#include "client.h"
#include "logging.h"
#include "slave.h"
#include "global.h"
#include "util.h"

#undef CATMODULE
#define CATMODULE "client"

int worker_count = 0, worker_min_count;
worker_t *worker_balance_to_check, *worker_least_used, *worker_incoming = NULL;

FD_t logger_fd[2];


void client_register (client_t *client)
{
    if (client)
        global.clients++;
}


const char *client_keepalive_header (client_t *client)
{
    return (client->flags & CLIENT_KEEPALIVE) ?  "Connection: Keep-Alive" : "Connection: Close";
}


/* verify that the socket is still connected. */
int client_connected (client_t *client)
{
    int ret = 1;
    if (client)
    {
        if (sock_active (client->connection.sock) == 0)
            ret = 0;
    }
    return ret;
}


void client_destroy(client_t *client)
{
    if (client == NULL)
        return;

    if (client->worker)
    {
        WARN0 ("client still on worker thread");
        return;
    }
    /* release the buffer now, as the buffer could be on the source queue
     * and may of disappeared after auth completes */
    if (client->refbuf)
    {
        refbuf_release (client->refbuf);
        client->refbuf = NULL;
    }

    if (client->flags & CLIENT_AUTHENTICATED)
        DEBUG1 ("client still authenticated \"%s\"", httpp_getvar (client->parser, HTTPP_VAR_URI));

    /* write log entry if ip is set (some things don't set it, like outgoing
     * slave requests
     */
    if (client->respcode > 0 && client->parser)
        logging_access(client);

    if (client->flags & CLIENT_IP_BAN_LIFT)
    {
        INFO1 ("lifting IP ban on client at %s", client->connection.ip);
        connection_release_banned_ip (client->connection.ip);
        client->flags &= ~CLIENT_IP_BAN_LIFT;
    }

    if (client->parser)
        httpp_destroy (client->parser);

    /* we need to free client specific format data (if any) */
    if (client->free_client_data)
        client->free_client_data (client);

    free(client->username);
    free(client->password);
    client->username = NULL;
    client->password = NULL;
    client->parser = NULL;
    client->respcode = 0;
    client->free_client_data = NULL;

    if (not_ssl_connection (&client->connection))
        sock_set_cork (client->connection.sock, 0); // ensure any corked data is actually sent.

    do
    {
        global_lock ();
        if (global.running != ICE_RUNNING || (client->connection.error == CONN_ERR_DOWN) ||
                (client->flags & CLIENT_KEEPALIVE) == 0 || client_connected (client) == 0)
        {
            global.clients--;
            config_clear_listener (client->server_conn);
            global_unlock ();
            connection_close (&client->connection);

            free(client);
            return;
        }
        global_unlock ();
        client->counter = client->schedule_ms = timing_get_time();
    } while (connection_reset (&client->connection, client->schedule_ms) < 0);  // loop back on failure to kick out

    DEBUG2 ("keepalive detected on %s (%" PRI_ConnID "), placing back onto worker", CONN_ADDR(client), CONN_ID(client));

    client->flags = 0;
    client->ops = &http_request_ops;
    client->shared_data = NULL;
    client->refbuf = NULL;
    client->pos = 0;
    client->intro_offset = 0;
    client_add_incoming (client);
}


int client_compare (void *compare_arg, void *a, void *b)
{
    client_t *ca = a, *cb = b;

    if (ca->connection.id < cb->connection.id) return -1;
    if (ca->connection.id > cb->connection.id) return 1;

    return 0;
}


/* helper function for reading data from a client */
int client_read_bytes (client_t *client, void *buf, unsigned len)
{
    int (*con_read)(struct connection_tag *handle, void *buf, size_t len) = connection_read;
    int bytes;

    if (len == 0)
        return 0;
    if (client->refbuf && client->pos < client->refbuf->len)
    {
        unsigned remaining = client->refbuf->len - client->pos;
        if (remaining > len)
            remaining = len;
        memcpy (buf, client->refbuf->data + client->pos, remaining);
        if (remaining > 2)
            {unsigned char*b = buf; DEBUG4 ("transferring %d (%2x %2x %2x) bytes previously stored", remaining, b[0], b[1], b[2]);}
        client->pos += remaining;
        if (client->pos >= client->refbuf->len)
            client_set_queue (client, NULL);
        return remaining;
    }
#ifdef HAVE_OPENSSL
    if (client->connection.ssl)
        con_read = connection_read_ssl;
#endif
    bytes = con_read (&client->connection, buf, len);

    if (bytes == -1 && client->connection.error && client->aux_data != (uintptr_t)-1)
        DEBUG2 ("reading from connection %"PRI_ConnID " from %s has failed", CONN_ID(client), CONN_ADDR(client));

    return bytes;
}


int client_send_302(client_t *client, const char *location)
{
    if (location == NULL) return -1;
    ice_http_t http = ICE_HTTP_INIT;
    ice_http_setup_flags (&http, client, 302, 0, NULL);
    ice_http_printf (&http, "Location", 0, "%s", location);
    return client_http_send (&http);
}


int client_send_400(client_t *client, const char *message)
{
    ice_http_t http = ICE_HTTP_INIT;
    ice_http_setup_flags (&http, client, 400, 0, NULL);
    ice_http_printf (&http, NULL, 0, "%s", message);
    return client_http_send (&http);

}


int client_send_403redirect (client_t *client, const char *mount, const char *reason)
{
    if (redirect_client (mount, client))
        return 0;
    return client_send_403 (client, reason);
}


int client_send_401 (client_t *client, const char *realm)
{
    ice_http_t http = ICE_HTTP_INIT;
    if (ice_http_setup_flags (&http, client, 401, 0, NULL) < 0) return -1;
    client_set_queue (client,NULL);
    ice_http_printf (&http, "WWW-Authenticate", 0, "Basic realm=\"%s\"", (realm ? realm : http.in_realm));
    return client_http_send (&http);
}


int client_send_403 (client_t *client, const char *reason)
{
    ice_http_t http = ICE_HTTP_INIT;
    client_set_queue (client,NULL);
    if (ice_http_setup_flags (&http, client, 403, 0, reason) < 0) return -1;
    return client_http_send (&http);
}

int client_send_404 (client_t *client, const char *message)
{
    ice_http_t http = ICE_HTTP_INIT;
    if (ice_http_setup_flags (&http, client, 404, 0, NULL) < 0) return -1;
    client_set_queue (client,NULL);
    if (message)
        ice_http_printf (&http, NULL, 0, "%s", message);
    return client_http_send (&http);
}


int client_send_416(client_t *client)
{
    ice_http_t http = ICE_HTTP_INIT;
    if (ice_http_setup_flags (&http, client, 416, 0, NULL) < 0) return -1;
    const char *fs = httpp_getvar (client->parser, "__FILESIZE");
    if (fs)
        ice_http_printf (&http, "Content-Range", 0, "*/%s", fs);
    client_set_queue (client,NULL);
    return client_http_send (&http);
}


int client_send_501(client_t *client)
{
    ice_http_t http = ICE_HTTP_INIT;
    if (ice_http_setup_flags (&http, client, 501, 0, NULL) < 0) return -1;
    return client_http_send (&http);
}


int client_send_options(client_t *client)
{
    ice_http_t http = ICE_HTTP_INIT;
    if (ice_http_setup_flags (&http, client, 204, 0, NULL) < 0) return -1;
    client_set_queue (client,NULL);
    return client_http_send (&http);
}


/* helper function for sending the data to a client */
int client_send_bytes (client_t *client, const void *buf, unsigned len)
{
    int (*con_send)(struct connection_tag *handle, const void *buf, size_t len) = connection_send;
    int ret;
#ifdef HAVE_OPENSSL
    if (client->connection.ssl)
        con_send = connection_send_ssl;
#endif
    ret = con_send (&client->connection, buf, len);

    if (client->connection.error == CONN_ERR_FINI)
        DEBUG3 ("Client %"PRI_ConnID " connection on %s from %s finished", CONN_ID(client), (client->mount ? client->mount:"unknown"), CONN_ADDR(client));
    else if (client->connection.error)
        DEBUG3 ("Client %"PRI_ConnID " connection on %s from %s died", CONN_ID(client), (client->mount ? client->mount:"unknown"), CONN_ADDR(client));

    return ret;
}


int client_send_buffer (client_t *client)
{
    const char *buf = client->refbuf->data + client->pos;
    int len = client->refbuf->len - client->pos;
    int ret = client_send_bytes (client, buf, len);

    if (ret > 0)
        client->pos += ret;
    if (client->connection.error == 0 && client->pos >= client->refbuf->len && client->aux_data)
    {
        int (*callback)(client_t *) = (void *)client->aux_data;
        return callback (client);
    }
    return ret;
}


struct _client_functions client_buffer_ops =
{
    client_send_buffer,
    client_destroy
};


int client_send_buffer_callback (client_t *client, int(*callback)(client_t*))
{
    client->aux_data = (uintptr_t)callback;
    client->ops = &client_buffer_ops;
    return 0;
}


int client_send_m3u (client_t *client, const char *path)
{
    const char  *host = httpp_getvar (client->parser, "host"),
          *args = httpp_getvar (client->parser, HTTPP_VAR_QUERYARGS);
    char *sourceuri = strdup (path);
    char *dot = strrchr (sourceuri, '.');
    char *protocol = not_ssl_connection (&client->connection) ? "http" : "https";
    const char *agent = httpp_getvar (client->parser, "user-agent");
    char userpass[1000] = "";
    char hostport[1000] = "";

    if (agent)
    {
        if (strstr (agent, "QTS") || strstr (agent, "QuickTime"))
            protocol = "icy";
    }
    /* at least a couple of players (fb2k/winamp) are reported to send a
     * host header but without the port number. So if we are missing the
     * port then lets treat it as if no host line was sent */
    if (host && strchr (host, ':') == NULL)
        host = NULL;

    if (dot)
        *dot = 0;
    do
    {
        if (client->username && client->password)
        {
            int ret = snprintf (userpass, sizeof userpass, "%s:%s@", client->username, client->password);
            if (ret < 0 || ret >= sizeof userpass)
                break;
        }
        if (host == NULL)
        {
            ice_config_t *config = config_get_config();
            int ret = snprintf (hostport, sizeof hostport, "%s:%u", config->hostname, config->port);
            if (ret < 0 || ret >= sizeof hostport)
                break;
            config_release_config();
            host = hostport;
        }
        ice_http_t http = ICE_HTTP_INIT;
        ice_http_setup_flags (&http, client, 200, 0, NULL);
        ice_http_printf (&http, "Content-Type", 0,              "%s", "audio/x-mpegurl");
        ice_http_printf (&http, "Content-Disposition", 0,       "%s", "attachment; filename=\"listen.m3u\"");
        ice_http_printf (&http, NULL, 0, "%s://%s%s%s%s\n", protocol, userpass, host, sourceuri, args?args:"");
        ice_http_complete (&http);
        free (sourceuri);
        return fserve_setup_client_fb (client, NULL);
    } while (0);
    free (sourceuri);
    return client_send_400 (client, "Not Available");
}


void client_set_queue (client_t *client, refbuf_t *refbuf)
{
    refbuf_t *next, *to_release = client->refbuf;

    while (to_release)
    {
        if (to_release->flags & REFBUF_SHARED)
        {
            ERROR1 ("content has a shared flag status for %s", client->connection.ip);
            break;
        }
        next = to_release->next;
        to_release->next = NULL;
        refbuf_release (to_release);
        to_release = next;
    }

    client->refbuf = refbuf;
    if (refbuf)
        refbuf_addref (client->refbuf);

    client->pos = 0;
}


int is_worker_incoming (worker_t *w)
{
    return (w == worker_incoming) ? 1 : 0;
}


static uint64_t worker_check_time_ms (worker_t *worker)
{
    uint64_t tm = timing_get_time();
    if (tm - worker->time_ms > 1000 && worker->time_ms)
        WARN2 ("worker %p has been stuck for %" PRIu64 " ms", worker, (tm - worker->time_ms));
    return tm;
}


static worker_t *find_least_busy_handler (int log)
{
    worker_t *min = workers;
    int min_count = INT_MAX;

    if (workers && workers->next)
    {
        worker_t *handler = workers;

        while (handler)
        {
            thread_mutex_lock (&handler->lock);
            int cur_count = handler->count + handler->pending_count;
            thread_mutex_unlock (&handler->lock);

            if (log) DEBUG2 ("handler %p has %d clients", handler, cur_count);
            if (cur_count < min_count)
            {
                min = handler;
                min_count = cur_count;
            }
            handler = handler->next;
        }
        worker_min_count = min_count;
    }
    return min;
}


worker_t *worker_selected (void)
{
    return worker_least_used;
}


/* worker mutex should be already locked */
static void worker_add_client (worker_t *worker, client_t *client)
{
    ++worker->pending_count;
    client->next_on_worker = NULL;
    *worker->pending_tailp = client;
    worker->pending_tailp = &client->next_on_worker;
    client->worker = worker;
}


int client_change_worker (client_t *client, worker_t *dest_worker)
{
    if (dest_worker->running == 0)
        return 0;
    client->next_on_worker = NULL;

    thread_mutex_lock (&dest_worker->lock);
    worker_add_client (dest_worker, client);
    thread_mutex_unlock (&dest_worker->lock);
    worker_wakeup (dest_worker);

    return 1;
}


void client_add_worker (client_t *client)
{
    worker_t *handler;

    thread_rwlock_rlock (&workers_lock);
    /* add client to the handler with the least number of clients */
    handler = worker_selected();
    thread_mutex_lock (&handler->lock);
    thread_rwlock_unlock (&workers_lock);

    worker_add_client (handler, client);
    thread_mutex_unlock (&handler->lock);
    worker_wakeup (handler);
}


int client_add_incoming (client_t *client)
{
    worker_t *handler;

    if (client->worker) return 0;
    client->schedule_ms = 0;
    thread_rwlock_rlock (&workers_lock);
    handler = worker_incoming;
    thread_mutex_lock (&handler->lock);

    worker_add_client (handler, client);
    thread_mutex_unlock (&handler->lock);
    worker_wakeup (handler);
    thread_rwlock_unlock (&workers_lock);
    return 1;
}


#ifdef _WIN32
#define pipe_create         sock_create_pipe_emulation
#define pipe_write(A, B, C) send(A, B, C, 0)
#define pipe_read(A,B,C)    recv(A, B, C, 0)
#else
 #ifdef HAVE_PIPE2
 #define pipe_create(x)      pipe2(x,O_CLOEXEC)
 #elif defined(FD_CLOEXEC)
  int pipe_create(FD_t x[]) {
    int r = pipe(x); if (r==0) {fcntl(x[0], F_SETFD,FD_CLOEXEC); \
    fcntl(x[1], F_SETFD,FD_CLOEXEC); } return r;
  }
 #else
  #define pipe_create pipe
 #endif
 #define pipe_write write
 #define pipe_read read
#endif


void worker_control_create (FD_t wakeup_fd[])
{
    if (pipe_create (&wakeup_fd[0]) < 0)
    {
        ERROR0 ("pipe failed, descriptor limit?");
        abort();
    }
    sock_set_blocking (wakeup_fd[0], 0);
    sock_set_blocking (wakeup_fd[1], 0);
}


typedef struct {
    worker_t *worker;
    client_t **prevp;
    uint64_t sched_ms;
    uint64_t wakeup_ms;
    uint16_t max_run;
    uint16_t time_recheck;
    uint16_t flags;
} worker_client_t;

#define WKRC_NORMAL_CLIENTS     (1)
#define WKRC_NORMAL_AFTER       (1<<1) // set when WKRC_NORMAL_CLIENTS is unset to cause an auto run of both fast and normal
#define WKR_CLIENT_INIT(W)      { .worker = W, .max_run = 1000, .flags = WKRC_NORMAL_CLIENTS }

static void worker_add_pending_clients (worker_client_t *wc)
{
    worker_t *worker = wc->worker;
    thread_mutex_lock (&worker->lock);
    if (worker->pending_clients)
    {
        *worker->fast_tailp = worker->pending_clients;
        worker->fast_tailp = worker->pending_tailp;
        worker->count += worker->pending_count;
        worker->pending_clients = NULL;
        worker->pending_tailp = &worker->pending_clients;
        unsigned count = worker->pending_count;
        worker->pending_count = 0;
        thread_mutex_unlock (&worker->lock);
        DEBUG2 ("Added %d pending clients to %p", count, worker);
        wc->prevp = &worker->fast_clients;
        wc->flags &= ~WKRC_NORMAL_CLIENTS;
        return;
    }
    thread_mutex_unlock (&worker->lock);
}


// enter with spin lock enabled, exit without
//
static void worker_wait (worker_client_t *wc)
{
    worker_t *worker = wc->worker;
    int ret = 0, duration = 1, running = worker->running;

    thread_mutex_unlock (&worker->lock);
    if (running)
    {
        uint64_t tm = worker_check_time_ms (worker);
        if (wc->wakeup_ms > tm)
            duration = (int)(wc->wakeup_ms - tm);
        if (duration > 60000) /* make duration at most 60s */
            duration = 60000;
    }
    else
    {
        wc->prevp = &worker->fast_clients;
        wc->flags &= ~WKRC_NORMAL_CLIENTS;
        wc->flags |= WKRC_NORMAL_AFTER;
        if (worker->count)
            DEBUG3 ("%p, %d clients, %s flush", worker, worker->count, wc->flags & WKRC_NORMAL_CLIENTS ? "normal" : "fast");
        return;
    }
    if (wc->flags & WKRC_NORMAL_CLIENTS)
    {
        if (duration < 5)
            wc->flags |= WKRC_NORMAL_AFTER;
        if (worker->fast_clients)
        {
            wc->prevp = &worker->fast_clients;
            wc->flags &= ~WKRC_NORMAL_CLIENTS;
            return;
        }

        // DEBUG2 ("%p for %d msec", worker, duration);
        ret = util_timed_wait_for_fd (worker->wakeup_fd[0], duration);
    }
    wc->flags |= WKRC_NORMAL_CLIENTS;
    if (ret > 0) /* may of been several wakeup attempts */
    {
        char ca[150];
        do
        {
            ret = pipe_read (worker->wakeup_fd[0], ca, sizeof ca);
            if (ret > 0)
                break;
            if (ret < 0 && sock_recoverable (sock_error()))
                break;
            sock_close (worker->wakeup_fd[1]);
            sock_close (worker->wakeup_fd[0]);
            worker_control_create (&worker->wakeup_fd[0]);
            worker_wakeup (worker);
            WARN0 ("Had to recreate worker control feed");
        } while (1);
        worker_add_pending_clients (wc);
    }
    if (worker->fast_clients)
    {
        wc->flags &= ~WKRC_NORMAL_CLIENTS;
        wc->prevp = &worker->fast_clients;
    }
    else
    {
        wc->flags &= ~WKRC_NORMAL_AFTER;
        wc->prevp = &worker->clients;
    }
    wc->sched_ms = 0;
}


static void worker_relocate_clients (worker_client_t *wc)
{
    worker_t *worker = wc->worker;
    if (workers == NULL)
        return;
    while (worker->count || worker->pending_count)
    {
        client_t *client = worker->clients, **prevp = &worker->clients;

        wc->wakeup_ms = worker->time_ms + 150;
        worker->current_time.tv_sec = (time_t)(worker->time_ms/1000);
        while (client)
        {
            client->worker = workers;
            prevp = &client->next_on_worker;
            client = *prevp;
        }
        if (worker->clients)
        {
            thread_mutex_lock (&workers->lock);
            *workers->pending_tailp = worker->clients;
            workers->pending_tailp = prevp;
            workers->pending_count += worker->count;
            thread_mutex_unlock (&workers->lock);
            worker_wakeup (workers);
            worker->clients = NULL;
            worker->last_p = &worker->clients;
            worker->count = 0;
        }
        thread_mutex_lock (&worker->lock);
        worker_wait (wc);
    }
}


static void worker_removed_client (worker_client_t *wc, client_t *next)
{
    worker_t *worker = wc->worker;
    // DEBUG3 (" %p, prevp %p, next %p", worker, *wc->prevp, next);
    worker->count--;
    if (next == NULL)
    {
        if ((wc->flags & WKRC_NORMAL_CLIENTS))
            worker->last_p = wc->prevp;
        else
            worker->fast_tailp = wc->prevp;
    }
    *wc->prevp = next;
}


static client_t *worker_next_client (worker_client_t *wc)
{
    worker_t *worker = wc->worker;
    client_t *client = *wc->prevp, *next = client->next_on_worker;

    int fast = 0;
    if (client->schedule_ms < worker->time_ms + 2 && client->fast_count < 4)
        fast = 1;       // treat as reschedule quickly, add to end of fast list
    if ((wc->flags & WKRC_NORMAL_CLIENTS))
    {
        if (fast)
        {   // put client on fast list
            // DEBUG2 ("%p, cl %p, fast on normal, avoid wakeup", worker, client);
            *worker->fast_tailp = client;
            worker->fast_tailp = &client->next_on_worker;
            if (client->next_on_worker == NULL)
                worker->last_p = wc->prevp;
            client->next_on_worker = NULL;
            *wc->prevp = next;
            return next;
        }
        if (next)
            wc->prevp = &client->next_on_worker;
        // DEBUG2 ("%p, cl %p, next on normal", worker, client);
    }
    else
    {
        if (fast)
        {
            if (next)
                wc->prevp = &client->next_on_worker;
            client->fast_count++;
            // DEBUG2 ("%p, cl %p, next on fast, avoid wakeup", worker, client);
            return next;
        }
        // DEBUG2 ("%p, cl %p, normal on fast", worker, client);
        // put client on normal list
        *worker->last_p = client;
        worker->last_p = &client->next_on_worker;
        if (client->next_on_worker == NULL)
            worker->fast_tailp = wc->prevp;
        client->next_on_worker = NULL;
        *wc->prevp = next;
    }
    if (client->schedule_ms < wc->wakeup_ms)
        wc->wakeup_ms = client->schedule_ms;
    client->fast_count = 0;
    return next;
}


static client_t *worker_pick_client (worker_client_t *wc)
{
    worker_t *worker = wc->worker;
    int worker_shutdown = (worker->running == 0);
    if (wc->max_run == 0)
    {
        wc->max_run = worker->count + 200;
        wc->sched_ms = 0;
        wc->wakeup_ms = worker->time_ms;
        // DEBUG1 ("%p max run limit reached, reset", worker);
        return NULL;
    }
    if (wc->time_recheck == 0)
    {
        thread_mutex_unlock (&worker->lock);
        worker->time_ms = timing_get_time();
        worker->current_time.tv_sec = (time_t)(worker->time_ms/1000);
        wc->time_recheck = 50;
        // DEBUG2 ("%p time recheck at %ld", worker, worker->time_ms);
        thread_mutex_lock (&worker->lock);
    }
    if (wc->sched_ms == 0)
    {   // update these periodically to keep in sync
        wc->wakeup_ms = worker->time_ms + 30000;
        wc->sched_ms = worker->time_ms + 2;
        if (wc->prevp == NULL) return NULL;
        // DEBUG2 ("time check %ld, sched thresh %ld", worker->time_ms, wc->sched_ms);
    }
    client_t *client;
#if 0
    DEBUG2 ("wlist %p, %s clients", worker, wc->flags & WKRC_NORMAL_CLIENTS ? "normal" : "fast");
    for (client = *wc->prevp; client; client = client->next_on_worker)
    {
         client_t **l = (wc->flags & WKRC_NORMAL_CLIENTS) ? worker->last_p : worker->fast_tailp;
         DEBUG4 ("wlist, L %d P %d, c %p, %ld", (l == &client->next_on_worker)? 1 : 0, *wc->prevp == client ? 1 : 0, client, client->schedule_ms);
    }
#endif
    client = *wc->prevp;
    while (1)
    {
        int fast_client = worker_shutdown || (wc->flags & WKRC_NORMAL_CLIENTS)==0;
        if (client == NULL)
        {
            if (wc->flags & WKRC_NORMAL_AFTER)
            {
                wc->flags |= WKRC_NORMAL_CLIENTS;
                wc->flags &= ~WKRC_NORMAL_AFTER;
                wc->prevp = &worker->clients;
                client = *wc->prevp;
                // DEBUG1("%p, switched to checking normal clients", worker);
                continue;
            }
            break;
        }
        if (client->worker != worker) abort();
        if (fast_client || client->schedule_ms < wc->sched_ms)
        {
            wc->max_run--;
            wc->time_recheck--;
            break;
        }
        client = worker_next_client (wc);
    }
    return client;
}


void *worker (void *arg)
{
    worker_t *worker = arg;
    long prev_count = -1;

    thread_rwlock_rlock (&global.workers_rw);
    worker->running = 1;

    worker_client_t wc = WKR_CLIENT_INIT (worker);
    while (1)
    {
        client_t *client;

        wc.time_recheck = 0;
        wc.max_run = 1000;

        thread_mutex_lock (&worker->lock);
        while ((client = worker_pick_client (&wc)))
        {
            thread_mutex_unlock (&worker->lock);

            client_t *nxc = client->next_on_worker;
            errno = 0;

            client->schedule_ms = worker->time_ms;
            int ret = client->ops->process (client);
            // DEBUG3 ("%p processed client %p, ret %d", worker, client, ret);
            if (ret < 0)
            {   // we call the client shutdown
                client->worker = NULL;
                if (client->ops->release)
                    client->ops->release (client);
                // at this point, client is unreliable
            }
            thread_mutex_lock (&worker->lock);
            if (ret)
            {
                worker_removed_client (&wc, nxc);
                continue;
            }
            worker_next_client (&wc);
        }
        if (prev_count != worker->count)
        {
            prev_count = worker->count;
            thread_mutex_unlock (&worker->lock);
            DEBUG2 ("%p now has %ld clients", worker, prev_count);
            thread_mutex_lock (&worker->lock);
        }
        if (worker->running == 0)
        {
            DEBUG3 ("%p count %d, pending %d", worker, worker->count, worker->pending_count);
            if (worker->count == 0 && worker->pending_count == 0)
                break;
        }
        worker_wait (&wc);
    }
    thread_mutex_unlock (&worker->lock);
    worker_relocate_clients (&wc);
    INFO0 ("shutting down");
    thread_rwlock_unlock (&global.workers_rw);
    return NULL;
}


// We pick a worker (consequetive) and set a max number of clients to move if needed
void worker_balance_trigger (time_t now)
{
    thread_rwlock_wlock (&workers_lock);
    if (worker_count > 1)
    {
        int log_counts = (now & 15) == 0 ? 1 : 0;

        worker_least_used = find_least_busy_handler (log_counts);
        if (worker_balance_to_check)
        {
            worker_t *w = worker_balance_to_check;
            // DEBUG2 ("Worker allocations reset on %p, least is %p", w, worker_least_used);
            thread_mutex_lock (&w->lock);
            w->move_allocations = 200;
            worker_balance_to_check = w->next;
            thread_mutex_unlock (&w->lock);
        }
        if (worker_balance_to_check == NULL)
            worker_balance_to_check = workers;
    }
    thread_rwlock_unlock (&workers_lock);
}


static void worker_start (void)
{
    worker_t *handler = calloc (1, sizeof(worker_t));

    worker_control_create (&handler->wakeup_fd[0]);

    handler->pending_tailp = &handler->pending_clients;
    thread_mutex_create (&handler->lock);
    handler->last_p = &handler->clients;
    handler->fast_tailp = &handler->fast_clients;

    thread_rwlock_wlock (&workers_lock);
    if (worker_incoming == NULL)
    {
        worker_incoming = handler;
        handler->move_allocations = 1000000;    // should stay fixed for this one
        handler->thread = thread_create ("worker", worker, handler, THREAD_ATTACHED);
        thread_rwlock_unlock (&workers_lock);
        INFO1 ("starting incoming worker thread %p", worker_incoming);
        worker_start();  // single level recursion, just get a special worker thread set up
        return;
    }
    handler->next = workers;
    workers = handler;
    worker_count++;
    worker_least_used = worker_balance_to_check = workers;
    thread_rwlock_unlock (&workers_lock);

    handler->thread = thread_create ("worker", worker, handler, THREAD_ATTACHED);
}


static void worker_stop (void)
{
    worker_t *handler;

    thread_rwlock_wlock (&workers_lock);
    do
    {
        if (worker_count > 0)
        {
            handler = workers;
            workers = handler->next;
            worker_least_used = worker_balance_to_check = workers;
            if (workers)
            {
                thread_mutex_lock (&workers->lock);
                workers->move_allocations = 100000;
                thread_mutex_unlock (&workers->lock);
            }
            worker_count--;
        }
        else
        {
            handler = worker_incoming;
            worker_incoming = NULL;
            INFO0 ("stopping incoming worker thread");
        }

        if (handler)
        {
            thread_rwlock_unlock (&workers_lock);
            thread_mutex_lock (&handler->lock);
            handler->running = 0;
            thread_mutex_unlock (&handler->lock);

            worker_wakeup (handler);

            thread_join (handler->thread);
            thread_mutex_destroy (&handler->lock);

            sock_close (handler->wakeup_fd[1]);
            sock_close (handler->wakeup_fd[0]);
            free (handler);

            thread_rwlock_wlock (&workers_lock);
            if (workers) break;         // break out unless no more normal workers
        }
    } while (worker_incoming);
    thread_rwlock_unlock (&workers_lock);
}


void workers_adjust (int new_count)
{
    INFO1 ("requested worker count %d", new_count);
    while (worker_count != new_count)
    {
        if (worker_count < new_count)
            worker_start ();
        else if (worker_count > new_count)
            worker_stop ();
    }
}


void worker_wakeup (worker_t *worker)
{
    pipe_write (worker->wakeup_fd[1], "W", 1);
}


void logger_commits (int id)
{
    pipe_write (logger_fd[1], "L", 1);
}

static void *log_commit_thread (void *arg)
{
    INFO0 ("started");
    thread_rwlock_rlock (&global.workers_rw);
    while (1)
    {
        int ret = util_timed_wait_for_fd (logger_fd[0], 5000);
        if (ret == 0)
        {
            global_lock();
            int loop = (global.running == ICE_RUNNING);
            global_unlock();
            if (loop) continue;
        }
        if (ret > 0)
        {
            char cm[80];
            ret = pipe_read (logger_fd[0], cm, sizeof cm);
            if (ret > 0)
            {
                // fprintf (stderr, "logger woken with %d\n", ret);
                log_commit_entries ();
                continue;
            }
        }
        int err = 0;
        if (ret < 0 && sock_recoverable ((err = sock_error())) && global.running == ICE_RUNNING)
            continue;
        sock_close (logger_fd[0]);
        thread_rwlock_rlock (&workers_lock);
        if (worker_count)
        {
            thread_rwlock_unlock (&workers_lock);
            worker_control_create (logger_fd);
            if (err) ERROR1 ("logger received code %d", err);
            continue;
        }
        thread_rwlock_unlock (&workers_lock);
        log_commit_entries ();
        // fprintf (stderr, "logger closed with zero workers\n");
        break;
    }
    thread_rwlock_unlock (&global.workers_rw);
    return NULL;
}


void worker_logger_init (void)
{
    worker_control_create (logger_fd);
    log_set_commit_callback (logger_commits);
}

void worker_logger (int stop)
{
    if (stop)
    {
        logger_commits(0);
        sock_close (logger_fd[1]);
        logger_fd[1] = -1;
        return;
    }
    thread_create ("Log Thread", log_commit_thread, NULL, THREAD_DETACHED);
}

