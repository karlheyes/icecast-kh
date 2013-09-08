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

int worker_count, worker_min_count;
worker_t *worker_balance_to_check, *worker_least_used;


void client_register (client_t *client)
{
    if (client)
        global.clients++;
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
        DEBUG1 ("client still in auth \"%s\"", httpp_getvar (client->parser, HTTPP_VAR_URI));

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

    connection_close (&client->connection);
    if (client->parser)
        httpp_destroy (client->parser);

    global_lock ();
    global.clients--;
    stats_event_args (NULL, "clients", "%d", global.clients);
    config_clear_listener (client->server_conn);
    global_unlock ();

    /* we need to free client specific format data (if any) */
    if (client->free_client_data)
        client->free_client_data (client);

    free(client->username);
    free(client->password);

    free(client);
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

    if (bytes == -1 && client->connection.error)
        DEBUG0 ("reading from connection has failed");

    return bytes;
}


int client_send_302(client_t *client, const char *location)
{
    client_set_queue (client, NULL);
    client->refbuf = refbuf_new (PER_CLIENT_REFBUF_SIZE);
    snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
            "HTTP/1.0 302 Temporarily Moved\r\n"
            "Content-Type: text/html\r\n"
            "Location: %s\r\n\r\n"
            "Moved <a href=\"%s\">here</a>\r\n", location, location);
    client->respcode = 302;
    client->refbuf->len = strlen (client->refbuf->data);
    return fserve_setup_client (client);
}


int client_send_400(client_t *client, const char *message)
{
    client_set_queue (client, NULL);
    client->refbuf = refbuf_new (PER_CLIENT_REFBUF_SIZE);
    snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
            "HTTP/1.0 400 Bad Request\r\n"
            "Content-Type: text/html\r\n\r\n"
            "<b>%s</b>\r\n", message?message:"");
    client->respcode = 400;
    client->refbuf->len = strlen (client->refbuf->data);
    return fserve_setup_client (client);
}


int client_send_401 (client_t *client, const char *realm)
{
    ice_config_t *config = config_get_config ();

    if (realm == NULL)
        realm = config->server_id;

    client_set_queue (client, NULL);
    client->refbuf = refbuf_new (500);
    snprintf (client->refbuf->data, 500,
            "HTTP/1.0 401 Authentication Required\r\n"
            "WWW-Authenticate: Basic realm=\"%s\"\r\n"
            "\r\n"
            "You need to authenticate\r\n", realm);
    config_release_config();
    client->respcode = 401;
    client->refbuf->len = strlen (client->refbuf->data);
    return fserve_setup_client (client);
}


int client_send_403(client_t *client, const char *reason)
{
    if (reason == NULL)
        reason = "Forbidden";
    client_set_queue (client, NULL);
    client->refbuf = refbuf_new (PER_CLIENT_REFBUF_SIZE);
    snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
            "HTTP/1.0 403 %s\r\n"
            "Content-Type: text/html\r\n\r\n", reason);
    client->respcode = 403;
    client->refbuf->len = strlen (client->refbuf->data);
    return fserve_setup_client (client);
}


int client_send_403redirect (client_t *client, const char *mount, const char *reason)
{
    if (redirect_client (mount, client))
        return 0;
    return client_send_403 (client, reason);
}


int client_send_404 (client_t *client, const char *message)
{
    int ret = -1;

    if (client->worker == NULL)   /* client is not on any worker now */
    {
        client_destroy (client);
        return 0;
    }
    client_set_queue (client, NULL);
    if (client->respcode)
    {
        worker_t *worker = client->worker;
        if (client->respcode >= 300)
            client->flags = client->flags & ~CLIENT_AUTHENTICATED;
        client->flags |= CLIENT_ACTIVE;
        worker_wakeup (worker);
    }
    else
    {
        if (message == NULL)
            message = "Not Available";
        client->refbuf = refbuf_new (PER_CLIENT_REFBUF_SIZE);
        snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
                "HTTP/1.0 404 Not Available\r\n"
                "Content-Type: text/html\r\n\r\n"
                "<b>%s</b>\r\n", message);
        client->respcode = 404;
        client->refbuf->len = strlen (client->refbuf->data);
        ret = fserve_setup_client (client);
    }
    return ret;
}


int client_send_416(client_t *client)
{
    client_set_queue (client, NULL);
    client->refbuf = refbuf_new (PER_CLIENT_REFBUF_SIZE);
    snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
            "HTTP/1.0 416 Request Range Not Satisfiable\r\n\r\n");
    client->respcode = 416;
    client->refbuf->len = strlen (client->refbuf->data);
    return fserve_setup_client (client);
}


int client_send_501(client_t *client)
{
    client_set_queue (client, NULL);
    client->refbuf = refbuf_new (PER_CLIENT_REFBUF_SIZE);
    snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
            "HTTP/1.0 501 Not Implemented\r\n\r\n");
    client->respcode = 501;
    client->refbuf->len = strlen (client->refbuf->data);
    return fserve_setup_client (client);
}

int client_send_options(client_t *client)
{
    client_set_queue (client, NULL);
    client->refbuf = refbuf_new (PER_CLIENT_REFBUF_SIZE);
    snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
            "HTTP/1.1 200 OK\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Headers: Origin, Accept Content-Type, X-Requested-With, Content-Type\r\n"
            "Access-Control-Allow-Methods: GET, OPTIONS, STATS\r\n\r\n");
    client->respcode = 200;
    client->refbuf->len = strlen (client->refbuf->data);
    return fserve_setup_client (client);
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

    if (client->connection.error)
        DEBUG0 ("Client connection died");

    return ret;
}

void client_set_queue (client_t *client, refbuf_t *refbuf)
{
    refbuf_t *to_release = client->refbuf;

    if (to_release && client->flags & CLIENT_HAS_INTRO_CONTENT)
    {
        refbuf_t *intro = to_release->next;
        while (intro && (intro->flags & REFBUF_SHARED) == 0)
        {
            refbuf_t *r = intro->next;
            intro->next = NULL;
            refbuf_release (intro);
            intro = r;
        }
        if (intro) // leave shared data, someone else should be freeing it
            ERROR1 ("intro content has a shared flag status for %s", client->connection.ip);
        to_release->next = NULL;
    }
    client->flags &= ~CLIENT_HAS_INTRO_CONTENT;
    client->refbuf = refbuf;
    if (refbuf)
        refbuf_addref (client->refbuf);

    client->pos = 0;
    if (to_release && (to_release->flags & REFBUF_SHARED) == 0)
        refbuf_release (to_release);
}


static worker_t *find_least_busy_handler (int log)
{
    worker_t *min = workers;

    if (workers && workers->next)
    {
        worker_t *handler = workers->next;

        worker_min_count = min->count + min->pending_count;
        if (log) DEBUG2 ("handler %p has %d clients", min, worker_min_count);
        while (handler)
        {
            int cur_count = handler->count + handler->pending_count;
            if (log) DEBUG2 ("handler %p has %d clients", handler, cur_count);
            if (cur_count < worker_min_count)
            {
                min = handler;
                worker_min_count = cur_count;
            }
            handler = handler->next;
        }
    }
    return min;
}


worker_t *worker_selected (void)
{
    if ((worker_least_used->count + worker_least_used->pending_count) - worker_min_count > 20)
        worker_least_used = find_least_busy_handler(1);
    return worker_least_used;
}


/* worker mutex should be already locked */
static void worker_add_client (worker_t *worker, client_t *client)
{
    ++worker->pending_count;
    client->next_on_worker = NULL;
    *worker->pending_clients_tail = client;
    worker->pending_clients_tail = &client->next_on_worker;
    client->worker = worker;
}


int client_change_worker (client_t *client, worker_t *dest_worker)
{
    if (dest_worker->running == 0)
        return 0;
    client->next_on_worker = NULL;

    thread_spin_lock (&dest_worker->lock);
    worker_add_client (dest_worker, client);
    thread_spin_unlock (&dest_worker->lock);
    worker_wakeup (dest_worker);

    return 1;
}


void client_add_worker (client_t *client)
{
    worker_t *handler;

    thread_rwlock_rlock (&workers_lock);
    /* add client to the handler with the least number of clients */
    handler = worker_selected();
    thread_spin_lock (&handler->lock);
    thread_rwlock_unlock (&workers_lock);

    worker_add_client (handler, client);
    thread_spin_unlock (&handler->lock);
    worker_wakeup (handler);
}


#ifdef _WIN32
#define pipe_create         sock_create_pipe_emulation
#define pipe_write(A, B, C) send(A, B, C, 0)
#define pipe_read(A,B,C)    recv(A, B, C, 0)
#else
#define pipe_create pipe
#define pipe_write write
#define pipe_read read
#endif


static void worker_control_create (worker_t *worker)
{
    if (pipe_create (&worker->wakeup_fd[0]) < 0)
    {
        ERROR0 ("pipe failed, descriptor limit?");
        abort();
    }
    sock_set_blocking (worker->wakeup_fd[0], 0);
    sock_set_blocking (worker->wakeup_fd[1], 0);
}


static client_t **worker_add_pending_clients (worker_t *worker)
{
    if (worker->pending_clients)
    {
        unsigned count;
        client_t **p;

        thread_spin_lock (&worker->lock);
        p = worker->last_p;
        *worker->last_p = worker->pending_clients;
        worker->last_p = worker->pending_clients_tail;
        worker->count += worker->pending_count;
        count = worker->pending_count;
        worker->pending_clients = NULL;
        worker->pending_clients_tail = &worker->pending_clients;
        worker->pending_count = 0;
        thread_spin_unlock (&worker->lock);
        DEBUG2 ("Added %d pending clients to %p", count, worker);
        if (worker->wakeup_ms > worker->time_ms+5)
            return p;  /* only these new ones scheduled so process from here */
    }
    worker->wakeup_ms = worker->time_ms + 60000;
    return &worker->clients;
}


static client_t **worker_wait (worker_t *worker)
{
    int ret, duration = 2;

    if (global.running == ICE_RUNNING)
    {
        uint64_t tm = timing_get_time();
        if (worker->wakeup_ms > tm)
            duration = (int)(worker->wakeup_ms - tm);
        if (duration > 60000) /* make duration between 2ms and 60s */
            duration = 60000;
    }

    ret = util_timed_wait_for_fd (worker->wakeup_fd[0], duration);
    if (ret > 0) /* may of been several wakeup attempts */
    {
        char ca[100];
        do
        {
            ret = pipe_read (worker->wakeup_fd[0], ca, sizeof ca);
            if (ret > 0)
                break;
            if (ret < 0 && sock_recoverable (sock_error()))
                break;
            sock_close (worker->wakeup_fd[1]);
            sock_close (worker->wakeup_fd[0]);
            worker_control_create (worker);
            worker_wakeup (worker);
            WARN0 ("Had to recreate worker control feed");
        } while (1);
    }

    worker->time_ms = timing_get_time();
    worker->current_time.tv_sec = (time_t)(worker->time_ms/1000);

    return worker_add_pending_clients (worker);
}


static void worker_relocate_clients (worker_t *worker)
{
    if (workers == NULL)
        return;
    while (worker->count || worker->pending_count)
    {
        client_t *client = worker->clients, **prevp = &worker->clients;

        worker->wakeup_ms = worker->time_ms + 150;
        while (client)
        {
            if (client->flags & CLIENT_ACTIVE)
            {
                client->worker = workers;
                prevp = &client->next_on_worker;
            }
            else
            {
                *prevp = client->next_on_worker;
                worker_add_client (worker, client);
                worker->count--;
            }
            client = *prevp;
        }
        if (worker->clients)
        {
            thread_spin_lock (&workers->lock);
            *workers->pending_clients_tail = worker->clients;
            workers->pending_clients_tail = prevp;
            workers->pending_count += worker->count;
            thread_spin_unlock (&workers->lock);
            worker_wakeup (workers);
            worker->clients = NULL;
            worker->last_p = &worker->clients;
            worker->count = 0;
        }
        worker_wait (worker);
    }
}

void *worker (void *arg)
{
    worker_t *worker = arg;
    long prev_count = -1;
    client_t **prevp = &worker->clients;

    worker->running = 1;
    worker->wakeup_ms = (int64_t)0;
    worker->time_ms = timing_get_time();

    while (1)
    {
        client_t *client = *prevp;
        uint64_t sched_ms = worker->time_ms + 2;

        while (client)
        {
            if (client->worker != worker) abort();
            /* process client details but skip those that are not ready yet */
            if (client->flags & CLIENT_ACTIVE)
            {
                int ret = 0;
                client_t *nx = client->next_on_worker;

                if (worker->running == 0 || client->schedule_ms <= sched_ms)
                {
                    ret = client->ops->process (client);
                    if (ret < 0)
                    {
                        client->worker = NULL;
                        if (client->ops->release)
                            client->ops->release (client);
                    }
                    if (ret)
                    {
                        worker->count--;
                        if (nx == NULL) /* is this the last client */
                            worker->last_p = prevp;
                        client = *prevp = nx;
                        continue;
                    }
                }
                if ((client->flags & CLIENT_ACTIVE) && client->schedule_ms < worker->wakeup_ms)
                    worker->wakeup_ms = client->schedule_ms;
            }
            prevp = &client->next_on_worker;
            client = *prevp;
        }
        if (prev_count != worker->count)
        {
            DEBUG2 ("%p now has %d clients", worker, worker->count);
            prev_count = worker->count;
        }
        if (worker->running == 0)
        {
            if (global.running == ICE_RUNNING)
                break;
            if (worker->count == 0 && worker->pending_count == 0)
                break;
        }
        prevp = worker_wait (worker);
    }
    worker_relocate_clients (worker);
    INFO0 ("shutting down");
    return NULL;
}


// We pick a worker (consequetive) and set a max number of clients to move if needed
void worker_balance_trigger (time_t now)
{
    int log_counts = (now % 10) == 0 ? 1 : 0;

    if (worker_count == 1)
        return; // no balance required, leave quickly
    thread_rwlock_rlock (&workers_lock);

    // lets only search for this once a second, not many times
    worker_least_used = find_least_busy_handler (log_counts);
    if (worker_balance_to_check)
    {
        worker_balance_to_check->move_allocations = 50;
        worker_balance_to_check = worker_balance_to_check->next;
    }
    if (worker_balance_to_check == NULL)
        worker_balance_to_check = workers;

    thread_rwlock_unlock (&workers_lock);
}


static void worker_start (void)
{
    worker_t *handler = calloc (1, sizeof(worker_t));

    worker_control_create (handler);

    handler->pending_clients_tail = &handler->pending_clients;
    thread_spin_create (&handler->lock);
    thread_rwlock_wlock (&workers_lock);
    handler->last_p = &handler->clients;
    handler->next = workers;
    workers = handler;
    worker_count++;
    worker_least_used = worker_balance_to_check = workers;
    handler->thread = thread_create ("worker", worker, handler, THREAD_ATTACHED);
    thread_rwlock_unlock (&workers_lock);
}


static void worker_stop (void)
{
    worker_t *handler;

    if (workers == NULL)
        return;
    thread_rwlock_wlock (&workers_lock);
    handler = workers;
    workers = handler->next;
    worker_least_used = worker_balance_to_check = workers;
    if (workers)
        workers->move_allocations = 100;
    worker_count--;
    thread_rwlock_unlock (&workers_lock);

    handler->running = 0;
    worker_wakeup (handler);

    thread_join (handler->thread);
    thread_spin_destroy (&handler->lock);

    sock_close (handler->wakeup_fd[1]);
    sock_close (handler->wakeup_fd[0]);
    free (handler);
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
