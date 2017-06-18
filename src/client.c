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
 * Copyright 2000-2014, Karl Heyes <karl@kheyes.plus.com>
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

FD_t logger_fd[2];

static void logger_commits (int id);


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

    sock_set_cork (client->connection.sock, 0); // ensure any corked data is actually sent.

    global_lock ();
    if (global.running != ICE_RUNNING || client->connection.error ||
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
    DEBUG0 ("keepalive detected, placing back onto worker");
    sock_set_cork (client->connection.sock, 1);    // reenable cork for the next go around
    client->counter = client->schedule_ms = timing_get_time();
    client->connection.con_time = client->schedule_ms/1000;
    client->connection.discon.time = client->connection.con_time + 7;
    client->ops = &http_request_ops;
    client->flags = CLIENT_ACTIVE;
    client->shared_data = NULL;
    client->refbuf = NULL;
    client->pos = 0;
    client->intro_offset = client->connection.sent_bytes = 0;
    client_add_worker (client);
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
    int len;
    char body [4096];

    client_set_queue (client, NULL);
    client->refbuf = refbuf_new (PER_CLIENT_REFBUF_SIZE);
    len = snprintf (body, sizeof body, "Moved <a href=\"%s\">here</a>\r\n", location);
    len = snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
            "HTTP/1.0 302 Temporarily Moved\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %d\r\n"
            "Location: %s\r\n\r\n%s",
            len, location, body);
    client->respcode = 302;
    client->flags &= ~CLIENT_KEEPALIVE;
    client->refbuf->len = len;
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
    client->flags &= ~CLIENT_KEEPALIVE;
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
    client->flags &= ~CLIENT_KEEPALIVE;
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
    client->flags &= ~CLIENT_KEEPALIVE;
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
        if (client->parser->req_type == httpp_req_head || message == NULL)
            message = "Not Available";
        ret = strlen (message);
        client->refbuf = refbuf_new (PER_CLIENT_REFBUF_SIZE);
        snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
                "HTTP/1.0 404 Not Available\r\n"
                "%s\r\nContent-Length: %d\r\nContent-Type: text/html\r\n\r\n"
                "%s", client_keepalive_header (client), ret,
                message ? message: "");
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
            "Connection: Keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Headers: Origin, Accept, X-Requested-With, Content-Type\r\n"
            "Access-Control-Allow-Methods: GET, OPTIONS, HEAD, STATS\r\n\r\n");
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


static int client_send_buffer (client_t *client)
{
    const char *buf = client->refbuf->data + client->pos;
    int len = client->refbuf->len - client->pos;
    int ret = client_send_bytes (client, buf, len);

    if (ret > 0)
        client->pos += ret;
    if (client->connection.error == 0 && client->pos >= client->refbuf->len)
    {
        int (*callback)(client_t *) = client->format_data;
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
    client->format_data = callback;
    client->ops = &client_buffer_ops;
    return 0;
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
        if (tm - worker->time_ms > 1000 && worker->time_ms)
            WARN2 ("worker %p has been stuck for %lu ms", worker, (unsigned long)(tm - worker->time_ms));
        if (worker->wakeup_ms > tm)
            duration = (int)(worker->wakeup_ms - tm);
        if (duration > 60000) /* make duration at most 60s */
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
            worker_control_create (&worker->wakeup_fd[0]);
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
    uint64_t c = 0;

    worker->running = 1;
    worker->wakeup_ms = (int64_t)0;
    worker->time_ms = timing_get_time();

    while (1)
    {
        client_t *client = *prevp;
        uint64_t sched_ms = worker->time_ms + 12;

        c = 0;
        while (client)
        {
            if (client->worker != worker) abort();
            /* process client details but skip those that are not ready yet */
            if (client->flags & CLIENT_ACTIVE)
            {
                int ret = 0;
                client_t *nx = client->next_on_worker;

                int process = (worker->running == 0 || client->schedule_ms <= sched_ms) ? 1 : 0;
                if (process)
                {
                    if (c > 300 && c & 1)  // only process alternate clients after so many
                       process = 0;
                }
                else if (client->wakeup && *client->wakeup)
                {
                    if (c & 1)
                        process = 1; // enable this one to pass through
                    else
                        client->schedule_ms = worker->time_ms;
                }

                if (process)
                {
                    c++;
                    if ((c & 31) == 0)
                    {
                        // update these after so many to keep in sync
                        worker->time_ms = timing_get_time();
                        worker->current_time.tv_sec = (time_t)(worker->time_ms/1000);
                    }
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

    worker_control_create (&handler->wakeup_fd[0]);

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
    if (worker_count == 0)
    {
        logger_commits(0);
        sock_close (logger_fd[1]);
        sock_close (logger_fd[0]);
    }
}


void worker_wakeup (worker_t *worker)
{
    pipe_write (worker->wakeup_fd[1], "W", 1);
}


static void logger_commits (int id)
{
    pipe_write (logger_fd[1], "L", 1);
}

static void *log_commit_thread (void *arg)
{
   INFO0 ("started");
   while (1)
   {
       int ret = util_timed_wait_for_fd (logger_fd[0], 5000);
       if (ret == 0) continue;
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
       if (ret < 0 && sock_recoverable (sock_error()))
           continue;
       int err = sock_error();
       sock_close (logger_fd[0]);
       sock_close (logger_fd[1]);
       if (worker_count)
       {
           worker_control_create (logger_fd);
           ERROR1 ("logger received code %d", err);
           continue;
       }
       // fprintf (stderr, "logger closed with zero workers\n");
       break;
   }
   return NULL;
}


void worker_logger_init (void)
{
    worker_control_create (logger_fd);
    log_set_commit_callback (logger_commits);
}

void worker_logger (void)
{
    thread_create ("Log Thread", log_commit_thread, NULL, THREAD_DETACHED);
}

