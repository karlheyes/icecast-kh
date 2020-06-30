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

/* -*- c-basic-offset: 4; indent-tabs-mode: nil; -*- */
/* slave.c
 * by Ciaran Anscomb <ciaran.anscomb@6809.org.uk>
 *
 * Periodically requests a list of streams from a master server
 * and creates source threads for any it doesn't already have.
 * */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_CURL
#include <curl/curl.h>
#endif
#ifdef HAVE_GETRLIMIT
#include <sys/resource.h>
#endif

#include "compat.h"

#include "timing/timing.h"
#include "thread/thread.h"
#include "avl/avl.h"
#include "net/sock.h"
#include "httpp/httpp.h"

#include "cfgfile.h"
#include "global.h"
#include "util.h"
#include "connection.h"
#include "refbuf.h"
#include "client.h"
#include "stats.h"
#include "logging.h"
#include "source.h"
#include "format.h"
#include "event.h"
#include "yp.h"
#include "slave.h"

#define CATMODULE "slave"

#ifdef HAVE_CURL
struct master_conn_details
{
    char *server;
    int port;
    int ssl_port;
    int send_auth;
    int on_demand;
    int previous;
    int ok;
    int max_interval;
    int run_on;
    time_t synctime;
    char *buffer;
    char *username;
    char *password;
    char *bind;
    char *server_id;
    char *args;
};
#endif


static void _slave_thread(void);
static void redirector_add (const char *server, int port, int interval);
static redirect_host *find_slave_host (const char *server, int port);
static int  relay_startup (client_t *client);
static int  relay_initialise (client_t *client);
static int  relay_read (client_t *client);
static void relay_release (client_t *client);

int slave_running = 0;
extern int worker_count;
int relays_connecting;
int streamlister;
time_t relay_barrier_master;
time_t relay_barrier_xml;

static volatile int update_settings = 0;
static volatile int update_all_sources = 0;
static volatile int restart_connection_thread = 0;
static time_t streamlist_check = 0;
static rwlock_t slaves_lock;
static spin_t relay_start_lock;
static time_t inactivity_timer;
static int inactivity_timeout;

redirect_host *redirectors;
worker_t *workers;
rwlock_t workers_lock;


struct _client_functions relay_client_ops =
{
    relay_read,
    relay_release
};

struct _client_functions relay_startup_ops =
{
    relay_startup,
    relay_release
};

struct _client_functions relay_init_ops =
{
    relay_initialise,
    relay_release
};


relay_server *relay_copy (relay_server *r)
{
    relay_server *copy = calloc (1, sizeof (relay_server));

    if (copy)
    {
        relay_server_host *from = r->hosts, **insert = &copy->hosts;

        while (from)
        {
            relay_server_host *to = calloc (1, sizeof (relay_server_host));
            to->ip = (char *)xmlCharStrdup (from->ip);
            to->mount = (char *)xmlCharStrdup (from->mount);
            if (from->bind)
                to->bind = (char *)xmlCharStrdup (from->bind);
            to->port = from->port;
            to->timeout = from->timeout;
            *insert = to;
            from = from->next;
            insert = &to->next;
        }

        copy->localmount = (char *)xmlStrdup (XMLSTR(r->localmount));
        if (r->username)
            copy->username = (char *)xmlStrdup (XMLSTR(r->username));
        if (r->password)
            copy->password = (char *)xmlStrdup (XMLSTR(r->password));
        copy->flags = r->flags;
        copy->flags |= RELAY_RUNNING;
        copy->interval = r->interval;
        copy->run_on = r->run_on;
        r->source = NULL;
        DEBUG2 ("copy relay %s at %p", copy->localmount, copy);
    }
    return copy;
}


/* force a recheck of the mounts.
 */
void slave_update_mounts (void)
{
    thread_spin_lock (&relay_start_lock);
    update_settings = 1;
    thread_spin_unlock (&relay_start_lock);
}

/* force a recheck of the mounts.
 */
void slave_update_all_mounts (void)
{
    thread_spin_lock (&relay_start_lock);
    update_settings = 1;
    update_all_sources = 1;
    thread_spin_unlock (&relay_start_lock);
}


/* called on reload, so drop all redirection and trigger source checkup and
 * rebuild all stat mountpoints
 */
void slave_restart (void)
{
    thread_spin_lock (&relay_start_lock);
    restart_connection_thread = 1;
    update_settings = 1;
    update_all_sources = 1;
    streamlist_check = 0;
    thread_spin_unlock (&relay_start_lock);
}


static int _compare_relay(void *arg, void *a, void *b)
{
    relay_server *nodea = (relay_server *)a;
    relay_server *nodeb = (relay_server *)b;

    return strcmp(nodea->localmount, nodeb->localmount);
}


void slave_initialize(void)
{
    if (slave_running)
        return;

    thread_rwlock_create (&slaves_lock);
    slave_running = 1;
    streamlister = 0;
    streamlist_check = 0;
    update_settings = 0;
    update_all_sources = 0;
    restart_connection_thread = 0;
    redirectors = NULL;
    workers = NULL;
    worker_count = 0;
    relays_connecting = 0;
    thread_spin_create (&relay_start_lock);
    thread_rwlock_create (&workers_lock);
    global.relays = avl_tree_new (_compare_relay, NULL);
    inactivity_timeout = 0;
    inactivity_timer = 0;
#ifndef HAVE_CURL
    ERROR0 ("streamlist request disabled, rebuild with libcurl if required");
#endif
    _slave_thread ();
    yp_stop ();
    workers_adjust(0);
}


void slave_shutdown(void)
{
    if (slave_running == 0)
        return;
    DEBUG0 ("shutting down slave");
    yp_shutdown();
    stats_shutdown();
    fserve_shutdown();
    config_shutdown();
    stop_logging();
    // stall until workers have shut down
    thread_rwlock_wlock (&global.workers_rw);
    thread_rwlock_unlock (&global.workers_rw);

    //INFO0 ("all workers shut down");
    avl_tree_free (global.relays, NULL);
    thread_rwlock_destroy (&slaves_lock);
    thread_rwlock_destroy (&workers_lock);
    thread_spin_destroy (&relay_start_lock);
    slave_running = 0;
}


int redirect_client (const char *mountpoint, client_t *client)
{
    int ret = 0, which;
    redirect_host *checking, **trail;

    thread_rwlock_rlock (&slaves_lock);
    /* select slave entry */
    if (global.redirect_count == 0)
    {
        thread_rwlock_unlock (&slaves_lock);
        return 0;
    }
    which=(int) (((float)global.redirect_count)*rand()/(RAND_MAX+1.0)) + 1;
    checking = redirectors;
    trail = &redirectors;

    DEBUG2 ("random selection %d (out of %d)", which, global.redirect_count);
    while (checking)
    {
        DEBUG2 ("...%s:%d", checking->server, checking->port);
        if (checking->next_update && checking->next_update+10 < time(NULL))
        {
            /* no streamist request, expire slave for now */
            *trail = checking->next;
            global.redirect_count--;
            /* free slave details */
            INFO2 ("dropping redirector for %s:%d", checking->server, checking->port);
            free (checking->server);
            free (checking);
            checking = *trail;
            if (which > 0)
                which--; /* we are 1 less now */
            continue;
        }
        if (--which == 0)
        {
            char *location;
            /* add enough for "http://" the port ':' and nul */
            int len = strlen (mountpoint) + strlen (checking->server) + 20;
            const char *user = client->username;
            const char *pass = client->password;
            const char *args = httpp_getvar (client->parser, HTTPP_VAR_QUERYARGS);
            const char *colon = ":", *at_sign = "@";

            if (args)
                len += strlen (args);
            else
                args = "";
            if (user && pass)
                len += strlen (user) + strlen (pass);
            else
                colon = at_sign = user = pass = "";
            INFO2 ("redirecting listener to slave server at %s:%d", checking->server, checking->port);
            location = alloca (len);
            snprintf (location, len, "%s://%s%s%s%s%s:%d%s%s", httpp_getvar (client->parser, HTTPP_VAR_PROTOCOL),
                    user, colon, pass, at_sign,
                    checking->server, checking->port, mountpoint, args);
            client_send_302 (client, location);
            ret = 1;
        }
        trail = &checking->next;
        checking = checking->next;
    }
    thread_rwlock_unlock (&slaves_lock);
    return ret;
}



static http_parser_t *get_relay_response (connection_t *con, const char *mount,
        const char *server, const char *headers)
{
    ice_config_t *config = config_get_config ();
    char *server_id = strdup (config->server_id);
    http_parser_t *parser = NULL;
    char response [4096];

    config_release_config ();

    /* At this point we may not know if we are relaying an mp3 or vorbis
     * stream, but only send the icy-metadata header if the relay details
     * state so (the typical case).  It's harmless in the vorbis case. If
     * we don't send in this header then relay will not have mp3 metadata.
     */
    sock_write (con->sock, "GET %s HTTP/1.0\r\n"
            "User-Agent: %s\r\n"
            "Host: %s\r\n"
            "%s"
            "\r\n",
            mount,
            server_id,
            server,
            headers ? headers : "");

    free (server_id);
    memset (response, 0, sizeof(response));
    if (util_read_header (con->sock, response, 4096, READ_ENTIRE_HEADER) == 0)
    {
        WARN2 ("Header read failure from %s %s", server, mount);
        return NULL;
    }
    parser = httpp_create_parser();
    httpp_initialize (parser, NULL);
    if (! httpp_parse_response (parser, response, strlen(response), mount))
    {
        INFO0 ("problem parsing response from relay");
        httpp_destroy (parser);
        return NULL;
    }
    return parser;
}



static void encode_auth_header (char *userpass, unsigned int remain)
{
    if (userpass && userpass[0])
    {
        char *esc_authorisation = util_base64_encode (userpass);

        if (snprintf (userpass, remain, "Authorization: Basic %s\r\n", esc_authorisation) < 0)
            userpass[0] = '\0';
        free (esc_authorisation);
    }
}


/* Actually open the connection and do some http parsing, handle any 302
 * responses within here.
 */
static int open_relay_connection (client_t *client, relay_server *relay, relay_server_host *host)
{
    int redirects = 0;
    http_parser_t *parser = NULL;
    connection_t *con = &client->connection;
    char *server = strdup (host->ip);
    char *mount = strdup (host->mount);
    int port = host->port, timeout = host->timeout, remain;
    char *p, headers[4096] = "";

    remain = sizeof (headers);
    if (relay->flags & RELAY_ICY_META)
        remain -= snprintf (headers, remain, "Icy-MetaData: 1\r\n");
    p = headers + strlen (headers);
    if (relay->username && relay->password)
    {
        INFO2 ("using username %s for %s", relay->username, relay->localmount);
        snprintf (p, remain, "%s:%s", relay->username, relay->password);
        encode_auth_header (p, remain);
    }
    while (1)
    {
        sock_t streamsock;
        char *bind = NULL;

        if (redirects > 10)
        {
            WARN1 ("detected too many redirects on %s", relay->localmount);
            break;
        }
        /* policy decision, we assume a source bind even after redirect, possible option */
        if (host->bind)
            bind = strdup (host->bind);

        if (bind)
            INFO4 ("connecting to %s:%d for %s, bound to %s", server, port, relay->localmount, bind);
        else
            INFO3 ("connecting to %s:%d for %s", server, port, relay->localmount);

        con->con_time = time (NULL);
        relay->in_use = host;
        streamsock = sock_connect_wto_bind (server, port, bind, timeout);
        free (bind);
        if (connection_init (con, streamsock, server) < 0)
        {
            WARN2 ("Failed to connect to %s:%d", server, port);
            break;
        }

        parser = get_relay_response (con, mount, server, headers);

        if (parser == NULL)
        {
            ERROR4 ("Problem trying to start relay on %s (%s:%d%s)", relay->localmount,
                    server, port, mount);
            break;
        }
        if (strcmp (httpp_getvar (parser, HTTPP_VAR_ERROR_CODE), "302") == 0)
        {
            /* better retry the connection again but with different details */
            const char *uri, *mountpoint;
            int len;

            uri = httpp_getvar (parser, "location");
            INFO2 ("redirect received on %s : %s", relay->localmount, uri);
            if (strncmp (uri, "http://", 7) != 0)
                break;
            uri += 7;
            mountpoint = strchr (uri, '/');
            free (mount);
            if (mountpoint)
                mount = strdup (mountpoint);
            else
                mount = strdup ("/");

            len = strcspn (uri, "@/");
            if (uri [len] == '@')
            {
                snprintf (p, remain, "%.*s", len, uri);
                encode_auth_header (p, remain);
                uri += len + 1;
            }
            len = strcspn (uri, ":/");
            port = 80;
            if (uri [len] == ':')
                port = atoi (uri+len+1);
            free (server);
            server = calloc (1, len+1);
            strncpy (server, uri, len);
            connection_close (con);
            httpp_destroy (parser);
            parser = NULL;
        }
        else
        {
            if (httpp_getvar (parser, HTTPP_VAR_ERROR_MESSAGE))
            {
                ERROR3 ("Error from relay request on %s (%s %s)", relay->localmount,
                        host->mount, httpp_getvar(parser, HTTPP_VAR_ERROR_MESSAGE));
                client->parser = NULL;
                break;
            }
            sock_set_blocking (streamsock, 0);
            thread_rwlock_wlock (&relay->source->lock);
            client->parser = parser; // old parser will be free in the format clear
            thread_rwlock_unlock (&relay->source->lock);
            client->connection.discon.time = 0;
            client->connection.con_time = time (NULL);
            client_set_queue (client, NULL);
            free (server);
            free (mount);

            return 0;
        }
        redirects++;
    }
    /* failed, better clean up */
    free (server);
    free (mount);
    if (parser)
        httpp_destroy (parser);
    connection_close (con);
    con->con_time = time (NULL); // sources count needs to drop in such cases
    if (relay->in_use) relay->in_use->skip = 1;
    return -1;
}


/* This does the actual connection for a relay. A thread is
 * started off if a connection can be acquired
 */
int open_relay (relay_server *relay)
{
    source_t *src = relay->source;
    relay_server_host *host = relay->hosts;
    client_t *client = src->client;
    do
    {
        int ret;

        if (host->skip)
        {
            INFO3 ("skipping %s:%d for %s", host->ip, host->port, relay->localmount);
            continue;
        }
        thread_rwlock_unlock (&src->lock);
        ret = open_relay_connection (client, relay, host);
        thread_rwlock_wlock (&src->lock);

        if (ret < 0)
            continue;

        if (source_format_init (src) < 0)
        {
            WARN1 ("Failed to complete initialisation on %s", relay->localmount);
            continue;
        }
        return 1;
    } while ((host = host->next) && global.running == ICE_RUNNING);
    return -1;
}

static void *start_relay_stream (void *arg)
{
    client_t *client = arg;
    relay_server *relay;
    source_t *src;
    int failed = 1, sources;

    global_lock();
    sources = ++global.sources;
    stats_event_args (NULL, "sources", "%d", global.sources);
    global_unlock();
    /* set the start time, because we want to decrease the sources on all failures */
    client->connection.con_time = time (NULL);
    do
    {
        ice_config_t *config = config_get_config();
        mount_proxy *mountinfo;

        relay = client->shared_data;
        src = relay->source;

        thread_rwlock_wlock (&src->lock);
        src->flags |= SOURCE_PAUSE_LISTENERS;
        if (sources > config->source_limit)
        {
            config_release_config();
            WARN1 ("starting relayed mountpoint \"%s\" requires a higher sources limit", relay->localmount);
            break;
        }
        config_release_config();
        INFO1("Starting relayed source at mountpoint \"%s\"", relay->localmount);

        if (open_relay (relay) < 0)
            break;
        stats_event_inc (NULL, "source_relay_connections");
        source_init (src);
        config = config_get_config();
        mountinfo = config_find_mount (config, src->mount);
        source_update_settings (config, src, mountinfo);
        INFO1 ("source %s is ready to start", src->mount);
        config_release_config();
        failed = 0;
    } while (0);

    client->ops = &relay_client_ops;
    client->schedule_ms = timing_get_time();

    if (failed)
    {
        /* failed to start any connection, better clean up and reset */
        if ((relay->flags & RELAY_ON_DEMAND) == 0)
        {
            yp_remove (relay->localmount);
            src->yp_public = -1;
        }
        relay->in_use = NULL;
        INFO2 ("listener count remaining on %s is %ld", src->mount, src->listeners);
        src->flags &= ~(SOURCE_PAUSE_LISTENERS|SOURCE_RUNNING);
    }
    thread_rwlock_unlock (&src->lock);

    thread_spin_lock (&relay_start_lock);
    relays_connecting--;
    thread_spin_unlock (&relay_start_lock);

    client->flags |= CLIENT_ACTIVE;
    worker_wakeup (client->worker);
    return NULL;
}



static int _drop_relay (void *a)
{
    relay_server *r = (relay_server*)a;

    if (r->source)
    {
        client_t *client = r->source->client;
        client->schedule_ms = 0;
    }
    r->flags &= ~RELAY_IN_LIST;
    DEBUG2 ("dropped relay %s (%p)", r->localmount, r);
    return 0;
}


static int _drop_relay_cleanup (void *a)
{
    relay_server *r = (relay_server*)a;

    _drop_relay (a);
    r->flags |= RELAY_CLEANUP;
    return 0;
}



static void detach_master_relay (const char *localmount, int cleanup)
{
    relay_server find;

    find.localmount = (char*)localmount;
    avl_delete (global.relays, &find, cleanup ? _drop_relay_cleanup : _drop_relay);
}



int relay_has_source (relay_server *relay, client_t *client)
{
    source_t *source = relay->source;
    if (source)
        thread_rwlock_wlock (&source->lock);
    else
    {
        source = source_reserve (relay->localmount, 0);
        if (source == NULL)
            return 0;
        relay->source = source;
        source->client = client;
        source->format->type = relay->type;
    }
    if (source_format_init (source) < 0)
    {
        detach_master_relay (relay->localmount, 1);
        thread_rwlock_unlock (&source->lock);
        return -1;
    }
    return 1;
}


static int relay_installed (relay_server *relay)
{
    client_t *client = calloc (1, sizeof (client_t));

    connection_init (&client->connection, SOCK_ERROR, NULL);
    switch (relay_has_source (relay, client))
    {
        case -1:
            free (client);
            return 0;
        case 1: 
            thread_rwlock_unlock (&relay->source->lock);
    }
    global_lock();
    client_register (client);
    global_unlock();

    client->shared_data = relay;
    client->ops = &relay_init_ops;
    relay->flags |= RELAY_IN_LIST;
    avl_insert (global.relays, relay);
    client->flags |= CLIENT_ACTIVE;
    client_add_worker (client);
    DEBUG2 ("adding relay client for %s (%p)", relay->localmount, relay);
    return 1;
}


#ifdef HAVE_CURL
static relay_server *create_master_relay (const char *local, const char *remote, format_type_t t, struct master_conn_details *master)
{
    relay_server *relay;
    relay_server_host *m;

    if (local[0] != '/')
    {
        WARN1 ("relay mountpoint \"%s\" does not start with /, skipping", local);
        return NULL;
    }
    relay = calloc (1, sizeof (relay_server));

    m = calloc (1, sizeof (relay_server_host));
    m->ip = (char *)xmlStrdup (XMLSTR(master->server));
    m->port = master->port;
    if (master->bind)
        m->bind = (char *)xmlStrdup (XMLSTR(master->bind));
    // may need to add the admin link later instead of assuming mount is as-is
    m->mount = (char *)xmlStrdup (XMLSTR(remote));
    m->timeout = 4;
    relay->hosts = m;

    relay->localmount = (char *)xmlStrdup (XMLSTR(local));
    relay->flags |= (RELAY_RUNNING | RELAY_ICY_META);
    if (master->on_demand)
        relay->flags |= RELAY_ON_DEMAND;
    if (master->on_demand) relay->flags |= RELAY_ON_DEMAND;
    relay->interval = master->max_interval;
    relay->run_on = master->run_on;
    if (master->send_auth)
    {
        relay->username = (char *)xmlStrdup (XMLSTR(master->username));
        relay->password = (char *)xmlStrdup (XMLSTR(master->password));
    }
    relay->updated = master->synctime;
    relay->flags |= RELAY_FROM_MASTER;
    return relay;
}


static int add_master_relay (const char *mount, const char *type, struct master_conn_details *master)
{
    int ret = -1, notfound;
    relay_server *result = NULL, find;

    if (strncmp (mount, "/admin/streams?mount=/", 22) == 0)
        find.localmount = (char *)(mount+21);
    else
        find.localmount = (char *)mount;

    notfound = avl_get_by_key (global.relays, &find, (void*)&result);
    if (notfound || (result->flags & RELAY_CLEANUP))
    {
        relay_server *new_relay = create_master_relay (find.localmount, mount, format_get_type (type), master);

        if (new_relay)
        {
            if (result && result->flags & RELAY_CLEANUP)
            {
                // drop this now, to avoid a duplicate relay that may match later
                detach_master_relay (find.localmount, 0);
            }
            if (relay_installed (new_relay))
                ret = new_relay->source ? 2 : 1;
            else
            {
                config_clear_relay (new_relay);
                ret = 0;
            }
        }
    }
    else
    {
        if (notfound == 0)
            result->updated = master->synctime; // avoid relay expiry
        if (streamlist_check == 0)
            INFO1 ("relay \"%s\" already in use, ignoring", mount);
    }
    return ret;
}


/* process a single HTTP header from streamlist response */
static size_t streamlist_header (void *ptr, size_t size, size_t nmemb, void *stream)
{
    size_t passed_len = size*nmemb;
    char *eol = memchr (ptr, '\r', passed_len);
    struct master_conn_details *master = stream;

    /* drop EOL chars if any */
    if (eol)
        *eol = '\0';
    else
    {
        eol = memchr (ptr, '\n', passed_len);
        if (eol)
            *eol = '\0';
        else
            return -1;
    }
    if (strncmp (ptr, "HTTP", 4) == 0)
    {
        int respcode = 0;
        if (sscanf (ptr, "HTTP%*s %d OK", &respcode) == 1 && respcode == 200)
            master->ok = 1;  // needed if resetting master relays ???
        else
            WARN1 ("Failed response from master \"%s\"", (char*)ptr);
    }
    //DEBUG1 ("header is %s", ptr);
    return passed_len;
}


/* process mountpoint list from master server. This may be called multiple
 * times so watch for the last line in this block as it may be incomplete
 */
static size_t streamlist_data (void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct master_conn_details *master = stream;
    size_t passed_len = size*nmemb;
    size_t len = passed_len;
    char *buffer = ptr, *buf = ptr;
    int prev = 0;

    if (master->ok == 0)
        return passed_len;
    if (master->previous)
    {
        char *eol = memchr (ptr, '\n', passed_len < 150 ? passed_len : 150);
        if (eol == NULL)
        {
            if (passed_len > 150 || master->previous > 200)
            {
                WARN1 ("long line received for append, ignoring %ld", (long)passed_len);
                return (master->ok = 0);
            }
            buffer = realloc (master->buffer, len + 1);
            if (buffer == NULL) return 0;
            master->buffer = buffer;
            memcpy (master->buffer + master->previous, ptr, passed_len);
            master->buffer [len] = '\0';
            master->previous = len;
            return passed_len;
        }
        // just fill out enough for 1 entry
        len = (eol - buffer) + 1 + master->previous;
        buffer = realloc (master->buffer, len + 1);
        if (buffer == NULL) return 0;
        master->buffer = buffer;
        prev = len - master->previous;
        memcpy (buffer+master->previous, ptr, prev);
        buffer [len] = '\0';
        buf = buffer;
    }

    avl_tree_wlock (global.relays);
    while (len)
    {
        int offset;
        char *eol = strchr (buf, '\n');
        if (eol)
        {
            offset = (eol - buf) + 1;
            *eol = '\0';
            eol = strchr (buf, '\r');
            if (eol) *eol = '\0';
        }
        else
        {
            /* incomplete line, the rest may be in the next read */
            master->buffer = calloc (1, len + 1);
            memcpy (master->buffer, buf, len);
            master->previous = len;
            break;
        }

        if (*buf == '/')
        {
            DEBUG1 ("read from master \"%s\"", buf);
            add_master_relay (buf, NULL, master);
        }
        else
            DEBUG1 ("skipping \"%s\"", buf);
        buf += offset;
        len -= offset;
        if (len == 0 && prev)
        {
            buf = ptr + prev;
            len =  passed_len - prev;
            free (master->buffer);
            master->buffer = NULL;
            master->previous = 0;
            prev = 0;
        }
    }
    avl_tree_unlock (global.relays);
    return passed_len;
}


/* retrieve streamlist from master server. The streamlist can be retrieved
 * from an SSL port if curl is capable and the config is aware of the port
 * to use
 */
static void *streamlist_thread (void *arg)
{
    struct master_conn_details *master = arg;
    CURL *handle;
    const char *protocol = "http";
    int port = master->port;
    char error [CURL_ERROR_SIZE];
    char url [1024], auth [100];

    DEBUG0 ("checking master stream list");
    if (master->ssl_port)
    {
        protocol = "https";
        port = master->ssl_port;
    }
    snprintf (auth, sizeof (auth), "%s:%s", master->username, master->password);
    snprintf (url, sizeof (url), "%s://%s:%d/admin/streams%s",
            protocol, master->server, port, master->args);
    handle = curl_easy_init ();
    curl_easy_setopt (handle, CURLOPT_USERAGENT, master->server_id);
    curl_easy_setopt (handle, CURLOPT_URL, url);
    curl_easy_setopt (handle, CURLOPT_HEADERFUNCTION, streamlist_header);
    curl_easy_setopt (handle, CURLOPT_HEADERDATA, master);
    curl_easy_setopt (handle, CURLOPT_WRITEFUNCTION, streamlist_data);
    curl_easy_setopt (handle, CURLOPT_WRITEDATA, master);
    curl_easy_setopt (handle, CURLOPT_USERPWD, auth);
    curl_easy_setopt (handle, CURLOPT_ERRORBUFFER, error);
    curl_easy_setopt (handle, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt (handle, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt (handle, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt (handle, CURLOPT_TIMEOUT, 120L);
    if (master->bind)
        curl_easy_setopt (handle, CURLOPT_INTERFACE, master->bind);

    master->ok = 0;
    master->synctime = time(NULL);
    if (curl_easy_perform (handle) != 0 || master->ok == 0)
    {
        /* fall back to traditional request */
        INFO0 ("/admin/streams failed trying streamlist");
        snprintf (url, sizeof (url), "%s://%s:%d/admin/streamlist.txt%s",
                protocol, master->server, port, master->args);
        curl_easy_setopt (handle, CURLOPT_URL, url);
        if (curl_easy_perform (handle) != 0)
            WARN2 ("Failed URL access \"%s\" (%s)", url, error);
    }
    if (master->ok)
        relay_barrier_master = master->synctime;

    curl_easy_cleanup (handle);
    free (master->server);
    free (master->username);
    free (master->password);
    free (master->buffer);
    free (master->server_id);
    free (master->args);
    free (master);
    streamlister = 0;
    return NULL;
}
#endif


void update_relays (ice_config_t *config)
{
    int notfound, trap = 10;
    relay_server *relay, *result, *copy, find;
    time_t sync_time = time (NULL);

    avl_tree_wlock (global.relays);
    relay = config->relays;
    while (relay)
    {
        find.localmount = relay->localmount;
        notfound = avl_get_by_key (global.relays, &find, (void*)&result);
        if (notfound)
        {
            relay_server *new_relay = relay_copy (relay);
            if (new_relay)
            {
                new_relay->updated = sync_time;
                if (! relay_installed (new_relay))
                    config_clear_relay (new_relay);
            }
        }
        else
        {
            detach_master_relay (find.localmount, 0); // drop current one from tree
            if (result->flags & RELAY_CLEANUP)
            {
                // should be rare but a relay could be leaving
                DEBUG1 ("old relay with cleanup flagged detected %s", result->localmount);
                if (--trap)
                    continue;
                WARN1 ("Detected loop with lookup of %s", find.localmount);
                break;
            }
            if (result->source == NULL)
            {
                INFO1 ("current relay %s not initialised, removed", result->localmount);
                continue;
            }
            copy = relay_copy (relay);
            DEBUG2 ("adding new relay %s (%p) into tree", relay->localmount, copy);
            // let client trigger the switchover for new details
            result->new_details = copy;
            copy->updated = sync_time;
            copy->flags |= RELAY_IN_LIST;
            avl_insert (global.relays, copy);
        }
        trap = 10;
        relay = relay->new_details;
    }
    relay_barrier_xml = sync_time;
    avl_tree_unlock (global.relays);
}


static void update_from_master (ice_config_t *config)
{
#ifdef HAVE_CURL
    struct master_conn_details *details;

    if (config->master_password == NULL || config->master_server == NULL ||
            config->master_server_port == 0)
        return;
    if (streamlister) return;
    streamlister = 1;
    details = calloc (1, sizeof (*details));
    details->server = strdup (config->master_server);
    details->port = config->master_server_port; 
    details->ssl_port = config->master_ssl_port; 
    details->username = strdup (config->master_username);
    details->password = strdup (config->master_password);
    details->send_auth = config->master_relay_auth;
    details->bind = (config->master_bind) ? strdup (config->master_bind) : NULL;
    details->on_demand = config->on_demand;
    details->server_id = strdup (config->server_id);
    details->max_interval = config->master_relay_retry;
    details->run_on = config->master_run_on;
    if (config->master_redirect)
    {
        details->args = malloc (4096);
        snprintf (details->args, 4096, "?rserver=%s&rport=%d&interval=%d",
                config->hostname, config->port, config->master_update_interval);
    }
    else
        details->args = strdup ("");

    thread_create ("streamlist", streamlist_thread, details, THREAD_DETACHED);
#endif
}


static void update_master_as_slave (ice_config_t *config)
{
    redirect_host *redirect;

    if (config->master_server == NULL || config->master_redirect == 0 || config->max_redirects == 0)
         return;

    thread_rwlock_wlock (&slaves_lock);
    redirect = find_slave_host (config->master_server, config->master_server_port);
    if (redirect == NULL)
    {
        INFO2 ("adding master %s:%d", config->master_server, config->master_server_port);
        redirector_add (config->master_server, config->master_server_port, 0);
    }
    else
        redirect->next_update += config->master_update_interval;
    thread_rwlock_unlock (&slaves_lock);
}


static void slave_startup (void)
{
    ice_config_t *config = config_get_config();

#ifdef HAVE_GETRLIMIT
    struct rlimit rlimit;
    if (getrlimit (RLIMIT_NOFILE, &rlimit) == 0)
    {
        if (rlimit.rlim_cur < rlimit.rlim_max)
        {
            long old = rlimit.rlim_cur;
            rlimit.rlim_cur = rlimit.rlim_max;
            if (setrlimit (RLIMIT_NOFILE, &rlimit) < 0)
                rlimit.rlim_cur = old;
        }
        WARN1 ("process has %ld max file descriptor limit", (long)rlimit.rlim_cur);
    }
    if (getrlimit (RLIMIT_CORE, &rlimit) == 0)
    {
        if (rlimit.rlim_cur < rlimit.rlim_max)
        {
            rlimit.rlim_cur = rlimit.rlim_max;
            setrlimit (RLIMIT_CORE, &rlimit);
        }
    }
#endif

    update_settings = 0;
    update_all_sources = 0;

    redirector_setup (config);
    stats_global (config);
    workers_adjust (config->workers_count);
    yp_initialize (config);
    update_relays (config);
    config_release_config();

    source_recheck_mounts (1);
    connection_thread_startup();
}

static void _slave_thread(void)
{
    slave_startup();

    while (1)
    {
        struct timespec current;
        int do_reread = 0;

        thread_get_timespec (&current);

        global_lock();
        if (global.running != ICE_RUNNING)
            break;
        /* re-read xml file if requested */
        if (global . schedule_config_reread)
        {
            global . schedule_config_reread = 0;
            do_reread = 1;
        }

        if (global.new_connections_slowdown)
            global.new_connections_slowdown--;
        if (global.new_connections_slowdown > 30)
            global.new_connections_slowdown = 30;

        global_unlock();

        global_add_bitrates (global.out_bitrate, 0L, THREAD_TIME_MS(&current));
        if (do_reread)
            event_config_read ();

        if (streamlist_check <= current.tv_sec)
        {
            ice_config_t *config = config_get_config();

            streamlist_check = current.tv_sec + config->master_update_interval;
            update_master_as_slave (config);

            update_from_master (config);

            config_release_config();
        }

        int update = 0, update_all = 0, restart = 0;
        thread_spin_lock (&relay_start_lock);
        if (update_settings)
        {
            update = update_settings;
            update_all = update_all_sources;
            if (update_all_sources || current.tv_sec%5 == 0)
            {
                update_settings = 0;
                update_all_sources = 0;
            }
            if (restart_connection_thread)
            {
                restart = restart_connection_thread;
                restart_connection_thread = 0;
            }
        }
        thread_spin_unlock (&relay_start_lock);

        if (update)
            source_recheck_mounts (update_all);
        if (restart)
        {
            connection_thread_shutdown();
            connection_thread_startup();
        }

        stats_global_calc (current.tv_sec);
        fserve_scan (current.tv_sec);

        /* allow for terminating icecast if no streams running */
        if (inactivity_timer)
        {
            if (global.sources)
            {
                inactivity_timer = 0;
                INFO0 ("inactivity timeout cancelled");
            }
            else if (inactivity_timer <= current.tv_sec)
            {
                INFO0 ("inactivity timeout reached, terminating server");
                global.running = ICE_HALTING;
            }
        }
        else
        {
            if (inactivity_timeout && global.sources == 0)
            {
                inactivity_timer = current.tv_sec + inactivity_timeout;
                INFO1 ("inactivity timeout started, terminate in %d seconds", inactivity_timeout);
            }
        }
        worker_balance_trigger (current.tv_sec);
        thread_sleep (1000000);
    }
    global_unlock();
    connection_thread_shutdown();
    fserve_running = 0;
    stats_clients_wakeup ();
    INFO0 ("shutting down current relays");
    time_t next = time(NULL) + 1000;
    thread_spin_lock (&relay_start_lock);
    relay_barrier_xml = next;
    relay_barrier_master = relay_barrier_xml;
    thread_spin_unlock (&relay_start_lock);
    redirector_clearall();

    INFO0 ("Slave thread shutdown complete");
}


relay_server *slave_find_relay (const char *mount)
{
    relay_server *result, find;

    find.localmount = (char*)mount;
    if (avl_get_by_key (global.relays, &find, (void*)&result))
        result = NULL;
    return result;
}



/* drop all redirection details.
 */
void redirector_clearall (void)
{
    thread_rwlock_wlock (&slaves_lock);
    while (redirectors)
    {
        redirect_host *current = redirectors;
        redirectors = current->next;
        INFO2 ("removing %s:%d", current->server, current->port);
        free (current->server);
        free (current);
    }
    global.redirect_count = 0;
    thread_rwlock_unlock (&slaves_lock);
}


void redirector_setup (ice_config_t *config)
{
    redirect_host *redir = config->redirect_hosts;

    thread_rwlock_wlock (&slaves_lock);
    while (redir)
    {
        redirector_add (redir->server, redir->port, 0);
        redir = redir->next;
    }
    thread_rwlock_unlock (&slaves_lock);

    inactivity_timeout = config->inactivity_timeout;
    inactivity_timer = 0;
}


/* Add new redirectors or update any existing ones
 */
void redirector_update (client_t *client)
{
    redirect_host *redirect;
    const char *rserver = httpp_get_query_param (client->parser, "rserver");
    const char *value;
    int rport = 0, interval = 0;

    if (rserver==NULL) return;
    value = httpp_get_query_param (client->parser, "rport");
    if (value == NULL) return;
    rport = atoi (value);
    if (rport <= 0) return;
    value = httpp_get_query_param (client->parser, "interval");
    if (value == NULL) return;
    interval = atoi (value);
    if (interval < 5) return;

    thread_rwlock_wlock (&slaves_lock);
    redirect = find_slave_host (rserver, rport);
    if (redirect == NULL)
    {
        ice_config_t *config = config_get_config();
        unsigned int allowed = config->max_redirects;

        config_release_config();

        if (global.redirect_count < allowed)
            redirector_add (rserver, rport, interval);
        else
            INFO2 ("redirect to slave limit reached (%d, %d)", global.redirect_count, allowed);
    }
    else
    {
        DEBUG2 ("touch update on %s:%d", redirect->server, redirect->port);
        redirect->next_update = time(NULL) + interval;
    }
    thread_rwlock_unlock (&slaves_lock);
}



/* search list of redirectors for a matching entry, lock must be held before
 * invoking this function
 */
static redirect_host *find_slave_host (const char *server, int port)
{
    redirect_host *redirect = redirectors;
    while (redirect)
    {
        if (strcmp (redirect->server, server) == 0 && redirect->port == port)
            break;
        redirect = redirect->next;
    }
    return redirect;
}


static void redirector_add (const char *server, int port, int interval)
{
    redirect_host *redirect = calloc (1, sizeof (redirect_host));
    if (redirect == NULL)
        abort();
    redirect->server = strdup (server);
    redirect->port = port;
    if (interval == 0)
        redirect->next_update = (time_t)0;
    else
        redirect->next_update = time(NULL) + interval;
    redirect->next = redirectors;
    redirectors = redirect;
    global.redirect_count++;
    INFO3 ("slave (%d) at %s:%d added", global.redirect_count,
            redirect->server, redirect->port);
}



static int relay_expired (relay_server *relay)
{
    thread_spin_lock (&relay_start_lock);
    time_t t = (relay->flags & RELAY_FROM_MASTER) ? relay_barrier_master : relay_barrier_xml;
    thread_spin_unlock (&relay_start_lock);

    return (relay->updated < t) ? 1 : 0;
}


static relay_server *get_relay_details (client_t *client)
{
    relay_server *relay = client->shared_data;

    avl_tree_rlock (global.relays);
    if (relay->new_details)
    {
        relay_server *old_details = relay;

        INFO1 ("Detected change in relay details for %s", relay->localmount);
        client->shared_data = relay->new_details;
        relay = client->shared_data;
        relay->source = old_details->source;
        old_details->source = NULL;
        config_clear_relay (old_details);
    }
    if (relay_expired (relay))
    {
        DEBUG1 ("relay expired %s", relay->localmount);
        relay->flags |= RELAY_CLEANUP;
    }
    avl_tree_unlock (global.relays);
    if (relay->flags & RELAY_CLEANUP)
        relay->flags &= ~RELAY_RUNNING;
    return relay;
}


static void relay_reset (relay_server *relay)
{
    relay_server_host *server = relay->hosts;

    for (; server; server = server->next)
       server->skip = 0;
    INFO1 ("servers to be retried on %s", relay->localmount);
}


static int relay_read (client_t *client)
{
    relay_server *relay = get_relay_details (client);
    source_t *source = relay->source;

    thread_rwlock_wlock (&source->lock);
    if (source_running (source))
    {
        if ((relay->flags & RELAY_RUNNING) == 0)
            source->flags &= ~SOURCE_RUNNING;
        if (source->listeners == 0 && (relay->flags & RELAY_ON_DEMAND))
        {
            if (client->connection.discon.time == 0)
                client->connection.discon.time = client->worker->current_time.tv_sec + relay->run_on;

            if (client->worker->current_time.tv_sec > client->connection.discon.time)
                source->flags &= ~SOURCE_RUNNING;
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
        /* this section is for once through code */
        int fallback = global.running == ICE_RUNNING ? 1 : 0;
        if (client->connection.con_time && global.running == ICE_RUNNING)
        {
            if ((relay->flags & RELAY_RUNNING) && relay->in_use)
                fallback = 0;
            if ((relay->flags & RELAY_ON_DEMAND) == 0 &&
                    client->worker->current_time.tv_sec - client->connection.con_time < 60)
            {
                /* force a server skip if a stream cannot be maintained for 1 min */
                WARN1 ("stream for %s died too quickly, skipping server for now", relay->localmount);
                if (relay->in_use) relay->in_use->skip = 1;
            }
            else
            {
                if (client->connection.sent_bytes < 500000 && source->flags & SOURCE_TIMEOUT)
                {
                    WARN1 ("stream for %s timed out, skipping server for now", relay->localmount);
                    if (relay->in_use) relay->in_use->skip = 1;
                }
                else
                    relay_reset (relay); // spent some time on this so give other servers a chance
            }
        }
        /* don't pause listeners if relay shutting down */
        if ((relay->flags & RELAY_RUNNING) == 0)
            source->flags &= ~SOURCE_PAUSE_LISTENERS;
        // fallback listeners unless relay is to be retried
        INFO2 ("fallback on %s %sattempted", source->mount, fallback ? "" : "not ");
        source_shutdown (source, fallback);
    }
    if (source->termination_count && source->termination_count <= source->listeners)
    {
        client->schedule_ms = client->worker->time_ms + 150;
        if (client->timer_start + 1500 < client->worker->time_ms)
        {               
            WARN2 ("%ld listeners still to process in terminating %s", source->termination_count, source->mount);
            source->flags &= ~SOURCE_TERMINATING;
        }   
        else
            DEBUG3 ("%s waiting (%lu, %lu)", source->mount, source->termination_count, source->listeners);
        thread_rwlock_unlock (&source->lock);
        return 0;
    }
    DEBUG1 ("all listeners have now been checked on %s", relay->localmount);
    if (client->connection.con_time)
    {
        global_lock();
        global.sources--;
        stats_event_args (NULL, "sources", "%d", global.sources);
        global_unlock();
        global_reduce_bitrate_sampling (global.out_bitrate);
    }
    client->timer_start = 0;
    client->parser = NULL;
    free (source->fallback.mount);
    source->fallback.mount = NULL;
    source->flags &= ~(SOURCE_TERMINATING|SOURCE_LISTENERS_SYNC|SOURCE_ON_DEMAND);
    if (relay->flags & RELAY_CLEANUP)
    {
        connection_close (&client->connection);
        if (source->listeners)
        {
            INFO1 ("listeners on terminating relay %s, rechecking", relay->localmount);
            client->timer_start = client->worker->time_ms;
            source->termination_count = source->listeners;
            source->flags &= ~SOURCE_PAUSE_LISTENERS;
            source->flags |= SOURCE_LISTENERS_SYNC;
            source_listeners_wakeup (source);
            thread_rwlock_unlock (&source->lock);
            return 0; /* listeners may be paused, recheck and let them leave this stream */
        }
        INFO1 ("shutting down relay %s", relay->localmount);
        if (relay->flags & RELAY_IN_LIST)
        {
            avl_tree_wlock (global.relays);
            detach_master_relay (relay->localmount, 1);
            avl_tree_unlock (global.relays);
        }
        stats_lock (source->stats, NULL);
        stats_set_args (source->stats, "listeners", "%lu", source->listeners);
        stats_set (source->stats, NULL, NULL);
        source->stats = 0;
        thread_rwlock_unlock (&source->lock);
        slave_update_mounts();
        return -1;
    }
    client->ops = &relay_init_ops;
    do {
        if (relay->flags & RELAY_RUNNING)
        {
            if (client->connection.con_time && relay->in_use)
            {
                INFO1 ("standing by to restart relay on %s", relay->localmount);
                stats_flush (source->stats);
                if (relay->flags & RELAY_ON_DEMAND && source->listeners == 0 && relay->in_use->next)
                {
                    source_clear_source (relay->source);
                    relay_reset (relay);
                }
                break;
            }
            if (relay->interval < 3)
                relay->interval = 60; // if set too low then give a decent retry delay
            client->schedule_ms = client->worker->time_ms + (relay->interval * 1000);
            INFO2 ("standing by to restart relay on %s in %d seconds", relay->localmount, relay->interval);
        }
        else
        {
            INFO1 ("Relay %s is disabled", relay->localmount);
            client->schedule_ms = client->worker->time_ms + 3600000;
        }
        stats_lock (source->stats, NULL);
        stats_set_args (source->stats, "listeners", "%lu", source->listeners);
        source_clear_source (relay->source);
        relay_reset (relay);
        stats_set (source->stats, NULL, NULL);
        source->stats = 0;
        slave_update_mounts();
    } while (0);

    thread_rwlock_unlock (&source->lock);
    connection_close (&client->connection);
    return 0;
}


static void relay_release (client_t *client)
{
    relay_server *relay = client->shared_data;
    DEBUG2("freeing relay %s (%p)", relay->localmount, relay);
    if (relay->source)
        source_free_source (relay->source);
    relay->source = NULL;
    config_clear_relay (relay);
    client_destroy (client);
}



// This is a special case one, to act as a once through, to get the source reserved and stat initialised
static int relay_initialise (client_t *client)
{
    relay_server *relay = get_relay_details (client);
    int rc = relay_has_source (relay, client);
    source_t *source = relay->source;

    if (rc < 0)  return -1;
    if (rc == 0)  // in cases where relay was added ok but source in use, should be rare
    {
        WARN1 ("relay for \"%s\" cannot get started, mountpoint in use, waiting", relay->localmount);
        client->schedule_ms = client->worker->time_ms + 120000;
        return 0;
    }
    do
    {
        if (relay->flags & RELAY_RUNNING)
        {
            if (relay->flags & RELAY_ON_DEMAND)
            {
                ice_config_t *config;
                mount_proxy *mountinfo;

                source_clear_source (source);
                config = config_get_config();
                mountinfo = config_find_mount (config, source->mount);
                source->flags |= SOURCE_ON_DEMAND;
                if (source->stats == 0)
                {
                    source->stats = stats_lock (source->stats, source->mount);
                    stats_release (source->stats);
                }
                source_update_settings (config, source, mountinfo);
                config_release_config();
                slave_update_mounts();
                stats_set_flags (source->stats, "listener_connections", "0", STATS_COUNTERS);
            }
            break;
        }
        thread_rwlock_unlock (&source->lock);
        if (relay->flags & RELAY_CLEANUP)
            return relay_read (client);
        client->schedule_ms = client->worker->time_ms + 1000000;
        return 0;
    } while(0);
    thread_rwlock_unlock (&source->lock);
    client->ops = &relay_startup_ops;
    return client->ops->process (client);
}


static int relay_startup (client_t *client)
{
    relay_server *relay = get_relay_details (client);
    worker_t *worker = client->worker;

    if ((relay->flags & RELAY_RUNNING) == 0)
    {
        if (relay->source == NULL) { WARN1 ("odd case for %s", relay->localmount); return -1; }
        client->ops = &relay_client_ops;
        client->schedule_ms = worker->time_ms + 10;
        DEBUG1 ("relay %s disabled", relay->localmount);
        return client->ops->process (client);
    }
    global_lock();
    if (global.running != ICE_RUNNING)  /* wait for cleanup */
    {
        global_unlock();
        client->schedule_ms = client->worker->time_ms + 50;
        return 0;
    }
    global_unlock();
    if (worker->move_allocations)
    {
        int ret = 0;
        worker_t *dest_worker;

        thread_rwlock_rlock (&workers_lock);
        dest_worker = worker_selected ();
        if (dest_worker != worker)
        {
            long diff = worker->count - dest_worker->count;
            if (diff > 5)
            {
                worker->move_allocations--;
                ret = client_change_worker (client, dest_worker);
            }
        }
        thread_rwlock_unlock (&workers_lock);
        if (ret)
            return ret;
    }

    if (relay->flags & RELAY_ON_DEMAND)
    {
        source_t *source = relay->source;
        int start_relay;
        mount_proxy *mountinfo;

        thread_rwlock_wlock (&source->lock);
        start_relay = source->listeners; // 0 or non-zero
        source->flags |= SOURCE_ON_DEMAND;
        thread_rwlock_unlock (&source->lock);
        mountinfo = config_find_mount (config_get_config(), source->mount);

        if (mountinfo && mountinfo->fallback_mount)
        {
            avl_tree_rlock (global.source_tree);
            if (fallback_count (config_get_config_unlocked(), mountinfo->fallback_mount) > 0)
                start_relay = 1;
            avl_tree_unlock (global.source_tree);
        }
        config_release_config();
        if (start_relay == 0)
        {
            if (source->stats == 0)
            {
                source->stats = stats_lock (source->stats, source->mount);
                stats_release (source->stats);
                slave_update_mounts();
            }
            client->schedule_ms = (worker->time_ms + 1000) | 0xff;
            return 0;
        }
        INFO1 ("starting on-demand relay %s", relay->localmount);
    }

    /* limit the number of relays starting up at the same time */
    thread_spin_lock (&relay_start_lock);
    if (relays_connecting > 3)
    {
        thread_spin_unlock (&relay_start_lock);
        client->schedule_ms = worker->time_ms + 200;
        if (global.new_connections_slowdown < 5)
            global.new_connections_slowdown++;
        return 0;
    }
    relays_connecting++;
    thread_spin_unlock (&relay_start_lock);

    client->flags &= ~CLIENT_ACTIVE;
    thread_create ("Relay Thread", start_relay_stream, client, THREAD_DETACHED);
    return 0;
}


int fallback_count (ice_config_t *config, const char *mount)
{
    int count = -1, loop = 10;
    const char *m = mount;
    char buffer[4096];

    if (mount == NULL) return -1;
    if (strstr (mount, "${")) return -1;
    while (m && loop--)
    {
        source_t *fallback = source_find_mount_raw (m);
        if (fallback == NULL || source_running (fallback) == 0)
        {
            unsigned int len;
            mount_proxy *mountinfo = config_find_mount (config, m);
            if (fallback == NULL)
            {
                fbinfo finfo;

                memset (&finfo, 0, sizeof (finfo));
                finfo.flags = FS_FALLBACK;
                finfo.mount = (char *)m;
                finfo.fallback = NULL;
                finfo.limit = mountinfo ? mountinfo->limit_rate/8 : 0;
                if (finfo.limit == 0)
                {
                    unsigned int rate;
                    if (sscanf (m, "%*[^[][%u]", &rate) == 1)
                       finfo.limit = rate * 1000 / 8;
                }
                count = fserve_query_count (&finfo);
            }
            if (mountinfo == NULL)
                break;
            len = sizeof buffer;
            if (util_expand_pattern (m, mountinfo->fallback_mount, buffer, &len) < 0)
                break;
            m = buffer;
            continue;
        }
        count = fallback->listeners;
        break;
    }
    return count;
}
