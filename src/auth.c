/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2010-2022, Karl Heyes <karl@kheyes.plus.com>,
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org>,
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

/**
 * Client authentication functions
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#include "auth.h"
#include "auth_htpasswd.h"
#include "auth_cmd.h"
#include "auth_url.h"
#include "source.h"
#include "client.h"
#include "cfgfile.h"
#include "stats.h"
#include "httpp/httpp.h"
#include "fserve.h"
#include "admin.h"
#include "global.h"

#include "logging.h"
#define CATMODULE "auth"

struct _auth_thread_t
{
    thread_type *thread;
    void *data;
    unsigned int id;
    struct auth_tag *auth;
};

static volatile int thread_id;
static rwlock_t auth_lock;
int allow_auth;

static void *auth_run_thread (void *arg);
static int  auth_postprocess_listener (auth_client *auth_user);
static void auth_postprocess_source (auth_client *auth_user);
static int  wait_for_auth (client_t *client);
static void auth_client_free (auth_client *auth_user);


struct _client_functions auth_release_ops =
{
    wait_for_auth,
    client_destroy
};


static int wait_for_auth (client_t *client)
{
    DEBUG0 ("client finished with auth");
    client->flags &= ~CLIENT_AUTHENTICATED;
    return -1;
}


void auth_check_http (client_t *client)
{
    const char *header;
    char *username, *password;

    /* process any auth headers if any available */
    header = httpp_getvar (client->parser, "authorization");
    if (header == NULL)
        return;

    if (strncmp(header, "Basic ", 6) == 0)
    {
        /* This will look something like "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" */
        char *tmp, *userpass = util_base64_decode (header+6);
        if (userpass == NULL)
        {
            WARN1("Base64 decode of Authorization header \"%s\" failed",
                    header+6);
            return;
        }

        tmp = strchr(userpass, ':');
        if (tmp == NULL)
        {
            free (userpass);
            return;
        }

        *tmp = 0;
        username = userpass;
        password = tmp+1;
        client->username = strdup (username);
        client->password = strdup (password);
        free (userpass);
        return;
    }
    WARN1 ("unhandled authorization header: %s", header);
}


static auth_client *auth_client_setup (const char *mount, client_t *client)
{
    ice_config_t *config = config_get_config_unlocked();
    auth_client *auth_user = calloc (1, sizeof(auth_client));

    auth_user->mount = strdup (mount);
    auth_user->hostname = strdup (config->hostname);
    auth_user->port = config->port;
    auth_user->client = client;
    if (client)
    {
        auth_user->flags = client->flags;
        if (client->mount == NULL)
            client->mount = auth_user->mount;
    }
    return auth_user;
}


static void queue_auth_client (auth_client *auth_user, mount_proxy *mountinfo)
{
    auth_t *auth;
    client_t *failed = NULL;
    auth_client **old_tail;
    int maxxed = 0;

    if (auth_user == NULL || mountinfo == NULL)
        return;
    auth = mountinfo->auth;
    if (auth_user->client)
        auth_user->client->worker = NULL;
    thread_mutex_lock (&auth->lock);
    auth_user->next = NULL;
    auth_user->auth = auth;
    old_tail = auth->tailp;
    *auth->tailp = auth_user;
    auth->tailp = &auth_user->next;
    int pending = ++auth->pending_count;
    if (auth->refcount > auth->handlers)
        maxxed = 1;
    else
    {
        int i;
        for (i=0; i<auth->handlers; i++)
        {
            if (auth->handles [i].thread == NULL)
            {
                //DEBUG1 ("starting auth thread %d", i);
                auth->refcount++;
                auth->handles [i].thread = thread_create ("auth thread", auth_run_thread, &auth->handles [i], THREAD_DETACHED);
                if (auth->handles [i].thread == NULL)
                {
                    auth->tailp = old_tail;
                    *old_tail = NULL;
                    auth->pending_count--;
                    auth->refcount--;
                    failed = auth_user->client;
                    auth_user->client = NULL;
                }
                break;
            }
        }
    }
    thread_mutex_unlock (&auth->lock);
    if (maxxed == 0)
        DEBUG2 ("auth on %s has %d pending", auth->mount, pending);
    if (failed)
    {
        ERROR0 ("failed to start auth thread, system limit probably reached");
        client_send_403redirect (failed, auth_user->mount, "system limit reached");
        auth_client_free (auth_user);
    }
}


/* release the auth. It is referred to by multiple structures so this is
 * refcounted and only actual freed after the last use
 */
void auth_release (auth_t *authenticator)
{
    if (authenticator == NULL) return;
    authenticator->refcount--;
    DEBUG2 ("...refcount on auth_t %s is now %d", authenticator->mount, authenticator->refcount);
    if (authenticator->refcount)
    {
        thread_mutex_unlock (&authenticator->lock);
        return;
    }

    /* cleanup auth threads attached to this auth */
    authenticator->flags &= ~AUTH_RUNNING;
    for (int i = 0; i < authenticator->handlers; i++)
    {
        if (authenticator->release_thread_data)
            authenticator->release_thread_data (authenticator, authenticator->handles [i].data);
        DEBUG2 ("...handler %d destroyed for %s", i, authenticator->mount);
    }
    free (authenticator->handles);

    if (authenticator->release)
        authenticator->release (authenticator);
    xmlFree (authenticator->type);
    xmlFree (authenticator->realm);
    xmlFree (authenticator->rejected_mount);
    thread_mutex_unlock (&authenticator->lock);
    thread_mutex_destroy (&authenticator->lock);
    free (authenticator->mount);
    free (authenticator);
}


static void auth_client_free (auth_client *auth_user)
{
    if (auth_user == NULL)
        return;
    if (auth_user->client)
    {
        client_t *client = auth_user->client;

        client_send_401 (client, auth_user->auth->realm);
        auth_user->client = NULL;
    }
    free (auth_user->hostname);
    free (auth_user->mount);
    free (auth_user);
}


/* wrapper function for auth thread to authenticate new listener
 * connection details
 */
static void auth_new_listener (auth_client *auth_user)
{
    client_t *client = auth_user->client;

    /* make sure there is still a client at this point, a slow backend request
     * can be avoided if client has disconnected */
    if (allow_auth == 0 || client_connected (client) == 0)
    {
        DEBUG1 ("dropping listener #%" PRIu64 " connection", client->connection.id);
        client->respcode = 400;
        return;
    }
    if (auth_user->auth->authenticate)
    {
        switch (auth_user->auth->authenticate (auth_user))
        {
            case AUTH_OK:
            case AUTH_FAILED:
                break;
            default:
                return;
        }
    }
    auth_postprocess_listener (auth_user);
}


/* wrapper function for auth thread to drop listener connections
 */
static void auth_remove_listener (auth_client *auth_user)
{
    if (auth_user->auth->release_listener)
        auth_user->auth->release_listener (auth_user);
    auth_user->auth = NULL;

    /* client is going, so auth is not an issue at this point */
    if (auth_user->client)
    {
        client_t *client = auth_user->client;
        client->flags &= ~CLIENT_AUTHENTICATED;
        DEBUG1 ("client #%" PRIu64 " completed", client->connection.id);
        thread_rwlock_rlock (&workers_lock);
        worker_t *worker = client->worker;
        if (worker)
            client_send_404 (client, NULL);
        else
            client_destroy (auth_user->client);
        thread_rwlock_unlock (&workers_lock);
        auth_user->client = NULL;
    }
}


/* Called from auth thread to process any request for source client
 * authentication. Only applies to source clients, not relays.
 */
static void stream_auth_callback (auth_client *auth_user)
{
    client_t *client = auth_user->client;

    if (auth_user->auth->stream_auth)
        auth_user->auth->stream_auth (auth_user);

    client->flags = auth_user->flags;

    auth_postprocess_source (auth_user);
}


/* Callback from auth thread to handle a stream start event, this applies
 * to both source clients and relays.
 */
static void stream_start_callback (auth_client *auth_user)
{
    auth_t *auth = auth_user->auth;

    if (auth->stream_start)
        auth->stream_start (auth_user);
    if (auth_user->client)
    {
        client_t *client = auth_user->client;
        free (client->connection.ip);
        refbuf_release (client->refbuf);
        free (client->shared_data); // useragent
        free (client);
        auth_user->client = NULL;
    }
}


/* Callback from auth thread to handle a stream start event, this applies
 * to both source clients and relays.
 */
static void stream_end_callback (auth_client *auth_user)
{
    auth_t *auth = auth_user->auth;

    if (auth->stream_end)
        auth->stream_end (auth_user);
    if (auth_user->client)
    {
        client_t *client = auth_user->client;
        free (client->connection.ip);
        refbuf_release (client->refbuf);
        free (client->shared_data); // useragent
        free (client);
        auth_user->client = NULL;
    }
}


/* The auth thread main loop. */
static void *auth_run_thread (void *arg)
{
    auth_thread_t *handler = arg;
    auth_t *auth = handler->auth;
    int id = handler->id;

    DEBUG2 ("Authentication thread %d started for %s", id, auth->mount);
    if (handler->data == NULL && auth->alloc_thread_data)
    {
        handler->data = auth->alloc_thread_data (auth);
        DEBUG2 ("...handler %d for %s initialized", id, auth->mount);
    }

    thread_rwlock_rlock (&auth_lock);

    while (1)
    {
        thread_mutex_lock (&auth->lock);
        if (auth->head)
        {
            auth_client *auth_user = auth->head;

            auth->head = auth_user->next;
            if (auth->head == NULL)
                auth->tailp = &auth->head;
            int pending = --auth->pending_count;
            thread_mutex_unlock (&auth->lock);
            auth_user->next = NULL;

            /* associate per-thread data with auth_user here */
            auth_user->thread_data = handler->data;
            auth_user->handler = id;

            if (auth_user->process)
                auth_user->process (auth_user);

            auth_client_free (auth_user);
            if (pending)
                DEBUG2 ("%d client(s) pending on %s", pending, auth->mount);
            continue;
        }
        handler->thread = NULL;
        break;
    }
    auth_release (auth);
    DEBUG1 ("Authenication thread (handler %d) shutting down", id);
    thread_rwlock_unlock (&auth_lock);
    return NULL;
}


int move_listener (client_t *client, struct _fbinfo *finfo)
{
    source_t *source;
    mount_proxy *minfo;
    int rate = finfo->limit, loop = 20, ret = -1;
    struct _fbinfo where;
    unsigned int len = 4096;
    char buffer [len];

    memcpy (&where, finfo, sizeof (where));
    if (finfo->override)
        where.override = strdup (finfo->override);
    avl_tree_rlock (global.source_tree);
    do
    {
        len = sizeof buffer;
        util_expand_pattern (where.override, where.mount, buffer, &len);
        where.mount = buffer;

        minfo = config_lock_mount (NULL, where.mount);

        if (rate == 0 && minfo && minfo->limit_rate)
            rate = minfo->limit_rate/8;
        source = source_find_mount_raw (where.mount);

        if (source == NULL && minfo == NULL)
            break;
        if (source)
        {
            thread_rwlock_wlock (&source->lock);
            if (source_available (source))
            {
                // an unused on-demand relay will still have an unitialised type
                if (source->format->type == finfo->type || source->format->type == FORMAT_TYPE_UNDEFINED)
                {
                    config_mount_ref (minfo, 0);
                    avl_tree_unlock (global.source_tree);
                    source_setup_listener (source, client);
                    source->listeners++;
                    client->flags |= CLIENT_HAS_MOVED;
                    thread_rwlock_unlock (&source->lock);
                    free (where.override);
                    return 0;
                }
            }
            thread_rwlock_unlock (&source->lock);
        }
        if (minfo && minfo->fallback.mount)
        {
            free (where.override);
            where.override = strdup (where.mount);
            where.mount = minfo->fallback.mount;
        }
        else
            break;
    } while (loop--);

    avl_tree_unlock (global.source_tree);
    config_mount_ref (minfo, 0);
    if (where.mount && ((client->flags & CLIENT_IS_SLAVE) == 0))
    {
        if (where.limit == 0)
        {
            if (rate == 0)
                if (sscanf (where.mount, "%*[^[][%d]", &rate) == 1)
                    rate = rate * 1000/8;
            where.limit = rate;
        }
        client->intro_offset = 0;
        ret = fserve_setup_client_fb (client, &where);
    }
    free (where.override);
    return ret;
}


/* Add listener to the pending lists of either the source or fserve thread. This can be run
 * from the connection or auth thread context. return -1 to indicate that client has been
 * terminated, 0 for receiving content.
 *
 * Drop count on mountinfo on exit.
 */
static int add_authenticated_listener (const char *mount, mount_proxy *mountinfo, client_t *client)
{
    int ret = 0;

    if (client->parser->req_type != httpp_req_head)
        client->flags |= CLIENT_AUTHENTICATED;

    /* some win32 setups do not do TCP win scaling well, so allow an override */
    if (mountinfo && mountinfo->so_sndbuf > 0)
        sock_set_send_buffer (client->connection.sock, mountinfo->so_sndbuf);

    /* check whether we are processing a streamlist request for slaves */
    if (strcmp (mount, "/admin/streams") == 0)
    {
        client->flags |= CLIENT_IS_SLAVE;
        if (client->parser->req_type == httpp_req_stats)
        {
            config_release_mount (mountinfo);
            stats_add_listener (client, STATS_SLAVE|STATS_GENERAL);
            return 0;
        }
        mount = httpp_get_query_param (client->parser, "mount");
        if (mount == NULL)
        {
            config_release_mount (mountinfo);
            command_list_mounts (client, TEXT);
            return 0;
        }
        mount_proxy *m = config_lock_mount (NULL, mount);
        config_release_mount (mountinfo);
        mountinfo = m;
    }

    /* Here we are parsing the URI request to see if the extension is .xsl, if
     * so, then process this request as an XSLT request
     */
    if (util_check_valid_extension (mount) == XSLT_CONTENT)
    {
        /* If the file exists, then transform it, otherwise, write a 404 */
        config_release_mount (mountinfo);
        DEBUG0("Stats request, sending XSL transformed stats");
        return stats_transform_xslt (client, mount);
    }

    ret = source_add_listener (mount, mountinfo, client);

    if (ret == -2)
    {
        if (mountinfo && mountinfo->file_seekable == 0)
        {
            DEBUG1 ("disable seek on file matching %s", mountinfo->mountname);
            httpp_deletevar (client->parser, "range");
            client->flags |= CLIENT_NO_CONTENT_LENGTH;
        }
        client->mount = mount;
        ret = fserve_client_create (client, mount);
    }
    config_release_mount (mountinfo);
    return ret;
}


static int auth_postprocess_listener (auth_client *auth_user)
{
    int ret;
    client_t *client = auth_user->client;
    auth_t *auth = auth_user->auth;
    mount_proxy *mountinfo;
    const char *mount = auth_user->mount;

    if (client == NULL)
        return 0;

    client->flags = auth_user->flags;

    if ((auth_user->flags & CLIENT_AUTHENTICATED) == 0)
    {
        /* auth failed so do we place the listener elsewhere */
        auth_user->client = NULL;
        if (auth->rejected_mount)
            mount = auth->rejected_mount;
        else
        {
            DEBUG1 ("listener #%" PRIu64 " rejected", client->connection.id);
            client_send_401 (client, auth_user->auth->realm);
            return -1;
        }
    }
    mountinfo = config_lock_mount (NULL, mount);
    ret = add_authenticated_listener (mount, mountinfo, client);
    auth_user->client = NULL;

    return ret;
}


/* Decide whether we need to start a source or just process a source
 * admin request.
 */
void auth_postprocess_source (auth_client *auth_user)
{
    if (auth_user->flags & CLIENT_AUTHENTICATED)
    {
        client_t *client = auth_user->client;
        const char *mount = auth_user->mount;
        const char *req = httpp_getvar (client->parser, HTTPP_VAR_URI);

        auth_user->client = NULL;
        if (strcmp (req, "/admin.cgi") == 0 || strncmp ("/admin/metadata", req, 15) == 0)
        {
            DEBUG2 ("metadata request (%s, %s)", req, mount);
            admin_mount_request (client);
        }
        else
        {
            DEBUG1 ("on mountpoint %s", mount);
            source_startup (client, mount);
        }
        return;
    }
    WARN1 ("Failed auth attempt for source \"%s\"", auth_user->mount);
}


/* Add a listener. Check for any mount information that states any
 * authentication to be used.
 */
int auth_add_listener (const char *mount, client_t *client)
{
    int ret = 0, need_auth = 1;
    mount_proxy *mountinfo = config_lock_mount (NULL, mount);

    if (client->flags & CLIENT_AUTHENTICATED)
        need_auth = 0;
    else
    {
        const char *range = httpp_getvar (client->parser, "range");
        if (range)
        {
            if (strncmp (range, "bytes=", 6) == 0)
            {
                int n = 0, v = 0;
                uint64_t pos1 = 0, pos2 = (uint64_t)-2;

                range += 6;
                if (range[0] == '-')
                    v = sscanf (range, "-%" SCNuMAX "%n", &pos2, &n);
                else
                {
                    v = sscanf (range, "%" SCNuMAX "-%" SCNuMAX"%n", &pos1, &pos2, &n);
                    if (v == 1)
                    {
                        v = sscanf (range, "%" SCNuMAX "-%n", &pos1, &n);
                        client->connection.flags |= CONN_FLG_END_UNSPEC;
                    }
                }

                if (v > 0 && range[n] == '\0' && pos1 <= pos2)
                {
                    pos2++;     // to help later, use like an eof marker, not end of range
                    client->intro_offset = pos1;
                    client->connection.start_pos = pos1;
                    client->connection.discon.sent = pos2;
                    client->flags |= CLIENT_RANGE_END;
                    if ((client->connection.flags & CONN_FLG_END_UNSPEC) == 0 && (pos2 - pos1) < 100)
                        need_auth = 0; // avoid auth check if range is very small, player hack
                    range = NULL;
                }
            }
            if (range)
                INFO2 ("client %" PRI_ConnID " has unexpected range (%s), ignoring", CONN_ID (client), range);
        }
    }
    if (client->parser->req_type == httpp_req_head)
    {
        client->flags &= ~CLIENT_AUTHENTICATED;
        need_auth = 0;
    }

    if (need_auth)
    {
        if (mountinfo)
        {
            auth_t *auth = mountinfo->auth;

            if (mountinfo->skip_accesslog)
                client->flags |= CLIENT_SKIP_ACCESSLOG;
            if (mountinfo->ban_client)
            {
                if (mountinfo->ban_client < 0)
                    client->flags |= CLIENT_IP_BAN_LIFT;
                connection_add_banned_ip (client->connection.ip, mountinfo->ban_client);
            }
            if (mountinfo->no_mount)
            {
                config_release_mount (mountinfo);
                return client_send_403 (client, "mountpoint unavailable");
            }
            if (mountinfo->redirect)
            {
                char buffer [4096] = "";
                unsigned int len = sizeof buffer;

                if (util_expand_pattern (mount, mountinfo->redirect, buffer, &len) == 0)
                {
                    config_release_mount (mountinfo);
                    return client_send_302 (client, buffer);
                }
                WARN3 ("failed to expand %s on %s for %s", mountinfo->redirect, mountinfo->mountname, mount);
                config_release_mount (mountinfo);
                return client_send_501 (client);
            }
            do
            {
                if (auth == NULL) break;
                if ((auth->flags & AUTH_RUNNING) == 0) break;
                if (auth->pending_count > 400)
                {
                    if (auth->flags & AUTH_SKIP_IF_SLOW) break;
                    config_release_mount (mountinfo);
                    WARN0 ("too many clients awaiting authentication");
                    if (global.new_connections_slowdown < 10)
                        global.new_connections_slowdown++;
                    return client_send_403 (client, "busy, please try again later");
                }
                if (auth->authenticate)
                {
                    auth_client *auth_user = auth_client_setup (mount, client);
                    auth_user->process = auth_new_listener;
                    DEBUG2 ("adding client #%" PRIu64 " (%s) for authentication", CONN_ID(client), CONN_ADDR(client));
                    queue_auth_client (auth_user, mountinfo);
                    config_release_mount (mountinfo);
                    return 1;
                }
            } while (0);
        }
        else
        {
            if (strcmp (mount, "/admin/streams") == 0)
            {
                config_release_mount (mountinfo);
                return client_send_401 (client, NULL);
            }
        }
    }
    ret = add_authenticated_listener (mount, mountinfo, client);
    return ret;
}


/* General listener client shutdown function. Here we free up the passed client but
 * if the client is authenticated and there's auth available then queue it.
 */
int auth_release_listener (client_t *client, const char *mount, mount_proxy *mountinfo)
{
    if (client->flags & CLIENT_AUTHENTICATED)
    {
        client_set_queue (client, NULL);

        if (mount && mountinfo && mountinfo->auth && mountinfo->auth->release_listener)
        {
            auth_client *auth_user = auth_client_setup (mount, client);
            client->ops = &auth_release_ops;
            client->connection.discon.time = time (NULL);
            auth_user->process = auth_remove_listener;
            queue_auth_client (auth_user, mountinfo);
            return 1;
        }
        client->flags &= ~CLIENT_AUTHENTICATED;
    }
    return client_send_404 (client, NULL);
}


static int get_authenticator (auth_t *auth, config_options_t *options)
{
    if (auth->type == NULL)
    {
        WARN0 ("no authentication type defined");
        return -1;
    }
    do
    {
        if (auth->handles)
        {   // for final setup after all settings supplied, log reporting mainly
            INFO2 ("on %s is type %s", auth->mount, auth->type);
            INFO3 ("handlers %d, dup %d, drop %d", auth->handlers, (auth->flags&AUTH_ALLOW_LISTENER_DUP ? 1 : 0),
                    (auth->flags&AUTH_DEL_EXISTING_LISTENER ? 1 : 0));
            if (auth->realm)
                INFO1 ("realm set as %s", auth->realm);
            if (auth->rejected_mount)
                INFO1 ("rejected set %s", auth->rejected_mount);
        }

        if (strcmp (auth->type, "url") == 0)
        {
            if (auth_get_url_auth (auth, options) < 0)
                return -1;
            break;
        }
        if (strcmp (auth->type, "command") == 0)
        {
#ifdef WIN32
            ERROR1("Authenticator type: \"%s\" not supported on win32 platform", auth->type);
            return -1;
#else
            if (auth_get_cmd_auth (auth, options) < 0)
                return -1;
            break;
#endif
        }
        if (strcmp (auth->type, "htpasswd") == 0)
        {
            if (auth_get_htpasswd_auth (auth, options) < 0)
                return -1;
            break;
        }

        ERROR1("Unrecognised authenticator type: \"%s\"", auth->type);
        return -1;
    } while (0);

    while (options)
    {
        if (strcmp (options->name, "allow_duplicate_users") == 0)
            auth->flags |= atoi (options->value) ? AUTH_ALLOW_LISTENER_DUP : 0;
        else if (strcmp(options->name, "realm") == 0)
            auth->realm = (char*)xmlStrdup (XMLSTR(options->value));
        else if (strcmp(options->name, "drop_existing_listener") == 0)
            auth->flags |= atoi (options->value) ? AUTH_DEL_EXISTING_LISTENER : 0;
        else if (strcmp (options->name, "rejected_mount") == 0)
            auth->rejected_mount = (char*)xmlStrdup (XMLSTR(options->value));
        else if (strcmp(options->name, "handlers") == 0)
            auth->handlers = atoi (options->value);
        options = options->next;
    }
    if (auth->handlers < 1) auth->handlers = 3;
    if (auth->handlers > 100) auth->handlers = 100;
    return 0;
}


int auth_get_authenticator (auth_t *auth, config_options_t *options)
{
    thread_mutex_create (&auth->lock);
    auth->refcount = 1;
    if (get_authenticator (auth, options) < 0)
        return -1;
    auth->tailp = &auth->head;

    /* allocate for N threads */
    auth->handles = calloc (auth->handlers, sizeof (auth_thread_t));
    auth->flags |= (AUTH_RUNNING|AUTH_CLEAN_ENV);
    for (int i=0; i<auth->handlers; i++)
    {
        auth->handles[i].id = thread_id++;
        auth->handles[i].auth = auth;
    }
    return 0;
}


/* Called when a source client connects and requires authentication via the
 * authenticator. This is called for both source clients and admin requests
 * that work on a specified mountpoint.
 */
int auth_stream_authenticate (client_t *client, const char *mount, mount_proxy *mountinfo)
{
    if (mountinfo && mountinfo->auth && mountinfo->auth->stream_auth)
    {
        auth_client *auth_user = auth_client_setup (mount, client);

        auth_user->process = stream_auth_callback;
        INFO1 ("request source auth for \"%s\"", mount);
        queue_auth_client (auth_user, mountinfo);
        return 1;
    }
    return 0;
}


/* called when the stream starts, so that authentication engine can do any
 * cleanup/initialisation.
 */
void auth_stream_start (mount_proxy *mountinfo, source_t *source)
{
    if (mountinfo && mountinfo->auth && mountinfo->auth->stream_start)
    {
        client_t *client = source->client;
        const char *agent = httpp_getvar (client->parser, "user-agent"),
                   *mount = source->mount;
        auth_client *auth_user = auth_client_setup (mount, NULL);

        auth_user->process = stream_start_callback;

        // use a blank client copy to avoid a race as slower callbacks could occur
        // after a short lived source.
        auth_user->client = calloc (1, sizeof (client_t));
        auth_user->client->connection.ip = strdup (client->connection.ip);
        if (agent)
            auth_user->client->shared_data = strdup (agent);
        INFO1 ("request stream startup for \"%s\"", mount);

        queue_auth_client (auth_user, mountinfo);
    }
}


/* Called when the stream ends so that the authentication engine can do
 * any authentication cleanup
 */
void auth_stream_end (mount_proxy *mountinfo, source_t *source)
{
    if (mountinfo && mountinfo->auth && mountinfo->auth->stream_end)
    {
        client_t *client = source->client;
        const char *agent = httpp_getvar (client->parser, "user-agent"),
                           *mount = source->mount;
        auth_client *auth_user = auth_client_setup (mount, NULL);

        // use a blank client copy to avoid a race
        auth_user->client = calloc (1, sizeof (client_t));
        auth_user->client->connection.ip = strdup (client->connection.ip);
        if (agent)
            auth_user->client->shared_data = strdup (agent);
        auth_user->process = stream_end_callback;
        INFO1 ("request stream end for \"%s\"", mount);

        queue_auth_client (auth_user, mountinfo);
    }
}


/* return -1 for failed, 0 for authenticated, 1 for pending
 */
int auth_check_source (client_t *client, const char *mount)
{
    ice_config_t *config = config_get_config();
    char *pass = config->source_password;
    char *user = "source";
    int ret = -1;
    mount_proxy *mountinfo = config_find_mount (config, mount);

    do
    {
        if (mountinfo)
        {
            ret = 1;
            if (mountinfo->hijack)
                client->flags |= CLIENT_HIJACKER;
            if (auth_stream_authenticate (client, mount, mountinfo) > 0)
                break;
            ret = -1;
            if (mountinfo->password)
                pass = mountinfo->password;
            if (mountinfo->username && client->server_conn->shoutcast_compat == 0)
                user = mountinfo->username;
        }
        if (connection_check_pass (client->parser, user, pass) > 0)
            ret = 0;
    } while (0);
    config_release_config();
    return ret;
}


int auth_finish_setup (auth_t *auth, const char *name)
{
    auth->mount = strdup (name);
    return get_authenticator (auth, NULL);
}


/* these are called at server start and termination */

void auth_initialise (void)
{
    thread_rwlock_create (&auth_lock);
    thread_id = 0;
    allow_auth = 1;
}

void auth_shutdown (void)
{
    if (allow_auth == 0)
        return;
    allow_auth = 0;
    thread_rwlock_wlock (&auth_lock);
    thread_rwlock_unlock (&auth_lock);
    thread_rwlock_destroy (&auth_lock);
    INFO0 ("Auth shutdown complete");
}

