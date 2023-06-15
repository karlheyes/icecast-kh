/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2022, Karl Heyes <karl@kheyes.plus.com>
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org>,
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

/*
 * Client authentication via URL functions
 *
 * authenticate user via a URL, this is done via libcurl so https can also
 * be handled. The request will have POST information about the request in
 * the form of
 *
 * action=listener_add&client=1&server=host&port=8000&mount=/live&user=fred&pass=mypass&ip=127.0.0.1&agent=""
 *
 * For a user to be accecpted the following HTTP header needs
 * to be returned (the actual string can be specified in the xml file)
 *
 * icecast-auth-user: 1
 *
 * A listening client may also be configured as only to stay connected for a
 * certain length of time. eg The auth server may only allow a 15 minute
 * playback by sending back.
 *
 * icecast-auth-timelimit: 900
 *
 * A listening client may be a slave relay and as such you may want it to avoid
 * certain checks like max listeners. Send this header back if to wish icecast
 * to treat the client as a slave relay.
 *
 * icecast-slave: 1
 *
 * On client disconnection another request can be sent to a URL with the POST
 * information of
 *
 * action=listener_remove&server=host&port=8000&client=1&mount=/live&user=fred&pass=mypass&ip=127.0.0.1&duration=3600
 *
 * client refers to the icecast client identification number. mount refers
 * to the mountpoint (beginning with / and may contain query parameters eg ?&
 * encoded) and duration is the amount of time in seconds. user and pass
 * setting can be blank
 *
 * On stream start and end, another url can be issued to help clear any user
 * info stored at the auth server. Useful for abnormal outage/termination
 * cases.
 *
 * action=mount_add&mount=/live&server=myserver.com&port=8000
 * action=mount_remove&mount=/live&server=myserver.com&port=8000
 *
 * On source client connection, a request can be made to trigger a URL request
 * to verify the details externally. Post info is
 *
 * action=stream_auth&mount=/stream&ip=IP&server=SERVER&port=8000&user=fred&pass=pass
 *
 * As admin requests can come in for a stream (eg metadata update) these requests
 * can be issued while stream is active. For these &admin=1 is added to the POST
 * details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>

#include "curl_ice.h"
#include "auth.h"
#include "source.h"
#include "client.h"
#include "cfgfile.h"
#include "httpp/httpp.h"
#include "timing/timing.h"
#include "mpeg.h"
#include "global.h"
#include "stats.h"

#include "logging.h"
#define CATMODULE "auth_url"

#ifdef HAVE_CURL
typedef struct
{
    int id;
    CURL *curl;
    char *server_id;
    char *location;
    char errormsg [CURL_ERROR_SIZE];
} auth_thread_data;

typedef struct _url_settings_t
{
    char *url;
    time_t stop_until;
    uint16_t timeout;
    uint16_t stop_duration;
} req_settings_t;


typedef struct {
    char *username;
    char *password;
    char *auth_header;
    char *timelimit_header;
    int  auth_header_len;
    int  timelimit_header_len;
    char *userpwd;
    int  header_chk_count;
    int  redir_limit;

    req_settings_t listener_add;
    req_settings_t listener_remove;
    req_settings_t mount_add;
    req_settings_t mount_remove;
    req_settings_t stream_auth;

    char *header_chk_list;      // nulld headers to pass from client into addurl.
    char *header_chk_prefix;    // prefix for POSTing client headers.
    mutex_t  updating;
} auth_url;


struct build_intro_contents
{
    format_type_t type;
    mpeg_sync sync;
    refbuf_t *head, **tailp;
    size_t intro_len;
};


static void clear_url_settings (req_settings_t *s)
{
    if (s)
    {
        free (s->url);
        s->url = NULL;
    }
}


static void auth_url_clear(auth_t *self)
{
    auth_url *url;

    INFO1 ("Doing auth URL cleanup for %s", self->mount);
    url = self->state;
    self->state = NULL;
    free (url->username);
    free (url->password);
    clear_url_settings (&url->listener_add);
    clear_url_settings (&url->listener_remove);
    clear_url_settings (&url->mount_add);
    clear_url_settings (&url->mount_remove);
    clear_url_settings (&url->stream_auth);
    thread_mutex_destroy (&url->updating);
    free (url->auth_header);
    free (url->timelimit_header);
    free (url->userpwd);
    free (url->header_chk_list);
    free (url->header_chk_prefix);
    free (url);
}


#ifdef CURLOPT_PASSWDFUNCTION
/* make sure that prompting at the console does not occur */
static int my_getpass(void *client, char *prompt, char *buffer, int buflen)
{
    buffer[0] = '\0';
    return 0;
}
#endif


static CURLcode do_curl_perform (CURL *curl, auth_client *auth_user, const char *msg)
{
    uint64_t start = timing_get_time ();
    CURLcode c = curl_easy_perform (curl);
    if (c == CURLE_OK)
    {
        uint64_t dura = timing_get_time () - start;
        if (dura > 3000)
            WARN4 ("slow %s response for client %" PRI_ConnID " (%s), %" PRIu64 "ms", msg,
                    CONN_ID(auth_user->client), CONN_ADDR(auth_user->client), dura);
    }
    return c;
}


static size_t handle_url_header (void *ptr, size_t size, size_t nmemb, void *stream)
{
    auth_client *auth_user = stream;
    unsigned bytes = size * nmemb;
    client_t *client = auth_user->client;
    auth_thread_data *atd = auth_user->thread_data;
    char *header = (char *)ptr, *header_val;

    do
    {
        if (bytes <= 1 || client == NULL || client->respcode || auth_user->state == 2)
            break;
        auth_t *auth = auth_user->auth;
        auth_url *url = auth->state;
        int retcode = 0, header_len, header_value_pos;
        unsigned int remain = bytes;

        if (auth_user->state == 0)      // First header expected
        {
            int msgpos = 0, pos = bytes;
            char line [bytes+1];
            sscanf (header, "%[^\r\n]", line);    // make sure with have a nul char for parsing

            if (sscanf (line, "HTTP%*[^ ] %3d %n%*[^\r]%n", &retcode, &msgpos, &pos) == 1)
            {
                if (retcode == 403)
                {
                    int msglen = pos - msgpos;
                    snprintf (atd->errormsg, sizeof(atd->errormsg), "%.*s", msglen, header+msgpos);
                }
                else if ((auth->flags & AUTH_SKIP_IF_SLOW) && retcode >= 400 && retcode < 600)
                {
                    /* prevent further attempts for a while */
                    snprintf (atd->errormsg, sizeof(atd->errormsg), "auth on %s disabled, response was \'%.200s...\'", auth->mount, header);
                    auth_user->flags |= CLIENT_AUTHENTICATED;
                    return 0;
                }
            }
            auth_user->state++;
            break;
        }
        if (bytes == 2 && memcmp (header, "\r\n", 2) == 0)
        {
            auth_user->state++;
            break;       // blank line check
        }

        header_val = memchr (header, ':', bytes);
        if (header_val == NULL)
            return 0;
        header_len = header_val - header;
        header_value_pos = header_len;
        header_value_pos++;
        while (header_value_pos < bytes && isblank (header [header_value_pos]))
            header_value_pos++;
        if (header_value_pos == bytes) break;     // EOL
        header_val = header + header_value_pos;
        remain = bytes - header_value_pos;
        if (remain > 8192)
            return 0;
        char hvalue [remain];
        sscanf (header_val, "%[^\r\n]", hvalue); // local copy with nul, no EOL

        if (strncasecmp (header, url->auth_header, url->auth_header_len) == 0)
        {
            auth_user->flags |= CLIENT_AUTHENTICATED;
            if (remain >= 9 && strncasecmp (hvalue, "withintro", 9) == 0)
                auth_user->flags |= CLIENT_HAS_INTRO_CONTENT;
            if (remain > 5 && strncasecmp (hvalue, "hijack", 6) == 0)
                auth_user->flags |= CLIENT_HIJACKER;
            if (remain > 0 && strncmp (hvalue, "0", 1) == 0)
            {
                WARN0 ("auth header returned with 0 value");
                auth_user->flags &= ~CLIENT_AUTHENTICATED;
            }
            break;
        }
        if (strncasecmp (header, url->timelimit_header, url->timelimit_header_len) == 0)
        {
            unsigned int limit = 60;
            sscanf (hvalue, "%u", &limit);
            client->connection.discon.time = time(NULL) + limit;
            break;
        }
        if (strncasecmp (header, "icecast-slave:", 14) == 0)
        {
            auth_user->flags |= CLIENT_IS_SLAVE;
            break;
        }

        if (strncasecmp (header, "icecast-auth-message:", 21) == 0)
        {
            snprintf (atd->errormsg, sizeof (atd->errormsg), "%s", hvalue);
            break;
        }
        if (strncasecmp (header, "ice-username:", 13) == 0)
        {
            free (client->username);
            client->username = strdup (hvalue);
            break;
        }
        if (strncasecmp (header, "Location:", 9) == 0)
        {
            free (atd->location);
            atd->location = strdup (hvalue);
            break;
        }
        if (strncasecmp (header, "Mountpoint:", 11) == 0)
        {
            free (auth_user->mount);
            auth_user->mount = strdup (hvalue);
            break;
        }
        if (strncasecmp (header, "content-type:", 13) == 0)
        {
            format_type_t type = format_get_type (hvalue);

            if (client->aux_data && (type == FORMAT_TYPE_AAC || type == FORMAT_TYPE_MPEG))
            {
                struct build_intro_contents *x = (struct build_intro_contents*)client->aux_data;
                x->type = type;
                mpeg_setup (&x->sync, client->connection.ip);
            }
            break;
        }
    } while (0);

    return (int)bytes;
}



static size_t handle_url_data (void *ptr, size_t size, size_t nmemb, void *stream)
{
    auth_client *auth_user = stream;
    unsigned bytes = size * nmemb;
    client_t *client = auth_user->client;

    if (client && client->respcode == 0 && (auth_user->flags & CLIENT_HAS_INTRO_CONTENT))
    {
        refbuf_t *n;
        struct build_intro_contents *x = (struct build_intro_contents*)client->aux_data;

        n = refbuf_new (bytes);
        memcpy (n->data, ptr, bytes);
        if (x->type)
        {
            int unprocessed = mpeg_complete_frames (&x->sync, n, 0);
            if (unprocessed < 0)
            {
                mpeg_data_insert (&x->sync, n); /* maybe short read, less than frame */
                return (int)(bytes);
            }
            if (unprocessed > 0)
            {
                if (mpeg_block_expanded (&x->sync))
                {
                    n->len = unprocessed;
                    mpeg_data_insert (&x->sync, n);
                    return (int)(bytes);
                }
                refbuf_t *next = refbuf_new (unprocessed);
                memcpy (next->data, n->data + n->len, unprocessed);
                next->len = unprocessed;
                mpeg_data_insert (&x->sync, next);
            }
        }
        if (n->len == 0)
            refbuf_release (n);
        else
        {
            *x->tailp = n;
            x->tailp = &n->next;
            x->intro_len += n->len;
        }
    }
    return (int)(bytes);
}


static auth_result url_remove_listener (auth_client *auth_user)
{
    client_t *client = auth_user->client;
    auth_url *url = auth_user->auth->state;
    auth_thread_data *atd = auth_user->thread_data;
    time_t now = time(NULL);
    char *userpwd = NULL;

    if (url->listener_remove.url == NULL || client == NULL)
        return AUTH_OK;
    time_t duration = client->connection.discon.time - client->connection.con_time;
    thread_mutex_lock (&url->updating);
    do
    {
        if (url->listener_remove.stop_until < now)
        {
            if (url->listener_remove.stop_until)
                url->listener_remove.stop_until = (time_t)0;
            break;
        }
        thread_mutex_unlock (&url->updating);
        WARN3 ("auth on %s disabled (client %" PRI_ConnID", handler %d)", auth_user->mount, CONN_ID(client), auth_user->handler);
        return AUTH_FAILED;
    } while (0);
    thread_mutex_unlock (&url->updating);

    ice_params_t post;
    ice_params_setup (&post, "=", "&", PARAMS_ESC);
    ice_params_printf (&post, "action", PARAM_AS,       "listener_remove");
    ice_params_printf (&post, "server", 0,              "%s", auth_user->hostname);
    ice_params_printf (&post, "port",   PARAM_AS,       "%d", auth_user->port);
    ice_params_printf (&post, "client", PARAM_AS,       "%" PRIu64, client->connection.id);

    ice_params_printf (&post, "mount",  0,              "%s", auth_user->mount);
    ice_params_printf (&post, "user",   0,              "%s", (client->username ? client->username : ""));
    ice_params_printf (&post, "pass",   0,              "%s", (client->password ? client->password : ""));
    ice_params_printf (&post, "ip",     0,              "%s", &client->connection.ip[0]);
    ice_params_printf (&post, "duration", PARAM_AS,     "%" PRIu64, (uint64_t)duration);
    ice_params_printf (&post, "agent",  0,              "%s", httpp_getvar (client->parser, "user-agent"));
    ice_params_printf (&post, "sent",   PARAM_AS,       "%" PRIu64, client->connection.sent_bytes);
    refbuf_t *rb = ice_params_complete (&post);
    if (rb == NULL) return AUTH_FAILED;

    if (strchr (url->listener_remove.url, '@') == NULL)
    {
        if (url->userpwd)
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, url->userpwd);
        else
        {
            /* auth'd requests may not have a user/pass, but may use query args */
            if (client->username && client->password)
            {
                int len = strlen (client->username) + strlen (client->password) + 2;
                userpwd = malloc (len);
                snprintf (userpwd, len, "%s:%s", client->username, client->password);
                curl_easy_setopt (atd->curl, CURLOPT_USERPWD, userpwd);
            }
            else
                curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
        }
    }
    else
    {
        /* url has user/pass but libcurl may need to clear any existing settings */
        curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    }
    curl_easy_setopt (atd->curl, CURLOPT_URL, url->listener_remove.url);
    curl_easy_setopt (atd->curl, CURLOPT_POSTFIELDS, rb->data);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEHEADER, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEDATA, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_TIMEOUT, (long)url->listener_remove.timeout);
    char msg [120];
    snprintf (msg, sizeof msg, ", listener remove %s, client %" PRI_ConnID ", handler %d",
            CONN_ADDR (client), CONN_ID(client), auth_user->handler);
#if LIBCURL_VERSION_NUM >= 0x072000
    curl_easy_setopt (atd->curl, CURLOPT_XFERINFODATA, msg);
#endif

    DEBUG3 ("...handler %d (%s) sending request (client %" PRI_ConnID ")", auth_user->handler, auth_user->mount, CONN_ID(client));
    if (do_curl_perform (atd->curl, auth_user, "listener remove"))
    {
        thread_mutex_lock (&url->updating);
        if (url->listener_remove.stop_until == 0)
            url->listener_remove.stop_until = time (NULL) + url->listener_remove.stop_duration;
        thread_mutex_unlock (&url->updating);
        WARN4 ("auth on %s failed with \"%s\"%s, stop %ds", auth_user->mount, atd->errormsg, msg, url->listener_remove.stop_duration);
    }
    else
        DEBUG3 ("...handler %d (%s) request complete (client %" PRI_ConnID ")", auth_user->handler, auth_user->mount, CONN_ID(client));

    free (userpwd);
    refbuf_release (rb);

    return AUTH_OK;
}


static auth_result url_add_listener (auth_client *auth_user)
{
    client_t *client = auth_user->client;
    auth_t *auth = auth_user->auth;
    auth_url *url = auth->state;
    auth_thread_data *atd = auth_user->thread_data;

    int res = 0, ret = AUTH_FAILED;
    char *userpwd = NULL;

    client_set_queue (client, NULL);
    if (url->listener_add.url == NULL || client == NULL)
        return AUTH_OK;

    thread_mutex_lock (&url->updating);
    if (url->listener_add.stop_until)
    {
        time_t now = time(NULL);
        if (url->listener_add.stop_until > now)
        {
            thread_mutex_unlock (&url->updating);
            if (auth->flags & AUTH_SKIP_IF_SLOW)
            {
                DEBUG3 ("auth on %s stopped, skipping for client %" PRI_ConnID " (handler %d)", auth_user->mount, CONN_ID(client), auth_user->handler);
                client->flags |= CLIENT_AUTHENTICATED;
                return AUTH_OK;
            }
            WARN3 ("auth on %s stopped, drop client %" PRI_ConnID " (handler %d)", auth_user->mount, CONN_ID(client), auth_user->handler);
            return AUTH_FAILED;
        }
        res = 1;
        url->listener_add.stop_until = 0;
    }
    thread_mutex_unlock (&url->updating);
    if (res)
        INFO2 ("restarting auth after timeout on %s, with client %" PRI_ConnID, auth_user->mount, CONN_ID(client));

    ice_params_t post;
    ice_params_setup (&post, "=", "&", PARAMS_ESC);
    ice_params_printf (&post, "action", PARAM_AS,       "listener_add");
    ice_params_printf (&post, "port",   PARAM_AS,       "%d", auth_user->port);
    ice_params_printf (&post, "client", PARAM_AS,       "%" PRIu64, client->connection.id);
    ice_params_printf (&post, "server", 0,              "%s", auth_user->hostname);

    const char *tmp = httpp_getvar (client->parser, HTTPP_VAR_QUERYARGS);
    ice_params_printf (&post, "mount",  0,      "%s%s", auth_user->mount, (tmp ? tmp : ""));
    ice_params_printf (&post, "user",   0,      "%s",   (client->username ? client->username : ""));
    ice_params_printf (&post, "pass",   0,      "%s",   (client->password ? client->password : ""));
    ice_params_printf (&post, "ip",     0,      "%s",   &client->connection.ip[0]);
    ice_params_printf (&post, "agent",  0,      "%s",   httpp_getvar (client->parser, "user-agent"));

    tmp = httpp_getvar (client->parser, "referer");
    ice_params_printf (&post, "referer", 0,     "%s", (tmp ? tmp : ""));

    char *listeners = stats_get_value (auth_user->mount, "listeners");
    ice_params_printf (&post, "listeners", PARAM_AS,    "%s", (listeners ? listeners : ""));
    free (listeners);

    char *cur_header = url->header_chk_list;
    for (int c = url->header_chk_count; c && cur_header[0]; c--)
    {
        const char *val = httpp_getvar (client->parser, cur_header);
        if (val)
        {
            char name[200];
            int r = snprintf (name, sizeof name, "%s%s", url->header_chk_prefix, cur_header);
            if (r > 0 && r < sizeof name)
                ice_params_printf (&post, name, 0, "%s", val);
        }
        cur_header += (strlen(cur_header) + 1); // get past next nul
    }
    refbuf_t *rb = ice_params_complete (&post);
    if (rb == NULL) return AUTH_FAILED;

    if (strchr (url->listener_add.url, '@') == NULL)
    {
        if (url->userpwd)
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, url->userpwd);
        else
        {
            /* auth'd requests may not have a user/pass, but may use query args */
            if (client->username && client->password)
            {
                int len = strlen (client->username) + strlen (client->password) + 2;
                userpwd = malloc (len);
                snprintf (userpwd, len, "%s:%s", client->username, client->password);
                curl_easy_setopt (atd->curl, CURLOPT_USERPWD, userpwd);
            }
            else
                curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
        }
    }
    else
    {
        /* url has user/pass but libcurl may need to clear any existing settings */
        curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    }
    curl_easy_setopt (atd->curl, CURLOPT_URL, url->listener_add.url);
    curl_easy_setopt (atd->curl, CURLOPT_POSTFIELDS, rb->data);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEHEADER, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEDATA, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_TIMEOUT, (long)url->listener_add.timeout);
#if LIBCURL_VERSION_NUM >= 0x072000
    char msg [100];
    snprintf (msg, sizeof msg, ", listener add on %s", &client->connection.ip[0]);
    curl_easy_setopt (atd->curl, CURLOPT_XFERINFODATA, msg);
#endif
    atd->errormsg[0] = '\0';
    free (atd->location);
    atd->location = NULL;
    /* setup in case intro data is returned */
    struct build_intro_contents intro = { .type = 0, .head = NULL, .intro_len = 0, .tailp = &intro.head }, *x = &intro;
    client->aux_data = (uintptr_t)&intro;

    DEBUG3 ("handler %d (%s) sending request (client %" PRI_ConnID ")", auth_user->handler, auth_user->mount, CONN_ID(client));
    res = do_curl_perform (atd->curl, auth_user, "listener add");
    DEBUG3 ("handler %d (%s) request finished (client %" PRI_ConnID ")", auth_user->handler, auth_user->mount, CONN_ID(client));
    client->aux_data = (uintptr_t)0;

    free (userpwd);
    refbuf_release (rb);

    if (auth_user->flags & CLIENT_AUTHENTICATED)
    {
        if (auth_user->flags & CLIENT_HAS_INTRO_CONTENT)
        {
            if (client->refbuf)
                client->refbuf->next = x->head;
            else
                client->refbuf = x->head;
            DEBUG3 ("intro (%d) received %lu for %s", x->type, (unsigned long)x->intro_len, client->connection.ip);
        }
        if (x->head == NULL)
            auth_user->flags &= ~CLIENT_HAS_INTRO_CONTENT;
        x->head = NULL;
        ret = AUTH_OK;
    }
    if (res)
    {
        thread_mutex_lock (&url->updating);
        if (url->listener_add.stop_until == 0)
            url->listener_add.stop_until = time (NULL) + url->listener_add.stop_duration;
        thread_mutex_unlock (&url->updating);
        WARN4 ("auth %s (%s) failed with %s, disable for %d seconds", url->listener_add.url,
                auth_user->mount, atd->errormsg, url->listener_add.stop_duration);
        if (auth->flags & AUTH_SKIP_IF_SLOW)
        {
            auth_user->flags |= CLIENT_AUTHENTICATED;
            ret = AUTH_OK;
        }
    }
    /* better cleanup memory */
    while (x->head)
    {
        refbuf_t *n = x->head;
        x->head = n->next;
        n->next = NULL;
        refbuf_release (n);
    }
    if (x->type)
        mpeg_cleanup (&x->sync);
    if (atd->location)
    {
        client_send_302 (client, atd->location);
        auth_user->client = NULL;
        free (atd->location);
        atd->location = NULL;
    }
    else if (atd->errormsg[0])
    {
        INFO3 ("listener %s (%s) returned \"%s\"", client->connection.ip, url->listener_add.url, atd->errormsg);
        if (atoi (atd->errormsg) == 403)
        {
            auth_user->client = NULL;
            client_send_403 (client, atd->errormsg+4);
        }
    }
    return ret;
}


/* called by auth thread when a source starts, the client in this case is a dummy
 * one with just copies of data.
 */
static void url_stream_start (auth_client *auth_user)
{
    client_t *client = auth_user->client;
    auth_url *url = auth_user->auth->state;
    auth_thread_data *atd = auth_user->thread_data;

    ice_params_t post;
    ice_params_setup (&post, "=", "&", PARAMS_ESC);
    ice_params_printf (&post, "action", 0,              "mount_add");
    ice_params_printf (&post, "mount",  0,              "%s",   auth_user->mount);
    ice_params_printf (&post, "server", 0,              "%s",   auth_user->hostname);
    ice_params_printf (&post, "port",   PARAM_AS,       "%d",   auth_user->port);
    ice_params_printf (&post, "ip",     0,              "%s",   &client->connection.ip[0]);
    ice_params_printf (&post, "agent",  0,              "%s",   client->aux_data ? (char*)client->aux_data : "");
    refbuf_t *rb = ice_params_complete (&post);
    if (rb == NULL) return;

    if (strchr (url->mount_add.url, '@') == NULL)
    {
        if (url->userpwd)
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, url->userpwd);
        else
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    }
    else
        curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    curl_easy_setopt (atd->curl, CURLOPT_URL, url->mount_add.url);
    curl_easy_setopt (atd->curl, CURLOPT_POSTFIELDS, rb->data);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEHEADER, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEDATA, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_TIMEOUT, (long)url->mount_add.timeout);

    DEBUG2 ("handler %d (%s) sending request", auth_user->handler, auth_user->mount);
    if (curl_easy_perform (atd->curl))
        WARN3 ("auth on %s failed with %s (handler %d)", auth_user->mount, atd->errormsg, auth_user->handler);
    else
        DEBUG2 ("handler %d (%s) request finished", auth_user->handler, auth_user->mount);
    refbuf_release (rb);
}


static void url_stream_end (auth_client *auth_user)
{
    client_t *client = auth_user->client;
    auth_url *url = auth_user->auth->state;
    auth_thread_data *atd = auth_user->thread_data;

    ice_params_t post;
    ice_params_setup (&post, "=", "&", PARAMS_ESC);
    ice_params_printf (&post, "action", 0,      "mount_remove");
    ice_params_printf (&post, "mount",  0,      "%s",   auth_user->mount);
    ice_params_printf (&post, "server", 0,      "%s",   auth_user->hostname);
    ice_params_printf (&post, "port",   0,      "%d",   auth_user->port);
    ice_params_printf (&post, "ip",     0,      "%s",   &client->connection.ip[0]);
    ice_params_printf (&post, "agent",  0,      "%s",   client->aux_data ? (char*)client->aux_data : "");
    refbuf_t *rb = ice_params_complete (&post);
    if (rb == NULL) return;

    if (strchr (url->mount_remove.url, '@') == NULL)
    {
        if (url->userpwd)
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, url->userpwd);
        else
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    }
    else
        curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    curl_easy_setopt (atd->curl, CURLOPT_URL, url->mount_remove.url);
    curl_easy_setopt (atd->curl, CURLOPT_POSTFIELDS, rb->data);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEHEADER, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEDATA, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_TIMEOUT, (long)url->mount_remove.timeout);

    DEBUG2 ("handler %d (%s) sending request", auth_user->handler, auth_user->mount);
    if (curl_easy_perform (atd->curl))
        WARN3 ("auth on %s failed with %s (handler %d)", auth_user->mount, atd->errormsg, auth_user->handler);
    else
        DEBUG2 ("handler %d (%s) request finished", auth_user->handler, auth_user->mount);
    refbuf_release (rb);
}


static void url_stream_auth (auth_client *auth_user)
{
    client_t *client = auth_user->client;
    auth_url *url = auth_user->auth->state;
    auth_thread_data *atd = auth_user->thread_data;
    int adm = 0;

    if (strchr (url->stream_auth.url, '@') == NULL)
    {
        if (url->userpwd)
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, url->userpwd);
        else
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    }
    else
        curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    curl_easy_setopt (atd->curl, CURLOPT_URL, url->stream_auth.url);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEHEADER, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEDATA, auth_user);

    ice_params_t post;
    ice_params_setup (&post, "=", "&", PARAMS_ESC);
    ice_params_printf (&post, "action", 0,      "stream_auth");
    ice_params_printf (&post, "mount",  0,      "%s",   auth_user->mount);
    ice_params_printf (&post, "server", 0,      "%s",   auth_user->hostname);
    ice_params_printf (&post, "port",   PARAM_AS,  "%d",   auth_user->port);
    ice_params_printf (&post, "ip",     0,      "%s",   &client->connection.ip[0]);
    ice_params_printf (&post, "user",   0,      "%s",   (client->username ? client->username : ""));
    ice_params_printf (&post, "pass",   0,      "%s",   (client->password ? client->password : ""));
    if (strcmp (auth_user->mount, httpp_getvar (client->parser, HTTPP_VAR_URI)) != 0)
        adm = ice_params_printf (&post, "admin", PARAM_AS,  "1") < 0 ? 0 : 1;
    refbuf_t *rb = ice_params_complete (&post);
    if (rb == NULL) return;

    curl_easy_setopt (atd->curl, CURLOPT_POSTFIELDS, rb->data);
    curl_easy_setopt (atd->curl, CURLOPT_TIMEOUT, (long)url->stream_auth.timeout);
    auth_user->flags &= ~CLIENT_AUTHENTICATED;
    DEBUG3 ("handler %d (%s) sending request (adm %d)", auth_user->handler, auth_user->mount, adm);
    if (curl_easy_perform (atd->curl))
        WARN4 ("auth on %s failed with %s (client %" PRI_ConnID ", handler %d)", auth_user->mount, atd->errormsg, CONN_ID (client), auth_user->handler);
    else
        DEBUG3 ("handler %d (%s) request finished (client %" PRI_ConnID ")", auth_user->handler, auth_user->mount, CONN_ID (client));
    refbuf_release (rb);
}


static auth_result auth_url_adduser(auth_t *auth, const char *username, const char *password)
{
    return AUTH_FAILED;
}

static auth_result auth_url_deleteuser (auth_t *auth, const char *username)
{
    return AUTH_FAILED;
}

static auth_result auth_url_listuser (auth_t *auth, xmlNodePtr srcnode)
{
    return AUTH_FAILED;
}

/* This is called with the config lock held */
static void *alloc_thread_data (auth_t *auth)
{
    auth_thread_data *atd = calloc (1, sizeof (auth_thread_data));
    ice_config_t *config = config_get_config_unlocked();
    auth_url *url = auth->state;
    atd->server_id = strdup (config->server_id);

    atd->curl = icecurl_easy_init ();
    curl_easy_setopt (atd->curl, CURLOPT_USERAGENT, atd->server_id);
    curl_easy_setopt (atd->curl, CURLOPT_HEADERFUNCTION, handle_url_header);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEFUNCTION, handle_url_data);
    curl_easy_setopt (atd->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt (atd->curl, CURLOPT_TIMEOUT, (long)6); // a default
    curl_easy_setopt (atd->curl, CURLOPT_ERRORBUFFER, &atd->errormsg[0]);
    curl_easy_setopt (atd->curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt (atd->curl, CURLOPT_MAXREDIRS, (long)url->redir_limit);
#ifdef CURLOPT_POSTREDIR
    curl_easy_setopt (atd->curl, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);
#endif
    if (auth->flags & AUTH_SKIP_IF_SLOW)
        curl_easy_setopt (atd->curl, CURLOPT_SSL_VERIFYPEER, 0L);
    return atd;
}


static void release_thread_data (auth_t *auth, void *thread_data)
{
    auth_thread_data *atd = thread_data;
    if (atd)
    {
        curl_easy_cleanup (atd->curl);
        free (atd->server_id);
        free (atd);
    }
}
#endif // HAVE_CURL


int auth_get_url_auth (auth_t *authenticator, config_options_t *options)
{
#ifdef HAVE_CURL
    auth_url *url_info;
    if (authenticator->state)
    {
        url_info = authenticator->state;
        INFO3 ("Timeout %ds (disabled %ds), max redirects %d", url_info->listener_add.timeout,
                url_info->listener_add.stop_duration, url_info->redir_limit);
        if (url_info->listener_add.url)
            INFO1 ("listener add set to %s", url_info->listener_add.url);
        if (url_info->listener_remove.url)
            INFO1 ("listener remove set to %s", url_info->listener_remove.url);
        if (url_info->mount_add.url)
            INFO1 ("mount add set to %s", url_info->mount_add.url);
        if (url_info->mount_remove.url)
            INFO1 ("mount remove set to %s", url_info->mount_remove.url);
        if (url_info->stream_auth.url)
            INFO1 ("stream_auth set to %s", url_info->stream_auth.url);
        INFO1 ("header to auth %s", url_info->auth_header);
        INFO1 ("timelimit header %s", url_info->timelimit_header);
        INFO1 ("client header prefix for POST %s", url_info->header_chk_prefix);
        return 0;
    }
    char *pass_headers = NULL;

    authenticator->release = auth_url_clear;
    authenticator->adduser = auth_url_adduser;
    authenticator->deleteuser = auth_url_deleteuser;
    authenticator->listuser = auth_url_listuser;
    authenticator->alloc_thread_data = alloc_thread_data;
    authenticator->release_thread_data = release_thread_data;

    url_info = calloc(1, sizeof(auth_url));
    url_info->auth_header = strdup ("icecast-auth-user:");
    url_info->timelimit_header = strdup ("icecast-auth-timelimit:");
    url_info->header_chk_prefix = strdup ("ClientHeader-");
    url_info->redir_limit = 1;
    thread_mutex_create (&url_info->updating);

    req_settings_t req_templ = { .timeout = 6, .stop_duration = 30 };

    while (options)
    {
        if(!strcmp(options->name, "username"))
        {
            free (url_info->username);
            url_info->username = strdup (options->value);
        }
        if(!strcmp(options->name, "password"))
        {
            free (url_info->password);
            url_info->password = strdup (options->value);
        }
        if(!strcmp(options->name, "headers"))
        {
            free (pass_headers);
            pass_headers = strdup (options->value);
        }
        if(!strcmp(options->name, "header_prefix"))
        {
            free (url_info->header_chk_prefix);
            url_info->header_chk_prefix = strdup (options->value);
        }
        if(!strcmp(options->name, "listener_add"))
        {
            authenticator->authenticate = url_add_listener;
            clear_url_settings (&url_info->listener_add);
            url_info->listener_add.url = options->value;
        }
        if(!strcmp(options->name, "listener_remove"))
        {
            authenticator->release_listener = url_remove_listener;
            clear_url_settings (&url_info->listener_remove);
            url_info->listener_remove.url = options->value;
        }
        if(!strcmp(options->name, "mount_add"))
        {
            authenticator->stream_start = url_stream_start;
            clear_url_settings (&url_info->mount_add);
            url_info->mount_add.url = options->value;
        }
        if(!strcmp(options->name, "mount_remove"))
        {
            authenticator->stream_end = url_stream_end;
            clear_url_settings (&url_info->mount_remove);
            url_info->mount_remove.url = options->value;
        }
        if(!strcmp(options->name, "stream_auth"))
        {
            authenticator->stream_auth = url_stream_auth;
            clear_url_settings (&url_info->stream_auth);
            url_info->stream_auth.url = options->value;
        }
        if(!strcmp(options->name, "auth_header"))
        {
            free (url_info->auth_header);
            url_info->auth_header = strdup (options->value);
        }
        if (strcmp(options->name, "timelimit_header") == 0)
        {
            free (url_info->timelimit_header);
            url_info->timelimit_header = strdup (options->value);
        }
        if (strcmp(options->name, "redirect_limit") == 0)
        {
            int redir = atoi (options->value);
            // excessive numbers will just be an operational problem, and -1 is indefinite in libcurl (default) so avoid
            url_info->redir_limit = (redir < 11 && redir >= 0) ? redir : 1;
        }
        if (strcmp(options->name, "timeout") == 0)
        {
            int timeout = atoi (options->value);
            req_templ.timeout = timeout > 0 ? timeout : 1;
        }
        if (strcmp(options->name, "on_error_wait") == 0)
        {
            int seconds = atoi (options->value);
            req_templ.stop_duration = seconds > 0 ? seconds : 1;
        }
        if (strcmp(options->name, "presume_innocent") == 0)
        {
            if (strcasecmp (options->value, "yes") == 0)
                authenticator->flags |= AUTH_SKIP_IF_SLOW;
        }
        options = options->next;
    }

    if (url_info->auth_header)
        url_info->auth_header_len = strlen (url_info->auth_header);
    if (url_info->timelimit_header)
        url_info->timelimit_header_len = strlen (url_info->timelimit_header);
    if (url_info->username && url_info->password)
    {
        int len = strlen (url_info->username) + strlen (url_info->password) + 2;
        url_info->userpwd = malloc (len);
        snprintf (url_info->userpwd, len, "%s:%s", url_info->username, url_info->password);
    }
    if (pass_headers)
    {
        char *cur_header = pass_headers;
        while (cur_header)
        {
            char *next_header = strstr (cur_header, ",");
            url_info->header_chk_count++;
            if (next_header)
            {
                *next_header=0;
                next_header++;
            }
            cur_header = next_header;
        }
        if (url_info->header_chk_count)
            url_info->header_chk_list = pass_headers;
        else
            free (pass_headers);
    }
    req_templ.url = url_info->listener_add.url ? strdup (url_info->listener_add.url) : NULL;
    url_info->listener_add = req_templ;

    req_templ.url = url_info->listener_remove.url ? strdup (url_info->listener_remove.url) : NULL;
    url_info->listener_remove = req_templ;

    req_templ.url = url_info->mount_add.url ? strdup (url_info->mount_add.url) : NULL;
    url_info->mount_add = req_templ;

    req_templ.url = url_info->mount_remove.url ? strdup (url_info->mount_remove.url) : NULL;
    url_info->mount_remove = req_templ;

    req_templ.url = url_info->stream_auth.url ? strdup (url_info->stream_auth.url) : NULL;
    url_info->stream_auth = req_templ;

    authenticator->state = url_info;
    return 0;
#else
    ERROR0 ("Auth URL disabled, no libcurl support");
    return -1;
#endif
}

