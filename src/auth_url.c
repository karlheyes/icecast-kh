/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2017, Karl Heyes <karl@kheyes.plus.com>
 *
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

#include <curl/curl.h>

#include "auth.h"
#include "source.h"
#include "client.h"
#include "cfgfile.h"
#include "httpp/httpp.h"
#include "mpeg.h"
#include "global.h"
#include "stats.h"

#include "logging.h"
#define CATMODULE "auth_url"

typedef struct
{
    int id;
    CURL *curl;
    char *server_id;
    char *location;
    char errormsg [CURL_ERROR_SIZE];
} auth_thread_data;

typedef struct {
    time_t stop_req_until;
    int  stop_req_duration;
    int  timeout;
    char *addurl;
    char *removeurl;
    char *stream_start;
    char *stream_end;
    char *stream_auth;
    char *username;
    char *password;
    char *auth_header;
    char *timelimit_header;
    int  auth_header_len;
    int  timelimit_header_len;
    char *userpwd;
    int  header_chk_count;
    char *header_chk_list;      // nulld headers to pass from client into addurl.
    char *header_chk_prefix;    // prefix for POSTing client headers.
} auth_url;


struct build_intro_contents
{
    format_type_t type;
    mpeg_sync sync;
    refbuf_t *head, **tailp;
    size_t intro_len;
};

static void auth_url_clear(auth_t *self)
{
    auth_url *url;

    INFO1 ("Doing auth URL cleanup for %s", self->mount);
    url = self->state;
    self->state = NULL;
    free (url->username);
    free (url->password);
    free (url->removeurl);
    free (url->addurl);
    free (url->stream_start);
    free (url->stream_end);
    free (url->stream_auth);
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


static size_t handle_returned_header (void *ptr, size_t size, size_t nmemb, void *stream)
{
    auth_client *auth_user = stream;
    unsigned bytes = size * nmemb;
    client_t *client = auth_user->client;
    auth_thread_data *atd = auth_user->thread_data;
    char *header = (char *)ptr, *header_data;

    if (bytes <= 1 || client == NULL)
        return bytes;
    do
    {
        auth_t *auth = auth_user->auth;
        auth_url *url = auth->state;
        int retcode = 0, header_datalen;

        /* replace the EOL with a nul char, libcurl may not provide a nul */
        header [bytes-2] = '\0';
        if (sscanf (ptr, "HTTP%*c%*u.%*u %3d %*c", &retcode) == 1)
        {
            if (retcode == 403)
            {
                char *p = strchr (ptr, ' ') + 1;
                snprintf (atd->errormsg, sizeof(atd->errormsg), "%s", p);
                p = strchr (atd->errormsg, '\r');
                if (p) *p='\0';
            }
            else if ((auth->flags & AUTH_SKIP_IF_SLOW) && retcode >= 400 && retcode < 600)
            {
                snprintf (atd->errormsg, sizeof(atd->errormsg), "auth on %s disabled, response was \'%.200s...\'", auth->mount, header);
                url->stop_req_until = time (NULL) + url->stop_req_duration; /* prevent further attempts for a while */
                client->flags |= CLIENT_AUTHENTICATED;
                return bytes;
            }
        }
        header_data = strchr (header, ':');
        if (header_data == NULL)
            return bytes;
        header_data++;
        header_data += strspn (header_data, " \t");  // find non-space start
        header_datalen = strcspn (header_data, "\r\n"); // find length

        if (strncasecmp (header, url->auth_header, url->auth_header_len) == 0)
        {
            client->flags |= CLIENT_AUTHENTICATED;
            if (header_data)
            {
                if (strstr (header_data, "withintro"))
                    client->flags |= CLIENT_HAS_INTRO_CONTENT;
                if (strstr (header_data, "hijack"))
                    client->flags |= CLIENT_HIJACKER;
                if (strstr (header_data, "0"))
                {
                    WARN0 ("auth header returned with 0 value");
                    client->flags &= ~CLIENT_AUTHENTICATED;
                }
            }
            break;
        }
        if (strncasecmp (header, url->timelimit_header, url->timelimit_header_len) == 0)
        {
            unsigned int limit = 60;
            sscanf (header_data, "%u\r\n", &limit);
            client->connection.discon.time = time(NULL) + limit;
            break;
        }
        if (strncasecmp (header, "icecast-slave:", 14) == 0)
        {
            client->flags |= CLIENT_IS_SLAVE;
            break;
        }

        if (strncasecmp (header, "icecast-auth-message:", 21) == 0)
        {
            snprintf (atd->errormsg, sizeof (atd->errormsg), "%.*s", header_datalen, header_data);
            break;
        }
        if (strncasecmp (header, "ice-username:", 13) == 0)
        {
            char *name = malloc (header_datalen+1);
            if (name)
            {
                snprintf (name, header_datalen+1, "%s", header_data);
                free (client->username);
                client->username = name;
            }
            break;
        }
        if (strncasecmp (header, "Location:", 9) == 0)
        {
            free (atd->location);
            atd->location = malloc (header_datalen+1);
            if (atd->location)
                snprintf (atd->location, header_datalen+1, "%s", header_data);
            break;
        }
        if (strncasecmp (header, "Mountpoint:", 11) == 0)
        {
            char *mount = malloc (header_datalen+1);
            if (mount)
            {
                snprintf (mount, header_datalen+1, "%s", header_data);
                free (auth_user->mount);
                auth_user->mount = mount;
            }
            break;
        }
        if (strncasecmp (header, "content-type:", 13) == 0)
        {
            format_type_t type = format_get_type (header_data);

            if (client->refbuf && (type == FORMAT_TYPE_AAC || type == FORMAT_TYPE_MPEG))
            {
                struct build_intro_contents *x = (void*)client->refbuf->data;
                x->type = type;
                mpeg_setup (&x->sync, client->connection.ip);
            }
            break;
        }
    } while (0);

    return (int)bytes;
}



static size_t handle_returned_data (void *ptr, size_t size, size_t nmemb, void *stream)
{
    auth_client *auth_user = stream;
    unsigned bytes = size * nmemb;
    client_t *client = auth_user->client;
    refbuf_t *r = client->refbuf;

    if (client && client->respcode == 0 && r &&
         client->flags & CLIENT_HAS_INTRO_CONTENT)
    {
        refbuf_t *n;
        struct build_intro_contents *x = (void*)r->data;

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
    time_t now = time(NULL), duration = now - client->connection.con_time;
    char *username, *password, *mount, *server, *ipaddr, *user_agent;
    const char *qargs, *tmp;
    char *userpwd = NULL, post [4096];

    if (url->removeurl == NULL || client == NULL)
        return AUTH_OK;
    if (url->stop_req_until)
    {
        if (url->stop_req_until >= now)
            return AUTH_FAILED;
        url->stop_req_until = 0;
    }
    server = util_url_escape (auth_user->hostname);

    if (client->username)
        username = util_url_escape (client->username);
    else
        username = strdup ("");

    if (client->password)
        password = util_url_escape (client->password);
    else
        password = strdup ("");

    tmp = httpp_getvar(client->parser, "user-agent");
    if (tmp == NULL)
        tmp = "-";
    user_agent = util_url_escape (tmp);

    /* get the full uri (with query params if available) */
    qargs = httpp_getvar (client->parser, HTTPP_VAR_QUERYARGS);
    snprintf (post, sizeof post, "%s%s", auth_user->mount, qargs ? qargs : "");
    mount = util_url_escape (post);
    ipaddr = util_url_escape (client->connection.ip);

    snprintf (post, sizeof (post),
            "action=listener_remove&server=%s&port=%d&client=%" PRIu64 "&mount=%s"
            "&user=%s&pass=%s&ip=%s&duration=%lu&agent=%s&sent=%" PRIu64,
            server, auth_user->port, client->connection.id, mount, username,
            password, ipaddr, (long unsigned)duration, user_agent, client->connection.sent_bytes);
    free (ipaddr);
    free (server);
    free (mount);
    free (username);
    free (password);
    free (user_agent);

    if (strchr (url->removeurl, '@') == NULL)
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
    curl_easy_setopt (atd->curl, CURLOPT_URL, url->removeurl);
    curl_easy_setopt (atd->curl, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEHEADER, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEDATA, auth_user);

    DEBUG2 ("...handler %d (%s) sending request", auth_user->handler, auth_user->mount);
    if (curl_easy_perform (atd->curl))
    {
        WARN3 ("auth to server %s (%s) failed with \"%s\"", url->removeurl, auth_user->mount, atd->errormsg);
        url->stop_req_until = time (NULL) + url->stop_req_duration; /* prevent further attempts for a while */
    }
    else
        DEBUG2 ("...handler %d (%s) request complete", auth_user->handler, auth_user->mount);

    free (userpwd);

    return AUTH_OK;
}


static auth_result url_add_listener (auth_client *auth_user)
{
    client_t *client = auth_user->client;
    auth_t *auth = auth_user->auth;
    auth_url *url = auth->state;
    auth_thread_data *atd = auth_user->thread_data;

    int res = 0, ret = AUTH_FAILED, poffset = 0;
    struct build_intro_contents *x;
    char *userpwd = NULL, post [8192];

    if (url->addurl == NULL || client == NULL)
        return AUTH_OK;

    if (url->stop_req_until)
    {
        time_t now = time(NULL);
        if (url->stop_req_until <= now)
        {
            INFO1 ("restarting url after timeout on %s", auth_user->mount);
            url->stop_req_until = 0;
        }
        else
        {
            if (auth->flags & AUTH_SKIP_IF_SLOW)
            {
                client->flags |= CLIENT_AUTHENTICATED;
                return AUTH_OK;
            }
            return AUTH_FAILED;
        }
    }
    do
    {
        ice_config_t *config = config_get_config ();
        char *user_agent, *username, *password, *mount, *ipaddr, *referer, *current_listeners,
             *server = util_url_escape (config->hostname);
        int port = config->port;
        config_release_config ();

        const char *tmp = httpp_getvar (client->parser, "user-agent");

        if (tmp == NULL)
            tmp = "-";
        user_agent = util_url_escape (tmp);

        if (client->username)
            username  = util_url_escape (client->username);
        else
            username = strdup ("");
        if (client->password)
            password  = util_url_escape (client->password);
        else
            password = strdup ("");

        /* get the full uri (with query params if available) */
        tmp = httpp_getvar (client->parser, HTTPP_VAR_QUERYARGS);
        snprintf (post, sizeof post, "%s%s", auth_user->mount, tmp ? tmp : "");
        mount = util_url_escape (post);
        ipaddr = util_url_escape (client->connection.ip);
        tmp = httpp_getvar (client->parser, "referer");
        referer = tmp ? util_url_escape (tmp) : strdup ("");

        current_listeners = stats_get_value (auth_user->mount, "listeners");
        if (current_listeners == NULL)
            current_listeners = strdup("");

        poffset = snprintf (post, sizeof (post),
                "action=listener_add&server=%s&port=%d&client=%" PRIu64 "&mount=%s"
                "&user=%s&pass=%s&ip=%s&agent=%s&referer=%s&listeners=%s",
                server, port, client->connection.id, mount, username,
                password, ipaddr, user_agent, referer, current_listeners);
        free (current_listeners);
        free (server);
        free (mount);
        free (referer);
        free (user_agent);
        free (username);
        free (password);
        free (ipaddr);
        if (poffset < 0 || poffset >= sizeof (post))
        {
            WARN2 ("client from %s (on %s), rejected with headers problem", &client->connection.ip[0], auth_user->mount);
            return AUTH_FAILED;
        }
    } while (0);

    if (url->header_chk_list)
    {
        int c = url->header_chk_count, remaining = sizeof(post) - poffset;
        char *cur_header = url->header_chk_list;
        const char *prefix = (url->header_chk_prefix && isalnum (url->header_chk_prefix[0])) ? url->header_chk_prefix : "ClientHeader-";

        for (; c ; c--)
        {
            int len = strlen (cur_header);
            const char *val = httpp_getvar (client->parser, cur_header);
            if (val)
            {
                char *valesc = util_url_escape (val);
                int r = remaining > 0 ? snprintf (post+poffset, remaining, "&%s%s=%s", prefix, cur_header, valesc) : -1;
                free (valesc);
                if (r < 0 || r > remaining)
                {
                    WARN2 ("client from %s (on %s), rejected with too much in headers", &client->connection.ip[0], auth_user->mount);
                    return AUTH_FAILED;
                }
                poffset += r;
                remaining -= r;
            }
            cur_header += (len + 1); // get past next nul
        }
    }

    if (strchr (url->addurl, '@') == NULL)
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
    curl_easy_setopt (atd->curl, CURLOPT_URL, url->addurl);
    curl_easy_setopt (atd->curl, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEHEADER, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEDATA, auth_user);
    atd->errormsg[0] = '\0';
    free (atd->location);
    atd->location = NULL;
    /* setup in case intro data is returned */
    x = (void *)client->refbuf->data;
    x->type = 0;
    x->head = NULL;
    x->intro_len = 0;
    x->tailp = &x->head;

    DEBUG2 ("handler %d (%s) sending request", auth_user->handler, auth_user->mount);
    res = curl_easy_perform (atd->curl);
    DEBUG2 ("handler %d (%s) request finished", auth_user->handler, auth_user->mount);

    free (userpwd);

    if (client->flags & CLIENT_AUTHENTICATED)
    {
        if (client->flags & CLIENT_HAS_INTRO_CONTENT)
        {
            client->refbuf->next = x->head;
            DEBUG3 ("intro (%d) received %lu for %s", x->type, (unsigned long)x->intro_len, client->connection.ip);
        }
        if (x->head == NULL)
            client->flags &= ~CLIENT_HAS_INTRO_CONTENT;
        x->head = NULL;
        ret = AUTH_OK;
    }
    if (res)
    {
        url->stop_req_until = time (NULL) + url->stop_req_duration; /* prevent further attempts for a while */
        WARN3 ("auth to server %s (%s) failed with %s", url->addurl, auth_user->mount, atd->errormsg);
        INFO1 ("will not auth new listeners for %d seconds", url->stop_req_duration);
        if (auth->flags & AUTH_SKIP_IF_SLOW)
        {
            client->flags |= CLIENT_AUTHENTICATED;
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
        INFO3 ("listener %s (%s) returned \"%s\"", client->connection.ip, url->addurl, atd->errormsg);
        if (atoi (atd->errormsg) == 403)
        {
            auth_user->client = NULL;
            client_send_403 (client, atd->errormsg+4);
        }
    }
    return ret;
}


/* called by auth thread when a source starts, there is no client_t in
 * this case
 */
static void url_stream_start (auth_client *auth_user)
{
    char *mount, *server, *ipaddr = NULL, *agent = NULL;
    client_t *client = auth_user->client;
    auth_url *url = auth_user->auth->state;
    auth_thread_data *atd = auth_user->thread_data;
    char post [4096];

    server = util_url_escape (auth_user->hostname);
    mount = util_url_escape (auth_user->mount);
    if (client)
    {
        if (client->connection.ip)
            ipaddr = util_url_escape (client->connection.ip);
        if (client->shared_data)
            agent = util_url_escape (client->shared_data);
    }
    if (ipaddr == NULL) ipaddr = strdup("");
    if (agent == NULL) agent = strdup("");

    snprintf (post, sizeof (post),
            "action=mount_add&mount=%.200s&server=%s&port=%d&ip=%s&agent=%.200s", mount, server,
            auth_user->port, ipaddr, agent);
    free (ipaddr);
    free (agent);
    free (server);
    free (mount);

    if (strchr (url->stream_start, '@') == NULL)
    {
        if (url->userpwd)
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, url->userpwd);
        else
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    }
    else
        curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    curl_easy_setopt (atd->curl, CURLOPT_URL, url->stream_start);
    curl_easy_setopt (atd->curl, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEHEADER, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEDATA, auth_user);

    DEBUG2 ("handler %d (%s) sending request", auth_user->handler, auth_user->mount);
    if (curl_easy_perform (atd->curl))
        WARN3 ("auth to server %s (%s) failed with %s", url->stream_start, auth_user->mount, atd->errormsg);
    DEBUG2 ("handler %d (%s) request finished", auth_user->handler, auth_user->mount);
}


static void url_stream_end (auth_client *auth_user)
{
    char *mount, *server, *ipaddr = NULL, *agent = NULL;
    client_t *client = auth_user->client;
    auth_url *url = auth_user->auth->state;
    auth_thread_data *atd = auth_user->thread_data;
    char post [4096];

    server = util_url_escape (auth_user->hostname);
    mount = util_url_escape (auth_user->mount);
    if (client)
    {
        if (client->connection.ip)
            ipaddr = util_url_escape (client->connection.ip);
        if (client->shared_data)
            agent = util_url_escape (client->shared_data);
    }
    if (ipaddr == NULL) ipaddr = strdup("");
    if (agent == NULL) agent = strdup("");

    snprintf (post, sizeof (post),
            "action=mount_remove&mount=%s&server=%.200s&port=%d&ip=%s&agent=%.200s", mount, server,
            auth_user->port, ipaddr, agent);
    free (ipaddr);
    free (agent);
    free (server);
    free (mount);

    if (strchr (url->stream_end, '@') == NULL)
    {
        if (url->userpwd)
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, url->userpwd);
        else
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    }
    else
        curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    curl_easy_setopt (atd->curl, CURLOPT_URL, url->stream_end);
    curl_easy_setopt (atd->curl, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEHEADER, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEDATA, auth_user);

    DEBUG2 ("handler %d (%s) sending request", auth_user->handler, auth_user->mount);
    if (curl_easy_perform (atd->curl))
        WARN3 ("auth to server %s (%s) failed with %s", url->stream_end, auth_user->mount, atd->errormsg);
    DEBUG2 ("handler %d (%s) request finished", auth_user->handler, auth_user->mount);
}


static void url_stream_auth (auth_client *auth_user)
{
    client_t *client = auth_user->client;
    auth_url *url = auth_user->auth->state;
    auth_thread_data *atd = auth_user->thread_data;
    char *mount, *host, *user, *pass, *ipaddr, *admin="";
    char post [4096];

    if (strchr (url->stream_auth, '@') == NULL)
    {
        if (url->userpwd)
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, url->userpwd);
        else
            curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    }
    else
        curl_easy_setopt (atd->curl, CURLOPT_USERPWD, "");
    curl_easy_setopt (atd->curl, CURLOPT_URL, url->stream_auth);
    curl_easy_setopt (atd->curl, CURLOPT_POSTFIELDS, post);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEHEADER, auth_user);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEDATA, auth_user);
    if (strcmp (auth_user->mount, httpp_getvar (client->parser, HTTPP_VAR_URI)) != 0)
        admin = "&admin=1";
    mount = util_url_escape (auth_user->mount);
    host = util_url_escape (auth_user->hostname);
    user = util_url_escape (client->username);
    pass = util_url_escape (client->password);
    ipaddr = util_url_escape (client->connection.ip);

    snprintf (post, sizeof (post),
            "action=stream_auth&mount=%s&ip=%s&server=%s&port=%d&user=%s&pass=%s%s",
            mount, ipaddr, host, auth_user->port, user, pass, admin);
    free (ipaddr);
    free (user);
    free (pass);
    free (mount);
    free (host);

    client->flags &= ~CLIENT_AUTHENTICATED;
    if (curl_easy_perform (atd->curl))
        WARN3 ("auth to server %s (%s) failed with %s", url->stream_auth, auth_user->mount, atd->errormsg);
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

    atd->curl = curl_easy_init ();
    curl_easy_setopt (atd->curl, CURLOPT_USERAGENT, atd->server_id);
    curl_easy_setopt (atd->curl, CURLOPT_HEADERFUNCTION, handle_returned_header);
    curl_easy_setopt (atd->curl, CURLOPT_WRITEFUNCTION, handle_returned_data);
    curl_easy_setopt (atd->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt (atd->curl, CURLOPT_TIMEOUT, (long)url->timeout);
#ifdef CURLOPT_PASSWDFUNCTION
    curl_easy_setopt (atd->curl, CURLOPT_PASSWDFUNCTION, my_getpass);
#endif
    curl_easy_setopt (atd->curl, CURLOPT_ERRORBUFFER, &atd->errormsg[0]);
    curl_easy_setopt (atd->curl, CURLOPT_FOLLOWLOCATION, 1);
#ifdef CURLOPT_POSTREDIR
    curl_easy_setopt (atd->curl, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);
#endif
    if (auth->flags & AUTH_SKIP_IF_SLOW)
        curl_easy_setopt (atd->curl, CURLOPT_SSL_VERIFYPEER, 0L);
    INFO0 ("...handler data initialized");
    return atd;
}


static void release_thread_data (auth_t *auth, void *thread_data)
{
    auth_thread_data *atd = thread_data;
    curl_easy_cleanup (atd->curl);
    free (atd->server_id);
    free (atd);
    DEBUG1 ("...handler destroyed for %s", auth->mount);
}


int auth_get_url_auth (auth_t *authenticator, config_options_t *options)
{
    auth_url *url_info;
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
    url_info->timeout = 5;
    url_info->stop_req_duration = 60;

    while(options) {
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
            free (url_info->addurl);
            url_info->addurl = strdup (options->value);
        }
        if(!strcmp(options->name, "listener_remove"))
        {
            authenticator->release_listener = url_remove_listener;
            free (url_info->removeurl);
            url_info->removeurl = strdup (options->value);
        }
        if(!strcmp(options->name, "mount_add"))
        {
            authenticator->stream_start = url_stream_start;
            free (url_info->stream_start);
            url_info->stream_start = strdup (options->value);
        }
        if(!strcmp(options->name, "mount_remove"))
        {
            authenticator->stream_end = url_stream_end;
            free (url_info->stream_end);
            url_info->stream_end = strdup (options->value);
        }
        if(!strcmp(options->name, "stream_auth"))
        {
            authenticator->stream_auth = url_stream_auth;
            free (url_info->stream_auth);
            url_info->stream_auth = strdup (options->value);
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
        if (strcmp(options->name, "timeout") == 0)
        {
            int timeout = atoi (options->value);
            url_info->timeout = timeout > 0 ? timeout : 1;
        }
        if (strcmp(options->name, "on_error_wait") == 0)
        {
            int seconds = atoi (options->value);
            url_info->stop_req_duration = seconds > 0 ? seconds : 1;
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

    authenticator->state = url_info;
    return 0;
}

