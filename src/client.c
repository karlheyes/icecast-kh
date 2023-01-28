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
        client->counter = client->schedule_ms = timing_get_time();
    } while (connection_reset (&client->connection, client->schedule_ms) < 0);  // loop back on failure to kick out

    DEBUG1 ("keepalive detected on %s, placing back onto worker", client->connection.ip);

    client->ops = &http_request_ops;
    client->flags = CLIENT_ACTIVE;
    client->shared_data = NULL;
    client->refbuf = NULL;
    client->pos = 0;
    client->intro_offset = 0;
    client->aux_data = (uintptr_t)-1;
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
        DEBUG2 ("list, %d, %d", client->pos, client->refbuf->len);
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


static int _date_hdr (client_http_headers_t * http, client_http_header_t *curr)
{
    client_t *cl = http->client;

    struct tm result;
    time_t now = cl->worker ? cl->worker->current_time.tv_sec : time(NULL);
    if (gmtime_r (&now, &result))
    {
        char *datebuf = malloc (40);
        if (strftime (datebuf, 40, "%a, %d %b %Y %X GMT", &result) > 0)
        {
            curr->value = datebuf;
            return 0;
        }
    }
    return -1;
}


static int _connection_hdr (client_http_headers_t * http, client_http_header_t *curr)
{
    if (http->in_major == 1 && http->in_minor == 1)
    {
        if (http->in_connection && strcasecmp (http->in_connection, "keep-alive") == 0)
        {
            curr->value = strdup ("keep-alive");
            http->client->flags |= CLIENT_KEEPALIVE;
        }
        return 0;
    }
    curr->value = NULL;
    return 0;
}


static int _send_cors_hdr (client_http_headers_t * http, client_http_header_t *curr)
{
    if (http->in_origin == NULL)
    {
        curr->value = NULL; // drop header but not error out
        return -1;
    }

    if (strcasecmp (curr->name, "Access-Control-Allow-Origin") == 0)
    {
        if (strcmp (curr->value, "*") == 0)
            curr->value = strdup (http->in_origin);
        if (strcmp (curr->value, "*") == 0)
            http->flags |= CLIENT_HTTPHDRS_WILDCARD_ORIGIN;
        else
            http->flags &= ~CLIENT_HTTPHDRS_WILDCARD_ORIGIN;
    }
    if (strcasecmp (curr->name, "Access-Control-Allow-Credentials") == 0 && (http->flags&CLIENT_HTTPHDRS_WILDCARD_ORIGIN))
        return -1;
    return 0;
}


static int _client_http_apply (client_http_headers_t *http, const client_http_header_t *header)
{
    client_http_header_t **trail = &http->headers, *chdr = http->headers;

    if (header->name == NULL)
    {
        if (header->value == NULL)
            return -1;      // definitely fail
        free (http->msg);
        http->msg = strdup (header->value);
        return 0;
    }
    if (header->callback == NULL && header->value == NULL) return -1; // error case

    // calc lengths of strings, but allow extra space for chars ': ' and '\r\n'
    int nlen = strlen (header->name), vlen;
    if (nlen) nlen += http->entry_div_len;

    client_http_header_t matched = { .name = NULL };

    while (chdr)
    {
        if (header->name[0] && strcasecmp (chdr->name, header->name) == 0)
        {
            matched = *chdr;
            if (chdr->flags & CFG_HTTPHDR_MULTI)
                break;
            if (chdr->flags & CFG_HTTPHDR_CONST)
                return -1;
            // replace existing data block
            break;
        }
        trail = &chdr->next;
        chdr = *trail;
    }
    if (matched.name == NULL)
    {
        chdr = calloc (1, sizeof (*chdr));
        chdr->name = header->name;
    }
    chdr->value = header->value;
    if (header->callback)
    {
        if (header->callback (http, chdr) < 0)
        {
            int ret = chdr->value == NULL ? 0 : -1;
            if (matched.name)
                *chdr = matched;      // leave as it was
            else
                free (chdr);
            return ret;
        }
    }
    chdr->name = strdup (header->name);
    if (chdr->value == NULL)
        chdr->value = strdup (header->value ? header->value : "");
    else if (header->flags & CLIENT_POST_ENC)
        chdr->value = util_url_escape (header->value);
    else if (chdr->value == header->value)
        chdr->value = strdup (header->value);

    chdr->flags = (header->flags & ~CFG_HTTPHDR_NOCOPY);
    vlen = strlen (chdr->value) + http->entry_end_len;
    chdr->callback = header->callback;
    chdr->value_len = vlen;
    chdr->name_len = nlen;
    http->len -= (matched.name_len + matched.value_len);
    http->len += (nlen + vlen);

    if (matched.name)
    {   // we are replacing so just clean up
        free (matched.name);
        free (matched.value);
    }
    else
    {   // insert
        chdr->next = *trail;
        *trail = chdr;
    }
    return 0;
}


int client_http_apply (client_http_headers_t *http, const client_http_header_t *header)
{
    const client_http_header_t *hdr = header;

    while (hdr)
    {
        if (_client_http_apply (http, hdr) < 0)
            WARN2 ("header problem %s:%s", hdr->name, hdr->value);
        hdr = hdr->next;
    }
    return 0;
}


void client_http_clear (client_http_headers_t *http)
{
    if (http->headers == NULL) return;  // means nothing set
    while (http->headers)
    {
        client_http_header_t *hdr = http->headers;
        http->headers = hdr->next;

        if ((hdr->flags & CFG_HTTPHDR_NOCOPY) == 0)
        {
            free (hdr->name);
            free (hdr->value);
        }
        free (hdr);
    }
    free (http->in_realm);
    free (http->msg);
}


int client_http_apply_block (client_http_headers_t *http, refbuf_t *ref)
{
    if (ref)
    {
        client_t *client = http->client;
        refbuf_t **rp = &client->refbuf;

        while (*rp)
            rp = &((*rp)->next);
        *rp = ref;
        http->block_total += ref->len;
    }
    return 0;
}


//
int client_http_apply_fmt (client_http_headers_t *http, int flags, const char *name, const char *fmt, ...)
{
    int ret = 1023;
    if (fmt == NULL) return -1;
    do {
        va_list ap;
        char content [ret + 1];
        va_start(ap, fmt);
        ret = vsnprintf (content, sizeof content, fmt, ap);
        va_end(ap);

        if (ret >= 0 && ret < sizeof content)
        {
            client_http_header_t hdr = { .next = NULL, .name = (char*)name, .value = content, .flags = flags };
            return client_http_apply (http, &hdr);
        }
    } while (ret < 8000);        // loop to retry with a larger size, although not silly
    WARN1 ("header content too large for %s", CONN_ADDR (http->client));
    return -1;
}


int  client_http_apply_cfg (client_http_headers_t *http, ice_config_http_header_t *h)
{
    while (h)
    {
        if (cached_pattern_compare (http->respcode, h->field.status) == 0)
        {
            client_http_header_t hdr = { .name = h->field.name, .value = h->field.value, .flags = h->flags, .callback = h->field.callback };
            client_http_apply (http, &hdr);
        }
        h = h->next;
    }
    return 0;
}


int client_http_status_lookup (int status, client_http_status_t *s)
{
#define RetX(A,B) (*s = (client_http_status_t){.status=A, .msg=B })
    switch (status)
    {
        case 100: RetX (100, "Continue"); break;
        case 200: RetX (200, "OK"); break;
        case 204: RetX (204, "No Content"); break;
        case 206: RetX (206, "Partial Content"); break;
        case 302: RetX (302, "Found"); break;
        case 401: RetX (401, "Authentication Required"); break;
        case 403: RetX (403, "Forbidden"); break;
        case 404: RetX (404, "File Not Found"); break;
        case 416: RetX (416, "Request Range Not Satisfiable"); break;
        case 501: RetX (501, "Not Implemented"); break;
        default:  RetX (400, "Bad Request"); break;
    }
    return 0;
}


static int client_http_setup_req (client_http_headers_t *http, unsigned int flags, const char *uri)
{
    if (uri == NULL || uri[0] == 0) return -1;
    // special case, first line has blank name as it is different to the other headers
    if (http->headers == NULL)
    {
        char line [1024];
        client_http_header_t  firsthdr = { .name = "", .value = line, .flags = CFG_HTTPHDR_CONST };
        snprintf (line, sizeof(line), "GET %.1000s HTTP/1.1", uri);

        http->len = 1;       // start with allowing for the nul
        http->in_major = http->in_minor = 1;
        client_http_apply (http, &firsthdr);
    }
    ice_config_t *config = config_get_config();
    client_http_apply_fmt (http, 0, "User-Agent", "%s", config->server_id);
    config_release_config();
    client_http_apply_fmt (http, 0, "Connection", "Close");
    return 0;
}


int  client_http_setup_flags (client_http_headers_t *http, client_t *client, int status, unsigned int flags, const char *statusmsg)
{
    if (client && client->respcode) return -1;
    memset (http, 0, sizeof (*http));
    http->client = client;
    http->entry_end_len = snprintf (&http->entry_end[0], sizeof (http->entry_end), "\r\n");
    http->entry_div_len = snprintf (&http->entry_div[0], sizeof (http->entry_div), ": ");
    if (flags & CLIENT_HTTPHDRS_REQUEST)
        return client_http_setup_req (http, flags, statusmsg);

    client_http_status_lookup (status, &http->conn);
    client->respcode = http->conn.status;

    // for matching on header pattern matching and quicker lookup/check
    snprintf (&http->respcode[0], sizeof (http->respcode), "%" PRIu16, client->respcode);

    char protocol[20];
    if (flags & CLIENT_HTTPHDRS_USE_ICY)
        strcpy (protocol, "ICY");
    else
    {
        const char *in_version = httpp_getvar (client->parser, HTTPP_VAR_VERSION);
        if (in_version == NULL)
            in_version = "1.0";
        int ret = sscanf (in_version, "%" SCNu8 ".%" SCNu8, &http->in_major, &http->in_minor);
        if (ret < 1 || ret > 2) return -1;  // parsing error
        if (http->in_major < 1 || http->in_major > 3 || http->in_minor > 1) return -1; // may need altering for newer specs
        snprintf (protocol, sizeof protocol, "HTTP/%d.%d", http->in_major, http->in_minor);
    }

    http->in_connection = httpp_getvar (client->parser, "connection");
    http->in_origin = httpp_getvar (client->parser, "origin");

    char line [1024];
    client_http_header_t  firsthdr = { .name = "", .value = line, .flags = CFG_HTTPHDR_CONST };
    if (statusmsg == NULL)
        statusmsg = http->conn.msg;
    snprintf (line, sizeof(line), "%s %d %.1000s", protocol, http->conn.status, statusmsg);

    http->len = 1;       // start with allowing for the nul
    client_http_apply (http, &firsthdr);

    ice_config_t *config = config_get_config();
    const char *realm = config->server_id;
    mount_proxy *mountinfo = client->mount ? config_find_mount (config, client->mount) : NULL;
    if (mountinfo)
    {
        if (mountinfo->auth && mountinfo->auth->realm)
            realm = mountinfo->auth->realm;
        if (mountinfo->http_headers)
            client_http_apply_cfg (http, mountinfo->http_headers);
    }
    else
        client_http_apply_cfg (http, config->http_headers);
    if (client->respcode == 401)        http->in_realm = strdup (realm);
    config_release_config();

    return 0;
}


int  client_post_setup (client_http_headers_t *http, unsigned int flags)
{
    memset (http, 0, sizeof (*http));
    http->entry_end_len = snprintf (&http->entry_end[0], sizeof (http->entry_end), "&");
    http->entry_div_len = snprintf (&http->entry_div[0], sizeof (http->entry_div), "=");

    http->len = 1;       // start with allowing for the nul
    http->in_length = -1;
    return 0;
}


static int _client_headers_complete (client_http_headers_t *http, refbuf_t *rb)
{
    client_http_header_t *h = http->headers;
    unsigned int remain = rb->len;
    char *p = rb->data;
    while (h)
    {
        const char *divider = h->name[0] ? &http->entry_div[0] : "";
        const char *endtag  = h->next    ? &http->entry_end[0] : "";
        int r = snprintf (p, remain, "%s%s%s%s", h->name, divider, h->value, endtag);
        if (r < 0 || r >= remain) return -1;
        p += r;
        remain -= r;
        h = h->next;
    }
    return p - rb->data;
}


int  client_http_complete (client_http_headers_t *http)
{
    if (http == NULL || http->headers == NULL) return -1;

    const char *msg = (http->msg) ? http->msg : "";
    int remain = strlen (msg);
    uint64_t msglen = remain + http->block_total;

    if (http->in_length > 0)
        client_http_apply_fmt (http, 0, "Content-Length", "%" PRIu64, http->in_length);  // forward notification
    else if (http->in_length == 0)
        client_http_apply_fmt (http, 0, "Content-Length", "%" PRIu64, msglen);  // headers + simple message

    _client_http_apply (http, &(client_http_header_t){ .name = "", .value = "\r\n" });

    remain += http->len;  // starts with space for nul char
    refbuf_t *rb = refbuf_new (remain);
    int written = _client_headers_complete (http, rb);
    if (written >= 0)
    {
        client_t *cl = http->client;
        rb->next = cl->refbuf;
        cl->refbuf = rb;
        char *p = rb->data + written;
        written += snprintf (p, (rb->len - written), "%s", msg);
        rb->len = written; // don't send the last nul
    }
    client_http_clear (http);
    return written < 0 ? -1 : 0;
}


refbuf_t *client_post_complete (client_http_headers_t *http)
{
    if (http == NULL || http->headers == NULL) return NULL;
    uint64_t remain = http->block_total + http->len;
    refbuf_t *rb = refbuf_new (remain);
    int written = _client_headers_complete (http, rb);
    if (written >= 0)
        rb->len = written; // do not include the last null even though it is there
    client_http_clear (http);
    return rb;
}


int client_http_send (client_http_headers_t *http)
{
    client_t *client = http->client;
    client_http_complete (http);
    return fserve_setup_client (client);
}


int client_send_302(client_t *client, const char *location)
{
    if (location == NULL) return -1;
    client_http_headers_t http;
    client_http_setup (&http, client, 302, NULL);
    client_http_apply_fmt (&http, 0, "Location", "%s", location);
    return client_http_send (&http);
}


int client_send_400(client_t *client, const char *message)
{
    client_http_headers_t http;
    client_http_setup (&http, client, 400, NULL);
    client_http_apply_fmt (&http, 0, NULL, "%s", message);
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
    client_http_headers_t http;
    if (client_http_setup (&http, client, 401, NULL) < 0) return -1;
    client_http_apply_fmt (&http, 0, "WWW-Authenticate", "Basic realm=\"%s\"", (realm ? realm : http.in_realm));
    return client_http_send (&http);
}


int client_send_403 (client_t *client, const char *reason)
{
    client_http_headers_t http;
    if (client_http_setup (&http, client, 403, reason) < 0) return -1;
    return client_http_send (&http);
}

int client_send_404 (client_t *client, const char *message)
{
    client_http_headers_t http;
    if (client_http_setup (&http, client, 404, NULL) < 0) return -1;
    if (message)
        client_http_apply_fmt (&http, 0, NULL, "%s", message);
    return client_http_send (&http);
}


int client_send_416(client_t *client)
{
    client_http_headers_t http;
    if (client_http_setup (&http, client, 416, NULL) < 0) return -1;
    return client_http_send (&http);
}


int client_send_501(client_t *client)
{
    client_http_headers_t http;
    if (client_http_setup (&http, client, 501, NULL) < 0) return -1;
    return client_http_send (&http);
}


int client_send_options(client_t *client)
{
    client_http_headers_t http;
    if (client_http_setup (&http, client, 204, NULL) < 0) return -1;
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

    if (client->connection.error)
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
        client_http_headers_t http;
        client_http_setup (&http, client, 200, NULL);
        client_http_apply_fmt (&http, 0, "Content-Type", "%s", "audio/x-mpegurl");
        client_http_apply_fmt (&http, 0, "Content-Disposition", "%s", "attachment; filename=\"listen.m3u\"");
        client_http_apply_fmt (&http, 0, NULL, "%s://%s%s%s%s\n", protocol, userpass, host, sourceuri, args?args:"");
        client_http_complete (&http);
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
            thread_spin_lock (&handler->lock);
            int cur_count = handler->count + handler->pending_count;
            thread_spin_unlock (&handler->lock);

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


void client_add_incoming (client_t *client)
{
    worker_t *handler;

    thread_rwlock_rlock (&workers_lock);
    handler = worker_incoming;
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
    thread_spin_lock (&worker->lock);
    if (worker->pending_clients)
    {
        unsigned count;
        client_t **p;

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
        return p;  /* only these new ones scheduled so process from here */
    }
    thread_spin_unlock (&worker->lock);
    worker->wakeup_ms = worker->time_ms + 60000;
    return &worker->clients;
}


// enter with spin lock enabled, exit without
//
static client_t **worker_wait (worker_t *worker)
{
    int ret, duration = 2;

    if (worker->running)
    {
        uint64_t tm = worker_check_time_ms (worker);
        if (worker->wakeup_ms > tm)
            duration = (int)(worker->wakeup_ms - tm);
        if (duration > 60000) /* make duration at most 60s */
            duration = 60000;
    }
    thread_spin_unlock (&worker->lock);

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
        worker->current_time.tv_sec = (time_t)(worker->time_ms/1000);
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
        thread_spin_lock (&worker->lock);
        worker_wait (worker);
    }
}

void *worker (void *arg)
{
    worker_t *worker = arg;
    long prev_count = -1;
    client_t **prevp = &worker->clients;
    uint64_t c = 0;

    thread_rwlock_rlock (&global.workers_rw);
    worker->running = 1;
    worker->wakeup_ms = (int64_t)0;
    worker->time_ms = timing_get_time();

    while (1)
    {
        client_t *client = *prevp;
        uint64_t sched_ms = worker->time_ms + 12;

        c = 0;
        thread_spin_lock (&worker->lock);
        while (client)
        {
            if (client->worker != worker) abort();
            /* process client details but skip those that are not ready yet */
            if (client->flags & CLIENT_ACTIVE)
            {
                int ret = 0;
                client_t *nx = client->next_on_worker;

                int process = 1;
                if (worker->running)  // force all active clients to run on worker shutdown
                {
                    if (client->schedule_ms <= sched_ms)
                    {
                        if (c > 9000 && client->wakeup == NULL)
                            process = 0;
                    }
                    else if (client->wakeup == NULL || *client->wakeup == 0)
                    {
                        process = 0;
                    }
                }

                if (process)
                {
                    thread_spin_unlock (&worker->lock);
                    if ((c & 511) == 0)
                    {
                        // update these periodically to keep in sync
                        worker->time_ms = worker_check_time_ms (worker);
                        worker->current_time.tv_sec = (time_t)(worker->time_ms/1000);
                    }
                    c++;
                    errno = 0;
                    ret = client->ops->process (client);
                    if (ret < 0)
                    {
                        client->worker = NULL;
                        if (client->ops->release)
                            client->ops->release (client);
                    }
                    if (ret)
                    {
                        thread_spin_lock (&worker->lock);
                        worker->count--;
                        if (nx == NULL) /* is this the last client */
                            worker->last_p = prevp;
                        client = *prevp = nx;
                        continue;
                    }
                    thread_spin_lock (&worker->lock);
                }
                if (ret == 0 && (client->flags & CLIENT_ACTIVE) && client->schedule_ms < worker->wakeup_ms)
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
            if (worker->count == 0 && worker->pending_count == 0)
                break;
        }
        prevp = worker_wait (worker);
    }
    thread_spin_unlock (&worker->lock);
    worker_relocate_clients (worker);
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
            thread_spin_lock (&w->lock);
            w->move_allocations = 200;
            worker_balance_to_check = w->next;
            thread_spin_unlock (&w->lock);
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

    handler->pending_clients_tail = &handler->pending_clients;
    thread_spin_create (&handler->lock);
    handler->last_p = &handler->clients;

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
                workers->move_allocations = 1000;
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
            thread_spin_lock (&handler->lock);
            handler->running = 0;
            thread_spin_unlock (&handler->lock);

            worker_wakeup (handler);
            thread_rwlock_unlock (&workers_lock);

            thread_join (handler->thread);
            thread_spin_destroy (&handler->lock);

            sock_close (handler->wakeup_fd[1]);
            sock_close (handler->wakeup_fd[0]);
            free (handler);
            thread_rwlock_wlock (&workers_lock);
        }
    } while (workers == NULL && worker_incoming);
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


static void logger_commits (int id)
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


ice_config_http_header_t default_headers[] =
{
    { .field = { .status = "2*",        .name = "Server",               .value = "Icecast" } },
    { .field = { .status = "[24]*",     .name = "Connection",           .value = "Close",
                                        .callback = _connection_hdr } },
    { .field = { .status = "2*",        .name = "Pragma",               .value = "no-cache" } },
    { .field = { .status = "2*",        .name = "Expires",              .value = "Thu, 19 Nov 1981 08:52:00 GMT" } },
    { .field = { .status = "2*",        .name = "Cache-Control",        .value = "no-store, no-cache, private" } },
    { .field = { .status = "2*",        .name = "Vary",                 .value = "Origin" } },
    { .field = { .status = "2*",        .name = "Access-Control-Allow-Origin",
                                        .value = "*",
                                        .callback = _send_cors_hdr } },
    { .field = { .status = "2*",        .name = "Access-Control-Allow-Credentials",
                                        .value = "True", .callback = _send_cors_hdr } },
    { .field = { .status = "2*",        .name = "Access-Control-Allow-Headers",
                                        .value = "Origin, Icy-MetaData, Range",
                                        .callback = _send_cors_hdr } },
    { .field = { .status = "2*",        .name = "Access-Control-Expose-Headers",
                                        .value = "Icy-Br, Icy-Description, Icy-Genre, Icy-MetaInt, Icy-Name, Icy-Pub, Icy-Url",
                                        .callback = _send_cors_hdr } },
    { .field = { .status = "2*",        .name = "Access-Control-Allow-Methods",
                                        .value = "GET, OPTIONS, SOURCE, PUT, HEAD, STATS",
                                        .callback = _send_cors_hdr } },
    { .field = { .status = "*",         .name = "Date",                 .callback = _date_hdr } },
    { .field = { .status = "*",         .name = "Content-Type",         .value = "text/html" } },
    { .field = { .name = NULL }}
};

