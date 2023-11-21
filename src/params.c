/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2023-2023,  Karl Heyes <karl@kheyes.plus.com>
 */

/*
 * routines for helping to encode a series of related parameters into a block. We
 * have 2 sets, a params block which is base for the other, and deals with the
 * core add and modify parameter handling. The second is a more specific one, http
 * headers. This latter one uses the former for the stoarge aspects,  while it
 * handles the interactions with the client. The former is also used for POST field
 * creation. In each case, the end result is a refbuf that can be used for sending.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <time.h>

#include "cfgfile.h"
#include "util.h"
#include "params.h"
#include "logging.h"


#define CATMODULE "param"

static int _date_hdr (ice_http_t * http, ice_param_t *curr)
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


static int _server_hdr (ice_http_t *http, ice_param_t *curr)
{
    curr->value = strdup (http->in_server_id);
    return 0;
}


static int _connection_hdr (ice_http_t *http, ice_param_t *curr)
{
    if (http->in_major == 1 && http->in_minor == 1 && http->in_length >= 0 && http->in_connection)
    {
        if (strcasecmp (http->in_connection, "keep-alive") == 0)
        {
            http->client->flags |= CLIENT_KEEPALIVE;
            curr->value = strdup ("keep-alive");
            return 0;
        }
    }
    http->client->flags &= ~CLIENT_KEEPALIVE;
    curr->value = NULL;
    return 0;
}


static int _send_cors_hdr (ice_http_t *http, ice_param_t *curr)
{
    ice_params_t *params = &http->headers;
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
            params->flags |= ICE_HTTP_WILDCARD_ORIGIN;
        else
            params->flags &= ~ICE_HTTP_WILDCARD_ORIGIN;
    }
    if (strcasecmp (curr->name, "Access-Control-Allow-Credentials") == 0 && (params->flags&ICE_HTTP_WILDCARD_ORIGIN))
        return -1;
    return 0;
}


static int _ice_params_apply (ice_params_t *params, const ice_param_t *header)
{
    ice_param_t **trail = &params->head, *chdr = params->head;

    if (header->callback == NULL && header->value == NULL) return -1; // error case

    // calc lengths of strings, but allow extra space for separators
    int nlen = strlen (header->name), vlen;
    if (nlen) nlen += params->entry_div_len;

    ice_param_t matched = { .name = NULL };

    while (chdr)
    {
        if (header->name[0] && strcasecmp (chdr->name, header->name) == 0)
        {
            matched = *chdr;
            if (chdr->flags & PARAM_MULTI)
                break;
            if (chdr->flags & PARAM_CONST)
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
    // encode string if header PARAM_AS not set and either the params or header is set to ESC
    int encode = ((header->flags & PARAM_AS) == 0 && ((params->flags & PARAMS_ESC) || (header->flags & PARAM_ESC)));
    chdr->value = header->value;
    char *tmp = NULL;
    const char *p = header->value ? header->value : "";
    if (header->callback)
    {
        if (header->callback (header->callback_arg, chdr) < 0)
        {
            int ret = chdr->value == NULL ? 0 : -1;
            if (matched.name)
                *chdr = matched;      // leave as it was
            else
                free (chdr);
            return ret;
        }
        if (encode && chdr->value && chdr->value != header->value)
            p = tmp = chdr->value;
    }
    chdr->name = strdup (header->name);
    if (encode && p && p[0])
        chdr->value = util_url_escape (p);
    else if (chdr->value == NULL)
        chdr->value = strdup (p);
    else if (chdr->value == header->value)
        chdr->value = strdup (header->value);

    chdr->flags = (header->flags & ~PARAM_NOCOPY);
    vlen = strlen (chdr->value) + params->entry_end_len;
    chdr->callback = header->callback;
    chdr->value_len = vlen;
    chdr->name_len = nlen;
    params->len -= (matched.name_len + matched.value_len);
    params->len += (nlen + vlen);

    free (tmp);
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


int ice_params_apply (ice_params_t *pm, const ice_param_t *header)
{
    const ice_param_t *hdr = header;

    while (hdr)
    {
        if (_ice_params_apply (pm, hdr) < 0)
            WARN2 ("problem applying %s:%s", hdr->name, hdr->value);
        hdr = hdr->next;
    }
    return 0;
}


int ice_http_apply (ice_http_t *http, const ice_param_t *header)
{
    for (; header; header = header->next)
    {
        if (header->name == NULL)
        {
            if (header->value == NULL)
                return -1;      // definitely fail
            free (http->msg);
            http->msg = strdup (header->value);
            continue;
        }
        _ice_params_apply (&http->headers, header); // process 1 param
    }
    return 0;
}


void ice_params_clear (ice_params_t *params)
{
    if (params->head == NULL) return;  // means nothing set
    while (params->head)
    {
        ice_param_t *p = params->head;
        params->head = p->next;

        if ((p->flags & PARAM_NOCOPY) == 0)
        {
            free (p->name);
            free (p->value);
        }
        free (p);
    }
    memset (params, 0, sizeof (*params));
}


void ice_http_clear (ice_http_t *http)
{
    if (http->client == NULL) return; // not been through setup
    ice_params_clear (&http->headers);
    free (http->in_realm);
    free (http->in_server_id);
    free (http->msg);
    http->msg = http->in_realm = http->in_server_id = NULL;
    http->client = NULL;
}


int ice_http_apply_block (ice_http_t *http, refbuf_t *ref)
{
    if (ref)
    {
        client_t *client = http->client;
        refbuf_t **rp = &client->refbuf;

        while (*rp)
            rp = &((*rp)->next);
        *rp = ref;
        http->headers.extra_len += ref->len;
        if (http->in_length == 0) http->in_length = -1; // unset for now
    }
    return http->headers.extra_len;
}


//
int ice_params_printf (ice_params_t *pm, const char *name, int flags, const char *fmt, ...)
{
    int ret = 1023;
    if (fmt == NULL) return -1;
    do {
        va_list ap;
        char content [ret + 1];
        va_start (ap, fmt);
        ret = vsnprintf (content, sizeof content, fmt, ap);
        va_end(ap);

        if (ret >= 0 && ret < sizeof content)
        {
            ice_param_t hdr = { .next = NULL, .name = (char*)name, .value = content, .flags = flags };
            return ice_params_apply (pm, &hdr);
        }
    } while (ret < 8000);        // loop to retry with a larger size, although not silly
    return -1;
}


int ice_http_printf (ice_http_t *http, const char *name, int flags, const char *fmt, ...)
{
    int ret = 1023;
    do
    {
        va_list ap;
        char content [ret + 1];
        va_start (ap, fmt);
        ret = vsnprintf (content, sizeof content, fmt, ap);
        va_end(ap);
        if (ret >= 0 && ret < sizeof content)
        {
            ice_param_t hdr = { .next = NULL, .name = (char*)name, .value = content, .flags = flags };
            return ice_http_apply (http, &hdr);
        }
    } while (ret < 8000);
    return -1;
}


int  ice_http_apply_cfg (ice_http_t *http, ice_config_http_header_t *h)
{
    while (h)
    {
        if (cached_pattern_compare (http->respcode, h->hdr.status) == 0)
        {
            ice_param_t hdr = { .name = h->hdr.name, .value = h->hdr.value, .flags = h->flags,
                .callback = h->hdr.callback, .callback_arg = http };
            _ice_params_apply (&http->headers, &hdr);
        }
        h = h->next;
    }
    return 0;
}


static int ice_http_status_lookup (int status, ice_http_status_t *s)
{
#define RetX(A,B) (*s = (ice_http_status_t){.status=A, .msg=B })
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


int  ice_params_setup (ice_params_t *params, const char *divider, const char *separator, unsigned int flags)
{
    memset (params, 0, sizeof (*params));
    params->entry_div_len = snprintf (&params->entry_div[0], sizeof (params->entry_div), "%s", divider);
    params->entry_end_len = snprintf (&params->entry_end[0], sizeof (params->entry_end), "%s", separator);
    params->flags = flags;

    params->len = 1;       // start with allowing for the nul
    return 0;
}


static int ice_http_setup_req (ice_http_t *http, unsigned int flags, const char *uri)
{
    if (uri == NULL || uri[0] == 0) return -1;
    // special case, first line has blank name as it is different to the other headers
    if (http->headers.head == NULL)
    {
        char line [1024];
        ice_param_t  firsthdr = { .name = "", .value = line, .flags = PARAM_CONST|PARAM_AS };
        snprintf (line, sizeof(line), "GET %.1000s HTTP/1.0", uri);

        http->headers.len = 1;       // start with allowing for the nul
        http->in_major = http->in_minor = 1;
        ice_http_apply (http, &firsthdr);
    }
    ice_config_t *config = config_get_config();
    ice_http_printf (http, "User-Agent", 0, "%s", config->server_id);
    config_release_config();
    ice_http_printf (http, "Connection", 0, "Close");
    return 0;
}


int  ice_http_setup_flags (ice_http_t *http, client_t *client, int status, unsigned int flags, const char *statusmsg)
{
    if (client && client->respcode) return -1;
    memset (http, 0, sizeof (*http));
    ice_params_setup (&http->headers, ": ", "\r\n", 0);
    http->client = client;
    if (flags & ICE_HTTP_REQUEST)
        return ice_http_setup_req (http, flags, statusmsg);

    ice_http_status_lookup (status, &http->conn);
    client->respcode = http->conn.status;

    // for matching on header pattern matching and quicker lookup/check
    snprintf (&http->respcode[0], sizeof (http->respcode), "%" PRIu16, client->respcode);

    char protocol[20];
    if (flags & ICE_HTTP_USE_ICY)
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

    if ((flags & ICE_HTTP_CONN_CLOSE) == 0)
        http->in_connection = httpp_getvar (client->parser, "connection");
    http->in_origin = httpp_getvar (client->parser, "origin");

    char line [1024];
    ice_param_t  firsthdr = { .name = "", .value = line, .flags = PARAM_CONST|PARAM_AS };
    if (statusmsg == NULL)
        statusmsg = http->conn.msg;
    snprintf (line, sizeof(line), "%s %d %.1000s", protocol, http->conn.status, statusmsg);

    ice_http_apply (http, &firsthdr);
    if (http->conn.status >= 100 && http->conn.status < 200)
    {
        client->respcode = 0;       // informational codes are followed by others so reset
        if (http->in_major < 1 || (http->in_major == 1 && http->in_minor == 0))
            return -1;
        http->in_length = -1;
        return 0;
    }
    if (http->conn.status >= 400)
        client->flags &= ~CLIENT_KEEPALIVE;  // for permanent errors, avoid keep alive

    ice_config_t *config = config_get_config();
    const char *realm = config->server_id;
    mount_proxy *mountinfo = client->mount ? config_find_mount (config, client->mount) : NULL;
    http->in_server_id = strdup (realm ? realm : PACKAGE_STRING);
    if (mountinfo)
    {
        if (mountinfo->auth && mountinfo->auth->realm)
            realm = mountinfo->auth->realm;
        if (mountinfo->http_headers)
            ice_http_apply_cfg (http, mountinfo->http_headers);
    }
    else
        ice_http_apply_cfg (http, config->http_headers);
    if (realm && client->respcode == 401)        http->in_realm = strdup (realm);
    config_release_config();

    return 0;
}


static int _ice_params_complete (ice_params_t *pm, refbuf_t *rb)
{
    ice_param_t *h = pm->head;
    unsigned int remain = rb->len;
    char *p = rb->data;
    while (h)
    {
        const char *divider = h->name[0] ? &pm->entry_div[0] : "";
        const char *endtag  = h->next    ? &pm->entry_end[0] : "";
        int r = snprintf (p, remain, "%s%s%s%s", h->name, divider, h->value, endtag);
        if (r < 0 || r >= remain) return -1;
        p += r;
        remain -= r;
        h = h->next;
    }
    return p - rb->data;
}


int  ice_http_complete (ice_http_t *http)
{
    if (http == NULL || http->client == NULL || http->headers.head == NULL) return -1;

    const char *msg = (http->msg) ? http->msg : "";
    int remain = strlen (msg);
    uint64_t msglen = remain + http->headers.extra_len;

    if (http->in_length > 0)
        ice_http_printf (http, "Content-Length", PARAM_PASS, "%" PRIu64, http->in_length);  // forward notification
    else if (http->in_length == 0)
        ice_http_printf (http, "Content-Length", PARAM_PASS, "%" PRIu64, msglen);  // headers + simple message

    ice_params_apply (&http->headers, &(ice_param_t){ .name = "", .value = "\r\n" });

    remain += http->headers.len;  // starts with space for nul char
    refbuf_t *rb = refbuf_new (remain);
    client_t *cl = http->client;
    int written = _ice_params_complete (&http->headers, rb);
    if (written >= 0)
    {
        rb->next = cl->refbuf;
        cl->refbuf = rb;
        rb->flags |= BUFFER_CONTAINS_HDR;
        char *p = rb->data + written;
        written += snprintf (p, (rb->len - written), "%s", msg);
        rb->len = written; // don't send the last nul
    }
    ice_http_clear (http);
    return written < 0 ? -1 : 0;
}


refbuf_t *ice_params_complete (ice_params_t *pm)
{
    if (pm == NULL || pm->head == NULL) return NULL;
    uint64_t remain = pm->extra_len + pm->len;
    refbuf_t *rb = refbuf_new (remain);
    int written = _ice_params_complete (pm, rb);
    if (written >= 0)
        rb->len = written; // do not include the last null even though it is there
    ice_params_clear (pm);
    return rb;
}


ice_config_http_header_t default_headers[] =
{
    { .hdr = { .status = "2*",          .name = "Server",               .value = "Icecast",
                                        .callback = _server_hdr }, },
    { .hdr = { .status = "[234]*",      .name = "Connection",           .value = "Close",
                                        .callback = _connection_hdr } },
    { .hdr = { .status = "2*",          .name = "Pragma",               .value = "no-cache" } },
    { .hdr = { .status = "2*",          .name = "Expires",              .value = "Thu, 19 Nov 1981 08:52:00 GMT" } },
    { .hdr = { .status = "2*",          .name = "Cache-Control",        .value = "no-store, no-cache, private" } },
    { .hdr = { .status = "2*",          .name = "Vary",                 .value = "Origin" } },
    { .hdr = { .status = "[23]*",          .name = "Access-Control-Allow-Origin",
                                        .value = "*",
                                        .callback = _send_cors_hdr } },
    { .hdr = { .status = "[23]*",          .name = "Access-Control-Allow-Credentials",
                                        .value = "true", .callback = _send_cors_hdr } },
    { .hdr = { .status = "[23]*",          .name = "Access-Control-Allow-Headers",
                                        .value = "Origin, Icy-MetaData, Range, Authorization",
                                        .callback = _send_cors_hdr } },
    { .hdr = { .status = "[23]*",          .name = "Access-Control-Expose-Headers",
                                        .value = "Icy-Br, Icy-Description, Icy-Genre, Icy-MetaInt, Icy-Name, Icy-Pub, Icy-Url",
                                        .callback = _send_cors_hdr } },
    { .hdr = { .status = "[23]*",          .name = "Access-Control-Allow-Methods",
                                        .value = "GET, OPTIONS, SOURCE, PUT, HEAD, STATS",
                                        .callback = _send_cors_hdr } },
    { .hdr = { .status = "*",           .name = "Date",                 .callback = _date_hdr } },
    { .hdr = { .status = "*",           .name = "Content-Type",         .value = "text/html" } },
    { .hdr = { .name = NULL }}
};

