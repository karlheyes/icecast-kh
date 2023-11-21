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

/* -*- c-basic-offset: 4; -*- */
/* format.c
**
** format plugin implementation
**
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#include "compat.h"
#include "connection.h"
#include "refbuf.h"

#include "timing/timing.h"
#include "source.h"
#include "format.h"
#include "global.h"
#include "httpp/httpp.h"

#include "format_ogg.h"
#include "format_mp3.h"
#include "format_ebml.h"

#include "logging.h"
#include "stats.h"
#define CATMODULE "format"


format_type_t format_get_type(const char *content_type)
{
    char contenttype [256];

    if (content_type == NULL) return FORMAT_TYPE_UNDEFINED;
    sscanf (content_type, "%250[^ ;]", contenttype);
    if(strcmp(contenttype, "application/x-ogg") == 0)
        return FORMAT_TYPE_OGG; /* Backwards compatibility */
    else if(strcmp(contenttype, "application/ogg") == 0)
        return FORMAT_TYPE_OGG; /* Now blessed by IANA */
    else if(strcmp(contenttype, "audio/ogg") == 0)
        return FORMAT_TYPE_OGG;
    else if(strcmp(contenttype, "video/ogg") == 0)
        return FORMAT_TYPE_OGG;
    else if(strcmp(contenttype, "audio/webm") == 0)
        return FORMAT_TYPE_EBML;
    else if(strcmp(contenttype, "video/webm") == 0)
        return FORMAT_TYPE_EBML;
    else if(strcmp(contenttype, "audio/x-matroska") == 0)
        return FORMAT_TYPE_EBML;
    else if(strcmp(contenttype, "video/x-matroska") == 0)
        return FORMAT_TYPE_EBML;
    else if(strcmp(contenttype, "video/x-matroska-3d") == 0)
        return FORMAT_TYPE_EBML;
    else if(strcmp(contenttype, "audio/aac") == 0)
        return FORMAT_TYPE_AAC;
    else if(strcmp(contenttype, "audio/aacp") == 0)
        return FORMAT_TYPE_AAC;
    else if(strcmp(contenttype, "audio/mpeg") == 0)
        return FORMAT_TYPE_MPEG;
    else if(strcmp(contenttype, "video/MP2T") == 0)
        return FORMAT_TYPE_MPEG;
    else
        return FORMAT_TYPE_UNDEFINED;
}


void format_apply_client (format_plugin_t *format, client_t *client)
{
    if (format->type == FORMAT_TYPE_UNDEFINED)
        return;

    if (client && format->parser != client->parser) // a relay client may have a new parser
    {
        if (format->parser) httpp_destroy (format->parser);
        format->parser = client->parser;
    }
    if (format->apply_client)
        format->apply_client (format, client);
}


void format_plugin_clear (format_plugin_t *format, client_t *client)
{
    if (format == NULL)
        return;
    if (format->free_plugin)
        format->free_plugin (format, client);
    free (format->charset);
    free (format->contenttype);
    if (format->parser)
        if (client == NULL || format->parser != client->parser) // a relay client may have a new parser
            httpp_destroy (format->parser);
    memset (format, 0, sizeof (format_plugin_t));
}


int format_get_plugin (format_plugin_t *plugin)
{
    int ret = -1;

    if (plugin->_state)
    {
        INFO1 ("internal format details already created for %s", plugin->mount);
        return 0;
    }
    plugin->qblock_copy = refbuf_copy_default;
    switch (plugin->type)
    {
        case FORMAT_TYPE_OGG:
            ret = format_ogg_get_plugin (plugin);
            break;
        case FORMAT_TYPE_AAC:
        case FORMAT_TYPE_MPEG:
            ret = format_mp3_get_plugin (plugin);
            break;
        case FORMAT_TYPE_EBML:
            ret = format_ebml_get_plugin (plugin);
            break;
        default:
            INFO1 ("unparsed format detected for %s", plugin->mount);
            break;
    }

    return ret;
}


int format_check_frames (struct format_check_t *c)
{
    int ret = -1;
    refbuf_t *r = refbuf_new (16384);
    mpeg_sync sync;
    mpeg_setup (&sync, c->desc);
    mpeg_check_numframes (&sync, 20);
    c->offset = 0;

    do
    {
        int bytes = pread (c->fd, r->data, 16384, c->offset);
        if (bytes <= 0)
            break;

        r->len = bytes;
        int unprocessed = mpeg_complete_frames (&sync, r, 0);
        if (r->len == 0)
        {
            break;
        }
        if (r->len > bytes)
        {
            c->offset = r->len;
            continue;
        }
        if (c->offset == 0)
            c->offset = bytes - (r->len + unprocessed);
        c->type = mpeg_get_type (&sync);
        c->srate = mpeg_get_samplerate (&sync);
        c->channels = mpeg_get_channels (&sync);
        c->bitrate = mpeg_get_bitrate (&sync);
        ret = 0;
        break;
    } while (1);
    refbuf_release (r);
    mpeg_cleanup (&sync);

    return ret;
}


int format_file_read (client_t *client, format_plugin_t *plugin, icefile_handle f)
{
    refbuf_t *refbuf = client->refbuf;
    ssize_t bytes = -1, len, range = 0;
    int unprocessed = 0;

    do
    {
        len = 4096;
        if (refbuf == NULL)
        {
            if (file_in_use (f) == 0)
                return -2;
            refbuf = client->refbuf = refbuf_new (len);
            client->pos = refbuf->len;
            client->queue_pos = 0;
            refbuf->flags |= BUFFER_LOCAL_USE;
        }
        if (client->pos < refbuf->len)
            break;

        if (refbuf->next)
        {
            //DEBUG1 ("next intro block is %d", refbuf->next->len);
            client->refbuf = refbuf->next;
            refbuf->next = NULL;
            refbuf_release (refbuf);
            client->pos = 0;
            return 0;
        }
        if ((refbuf->flags & BUFFER_LOCAL_USE) == 0)
        {
            client_set_queue (client, NULL);
            refbuf = NULL;
            continue;
        }

        if (file_in_use (f) == 0) return -2;

        if (client->connection.discon.time && client->worker->current_time.tv_sec >= client->connection.discon.time)
            return -1;

        bytes = pread (f, refbuf->data, len, client->intro_offset);
        if (bytes <= 0)
        {
            client->flags &= ~CLIENT_HAS_INTRO_CONTENT;
            return bytes < 0 ? -2 : -1;
        }
        refbuf->len = bytes;
        client->pos = 0;
        if (plugin && plugin->align_buffer)
        {
            /* here the buffer may require truncating to keep the buffers aligned on
             * certain boundaries */
            unprocessed = plugin->align_buffer (client, plugin);
            if (unprocessed == bytes)
            {
                if (range == 0)
                    return -1;
                refbuf->len = unprocessed;
                unprocessed = 0;
            }
            if (unprocessed < 0 || unprocessed > bytes)
            {
                unprocessed = 0;
                client->connection.error = 1;
            }
        }
        client->intro_offset += (bytes - unprocessed);
        if (unprocessed == 0 && refbuf->len)
            break;
    } while (1);
    return refbuf->len - client->pos;
}


int format_generic_write_to_client (client_t *client)
{
    refbuf_t *refbuf = client->refbuf;
    int ret;
    const char *buf = refbuf->data + client->pos;
    unsigned int len = refbuf->len - client->pos;

    ret = client_send_bytes (client, buf, len);

    if (ret > 0)
    {
        client->pos += ret;
        client->counter += ret;
        client->queue_pos += ret;
        if ((refbuf->flags & BUFFER_CONTAINS_HDR) && client->pos >= refbuf->len)
        {
            client->connection.sent_bytes = 0;
            if ((client->flags & CLIENT_RANGE_END) || client->connection.discon.sent)
                client->connection.flags |= CONN_FLG_DISCON;
        }
    }

    return ret;
}


static const char *search_ua_namever (const char *ua, const char *patt)
{
    const char *p = ua;
    int len = strlen (patt);
    while (p)
    {
       char *s = strstr (p, patt);
       if (s)
       {
           int off = 0;
           const char *v = s+len;
           if (sscanf (v, "%*[0-9.]%n", &off) == 0 && (v[off] == ' ' || v[off] == '\0'))
               return s;
           p = s+len;
           continue;
       }
       break;
    }
    return NULL;
}


#define FMT_RETURN_ICY                      1
#define FMT_LOWERCASE_TYPE                  (1<<1)
#define FMT_AACP2AAC                        (1<<2)
#define FMT_DISABLE_CHUNKED                 (1<<3)
#define FMT_REDIRECT_WPARAM                 (1<<4)
#define FMT_DROP_RANGE                      (1<<5)


static int apply_client_tweaks (ice_http_t *http, format_plugin_t *plugin, client_t *client)
{
    const char *fs = httpp_getvar (client->parser, "__FILESIZE");
    const char *opt = httpp_get_query_param (client->parser, "_hdr");
    const char *contenttypehdr = "Content-Type";
    const char *contenttype = plugin ? plugin->contenttype : "application/octet-stream";
    const char *useragent = httpp_getvar (client->parser, "user-agent");
    int fmtcode = FMT_AACP2AAC, http_flags = 0;
    uint64_t length = 0;

    do {
        if (opt)
        {
            fmtcode = atoi (opt);
            break;
        }
        // ignore following settings for files.
        if (fs == NULL && useragent && plugin)
        {
            if (strstr (useragent, "shoutcastsource")) /* hack for mpc */
                fmtcode |= FMT_RETURN_ICY;
            if (strstr (useragent, "Windows-Media-Player")) /* hack for wmp*/
                fmtcode |= FMT_RETURN_ICY;
            if (strstr (useragent, "RealMedia")) /* hack for rp (mainly mobile) */
                fmtcode |= FMT_RETURN_ICY;
            if (strstr (useragent, "Shoutcast Server")) /* hack for sc_serv */
                fmtcode |= FMT_LOWERCASE_TYPE;

            if (search_ua_namever (useragent, "Safari/"))
            {   // Safari is an oddball, seems to use multiple connections with one being a range request of 0-1 to get the
                // size. To add to the confusion, chrome and others use the safari in the useragent, supposedly for compatability
                // although is does do the same thing.
                if (search_ua_namever (useragent, "Chrome/") == NULL && search_ua_namever (useragent, "Chromium/") == NULL)
                    fmtcode |= FMT_REDIRECT_WPARAM|FMT_DROP_RANGE;
            }
            if (strstr (useragent, "BlackBerry"))
                fmtcode |= FMT_RETURN_ICY;
        }
    } while (0);

    if (fmtcode & FMT_DISABLE_CHUNKED)
        client->flags &= ~CLIENT_KEEPALIVE;
    if (fmtcode & FMT_RETURN_ICY)
        http_flags |= ICE_HTTP_USE_ICY;
    if (fmtcode & FMT_LOWERCASE_TYPE)
        contenttypehdr = "content-type";
    // the following may eventually go and just assume aac instead of aacp
    if ((fmtcode & FMT_AACP2AAC) && plugin->type == FORMAT_TYPE_AAC) // ie for avoiding audio/aacp
        contenttype = "audio/aac";
    if (fmtcode & FMT_REDIRECT_WPARAM)
    {
        const char *ic2 = httpp_get_query_param (client->parser, "_ic2");
        if (ic2 == NULL && client->respcode == 0)
        {
            const char *uhost = httpp_getvar (client->parser, "host");
            const char *args = httpp_getvar (client->parser, HTTPP_VAR_QUERYARGS); // maybe null
            const char *uri = httpp_getvar (client->parser, HTTPP_VAR_URI);
            if (uhost)
            {   // trigger a redirect with a random query param, to trick any caching
                const char *proto = not_ssl_connection (&client->connection) ? "http" : "https";
                char sep = (args) ? '&' : '?';
                unsigned plen = 40 + ((args) ? strlen (args) : 0);
                char params [plen];
                snprintf (params, sizeof params,"%s%c_ic2=%"PRId64, (args)?args:"", sep, timing_get_time());
                ice_http_setup_flags (http, client, 302, 0, NULL);
                ice_http_printf (http, "Location", 0, "%s://%s%s%s", proto, uhost, uri, params);
                client->connection.flags |= CONN_FLG_DISCON;
                client->connection.discon.sent = 0;
                client->flags &= ~CLIENT_AUTHENTICATED;
                return fmtcode;
            }
        }
        fmtcode &= ~FMT_REDIRECT_WPARAM;
    }
    if (fmtcode & FMT_DROP_RANGE)
    {
        client->connection.flags &= ~CONN_FLG_DISCON;
        client->connection.discon.sent = 0;
        client->connection.start_pos = 0;
        client->flags &= ~CLIENT_RANGE_END;
    }

    /* hack for flash player, it wants a length. */
    if (httpp_getvar (client->parser, "x-flash-version"))
        length = 221183499;
    else
    {   // flash may not send above header, so check for swf in referer
        const char *referer = httpp_getvar (client->parser, "referer");
        if (referer)
        {
            int len = strcspn (referer, "?");
            if (len >= 4 && strncmp (referer+len-4, ".swf", 4) == 0)
                length = 221183499;
        }
    }

    if (fs)
    {
        uint64_t len = (uint64_t)-1;
        sscanf (fs, "%" SCNuMAX, &len);
        if (length == 0 || len < length)
            length = len;
    }
    else if (http->in_length)
    {
        if (length == 0 || http->in_length < length)
            length = http->in_length;
    }
    if (client->flags & CLIENT_RANGE_END)
    {
        if (length && client->connection.discon.sent > length)
            client->connection.discon.sent = length - 1;

        uint64_t range = client->connection.discon.sent;
        char total_size [32] = "*";

        if (range == 0 || (fs == NULL && range > (1<<30)))
        {       // ignore most range requests on streams, treat as full
            client->connection.discon.sent = 0;
            client->intro_offset = 0;
            client->flags &= ~CLIENT_RANGE_END;
            length = -1;
        }
        else
        {
            ice_http_setup_flags (http, client, 206, 0, NULL);
            uint64_t last = client->connection.discon.sent + client->connection.start_pos -1;
            if (fs)
                snprintf (total_size, sizeof total_size, "%" PRIu64, length);
            else
                snprintf (total_size, sizeof total_size, "%" PRIu64, ((uint64_t)1<<30)-1);
            ice_http_printf (http, "Accept-Ranges", 0, "bytes");
            ice_http_printf (http, "Content-Range", 0, "bytes %" PRIu64 "-%" PRIu64 "/%s",
                    (uint64_t)client->connection.start_pos, last, total_size );
            http->in_length = range > 0 ? range : -1;
            DEBUG3 ("client %" PRI_ConnID ", req %s range %" PRIu64 " requested\n", CONN_ID(client), client->mount, range);
            if (range <= 100 && client->parser->req_type != httpp_req_head)
            {
                char line [range+1];
                memset (line, 'F', range);
                line[range] = 0;
                ice_http_printf (http, NULL, 0, "%s", line);
                client->connection.flags &= ~CONN_FLG_DISCON;
                client->connection.discon.sent = 0;
                client->flags &= ~(CLIENT_AUTHENTICATED|CLIENT_HAS_INTRO_CONTENT); // drop these flags
                DEBUG2 ("wrote %" PRIu64 " bytes for partial request from %s", range, &client->connection.ip[0]);
            }
        }
    }
    if (client->respcode == 0)
    {
        ice_http_setup_flags (http, client, 200, http_flags, NULL);
        http->in_length = (off_t)((length) ? length : -1);
        int chunked = 0;

        if (plugin && plugin->flags & FORMAT_FL_ALLOW_HTTPCHUNKED)
            chunked = (http->in_major == 1 && http->in_minor == 1) ? 1 : 0;
        if (chunked && (fmtcode & FMT_DISABLE_CHUNKED) == 0)
        {
            client->flags |= CLIENT_CHUNKED;
            ice_http_printf (http, "Transfer-Encoding", 0, "chunked");
        }
    }
    if (contenttype)
        ice_http_printf (http, contenttypehdr, 0, "%s", contenttype);

    return fmtcode;
}


int format_client_headers (format_plugin_t *plugin, ice_http_t *http, client_t *client)
{
    if (apply_client_tweaks (http, plugin, client) & FMT_REDIRECT_WPARAM)
        return 0;

    if (plugin && plugin->parser)
    {
        /* iterate through source http headers and send to client */
        avl_tree_rlock (plugin->parser->vars);
        avl_node *node = avl_get_first (plugin->parser->vars);
        while (node)
        {
            http_var_t *var = (http_var_t *)node->key;
            node = avl_get_next (node);

            if (strcasecmp (var->name, "ice-audio-info") == 0)
            {
                /* convert ice-audio-info to icy-br */
                char *brfield = NULL;
                unsigned int bitrate;

                brfield = strstr (var->value, "bitrate=");
                if (brfield && sscanf (brfield, "bitrate=%u", &bitrate) == 1)
                    ice_http_printf (http, "icy-br", 0, "%u", bitrate);
                ice_http_printf (http, var->name, 0, "%s", var->value);
                continue;
            }
            if (strcasecmp (var->name, "ice-password") == 0) continue;
            if (strcasecmp (var->name, "icy-metaint") == 0) continue;
            if (strncasecmp (var->name, "Access-control-", 15) == 0) continue;
            if (strncasecmp ("ice-", var->name, 4) == 0)
            {
                if (!strcasecmp ("ice-public", var->name))
                    ice_http_printf (http, "icy-pub", 0, "%s", var->value);
                else
                    if (strcasecmp ("ice-bitrate", var->name) == 0)
                        ice_http_printf (http, "icy-br", 0, "%s", var->value);
                    else
                    {
                        char icyname[1000];
                        snprintf (icyname, sizeof icyname, "icy%s", var->name + 3);
                        ice_http_printf (http, icyname, 0, "%s", var->value);
                    }
                continue;
            }
            if (!strncasecmp ("icy-", var->name, 4))
                ice_http_printf (http, var->name, 0, "%s", var->value);
        }
        avl_tree_unlock (plugin->parser->vars);
    }
    return 0;
}

