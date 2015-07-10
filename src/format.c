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
    format->read_bytes = 0;
    format->sent_bytes = 0;
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


int format_file_read (client_t *client, format_plugin_t *plugin, icefile_handle f)
{
    refbuf_t *refbuf = client->refbuf;
    ssize_t bytes = -1, len;
    int unprocessed = 0;

    do
    {
        len = 8192;
        if (refbuf == NULL)
        {
            if (file_in_use (f) == 0)
                return -2;
            refbuf = client->refbuf = refbuf_new (len);
            client->flags |= CLIENT_HAS_INTRO_CONTENT;
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

        if (client->flags & CLIENT_RANGE_END)
        {
            ssize_t range;
            if (client->intro_offset >= client->connection.discon.offset)
            {
                DEBUG0 ("End of requested range");
                return -1;
            }
            range = client->connection.discon.offset - client->intro_offset + 1;
            if (range < len)
                len = range;
        }
        else
            if (client->connection.discon.time && client->worker->current_time.tv_sec >= client->connection.discon.time)
                return -1;

        bytes = pread (f, refbuf->data, len, client->intro_offset);
        if (bytes <= 0)
            return bytes < 0 ? -2 : -1;

        if (client->connection.sent_bytes > 0 && client->intro_offset == 0 &&
                bytes >= 10 && memcmp (refbuf->data, "ID3", 3) == 0)
        {
            // special case of filtering ID3 from fallback files
            unsigned char *p = (unsigned char*)refbuf->data;
            
            if (p[3] < 0xFF && p[4] < 0xFF && (p[5] & 0xF) == 0)
            {
                int ver = p[3], rev = p[4];
                size_t size = (p[6] & 0x7f);
                size = (size << 7) + (p[7] & 0x7f);
                size = (size << 7) + (p[8] & 0x7f);
                size = (size << 7) + (p[9] & 0x7f);

                client->intro_offset = size + 10;
                DEBUG3 ("Detected ID3v2 (%d.%d) in file, tag size %" PRIu64, ver, rev, (uint64_t)size);
                continue;
            }
        }
        refbuf->len = bytes;
        client->pos = 0;
        if (plugin && plugin->align_buffer)
        {
            /* here the buffer may require truncating to keep the buffers aligned on
             * certain boundaries */
            unprocessed = plugin->align_buffer (client, plugin);
            if (unprocessed == bytes)
                return -1;
            if (unprocessed < 0 || unprocessed > bytes)
            {
                unprocessed = 0;
                client->connection.error = 1;
            }
        }
        client->intro_offset += (bytes - unprocessed);
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
    }

    return ret;
}


int format_general_headers (format_plugin_t *plugin, client_t *client)
{
    unsigned remaining = 4096 - client->refbuf->len;
    char *ptr = client->refbuf->data + client->refbuf->len, *junk = NULL;
    int bytes = 0;
    int bitrate_filtered = 0;
    avl_node *node;
    ice_config_t *config;
    uint64_t length = 0; 

    /* hack for flash player, it wants a length. */
    if (httpp_getvar (client->parser, "x-flash-version"))
        length = 221183499;
    else
    {
        // flash may not send above header, so check for swf in referer
        const char *referer = httpp_getvar (client->parser, "referer");
        if (referer)
        {
            int len = strcspn (referer, "?");
            if (len >= 4 && strncmp (referer+len-4, ".swf", 4) == 0)
                length = 221183499;
        }
    }

    if (client->respcode == 0)
    {
        const char *useragent = httpp_getvar (client->parser, "user-agent");
        const char *protocol = "HTTP/1.0";
        const char *contenttypehdr = "Content-Type";
        const char *contenttype = plugin->contenttype;
        const char *fs = httpp_getvar (client->parser, "__FILESIZE");

        if (useragent)
        {
            const char *resp = httpp_get_query_param (client->parser, "_hdr");
            int fmtcode = 0;
#define FMT_RETURN_ICY          1
#define FMT_LOWERCASE_TYPE      2
#define FMT_FORCE_AAC           4

            do
            {
                if (resp)
                {
                    fmtcode = atoi (resp);
                    break;
                }
                if (fs) break;  // ignore following settings for files.
                if (strstr (useragent, "shoutcastsource")) /* hack for mpc */
                    fmtcode = FMT_RETURN_ICY;
                if (strstr (useragent, "Windows-Media-Player")) /* hack for wmp*/
                    fmtcode = FMT_RETURN_ICY;
                if (strstr (useragent, "RealMedia")) /* hack for rp (mainly mobile) */
                    fmtcode = FMT_RETURN_ICY;
                if (strstr (useragent, "Shoutcast Server")) /* hack for sc_serv */
                    fmtcode = FMT_LOWERCASE_TYPE;
                // if (strstr (useragent, "Sonos"))
                //    contenttypehdr = "content-type";
                if (plugin->type == FORMAT_TYPE_AAC && strstr (useragent, "AppleWebKit"))
                    fmtcode |= FMT_FORCE_AAC;
                if (strstr (useragent, "BlackBerry"))
                {
                    fmtcode |= FMT_RETURN_ICY;
                    if (plugin->type == FORMAT_TYPE_AAC)
                        fmtcode |= FMT_FORCE_AAC;
                }
            } while (0);
            if (fmtcode & FMT_RETURN_ICY)
                protocol = "ICY";
            if (fmtcode & FMT_LOWERCASE_TYPE)
                contenttypehdr = "content-type";
            if (fmtcode & FMT_FORCE_AAC) // ie for avoiding audio/aacp
                contenttype = "audio/aac";
        }
        if (fs)
        {
            uint64_t len = (uint64_t)-1;
            sscanf (fs, "%" SCNuMAX, &len);
            if (length == 0 || len < length)
                length = len;
        }
        if (client->flags & CLIENT_RANGE_END)
        {
            if (length && client->connection.discon.offset > length)
                client->connection.discon.offset = length - 1;

            if (client->connection.discon.offset == 0 || client->intro_offset >= client->connection.discon.offset)
            {
                DEBUG2 ("client range invalid (%" PRIu64 ", %" PRIu64 ")", client->intro_offset, client->connection.discon.offset);
                return -1;
            }
            length = client->connection.discon.offset - client->intro_offset + 1;
            if (fs) // allow range on files
            {
                client->respcode = 206;
                bytes = snprintf (ptr, remaining, "%s 206 Partial Content\r\n"
                        "%s: %s\r\n"
                        "Accept-Ranges: bytes\r\n"
                        "Content-Length: %" PRIu64 "\r\n"
                        "Content-Range: bytes %" PRIu64 "-%" PRIu64 "/%" PRIu64 "\r\n",
                        protocol, contenttypehdr,
                        contenttype ? contenttype : "application/octet-stream",
                        length,
                        client->intro_offset, client->connection.discon.offset, length);
            }
            else
            {
                // for range requests on streams we return a 200 OK but only send a couple of bytes
                length = 2;
                client->connection.discon.offset = client->intro_offset + 2;
                if (client->parser->req_type != httpp_req_head && remaining - bytes > length + 2)
                {
                    junk = malloc (length+1);
                    memset (junk, 255, length);
                    junk[length] = '\0';
                    plugin = NULL;
                    client->flags &= ~CLIENT_AUTHENTICATED;
                    DEBUG2 ("wrote %d bytes for partial request from %s", (int)length, &client->connection.ip[0]);
                }
            }
        }
        if (client->respcode == 0)
        {
            if (length)
            {
                client->respcode = 200;
                bytes = snprintf (ptr, remaining, "%s 200 OK\r\n"
                        "Content-Length: %" PRIu64 "\r\n"
                        "%s: %s\r\n", protocol, length, contenttypehdr, contenttype);
            }
            else
            {
                client->respcode = 200;
                bytes = snprintf (ptr, remaining, "%s 200 OK\r\nAccept-Ranges: bytes\r\n"
                        "%s: %s\r\n", protocol, contenttypehdr, contenttype);
            }
        }
        remaining -= bytes;
        ptr += bytes;
    }

    if (plugin && plugin->parser)
    {
        /* iterate through source http headers and send to client */
        avl_tree_rlock (plugin->parser->vars);
        node = avl_get_first (plugin->parser->vars);
        while (node)
        {
            int next = 1;
            http_var_t *var = (http_var_t *)node->key;
            bytes = 0;
            if (!strcasecmp (var->name, "ice-audio-info"))
            {
                /* convert ice-audio-info to icy-br */
                char *brfield = NULL;
                unsigned int bitrate;

                if (bitrate_filtered == 0)
                    brfield = strstr (var->value, "bitrate=");
                if (brfield && sscanf (brfield, "bitrate=%u", &bitrate))
                {
                    bytes = snprintf (ptr, remaining, "icy-br:%u\r\n", bitrate);
                    next = 0;
                    bitrate_filtered = 1;
                }
                else
                    /* show ice-audio_info header as well because of relays */
                    bytes = snprintf (ptr, remaining, "%s: %s\r\n", var->name, var->value);
            }
            else
            {
                if (strcasecmp (var->name, "ice-password") &&
                        strcasecmp (var->name, "icy-metaint"))
                {
                    if (!strncasecmp ("ice-", var->name, 4))
                    {
                        if (!strcasecmp ("ice-public", var->name))
                            bytes = snprintf (ptr, remaining, "icy-pub:%s\r\n", var->value);
                        else
                            if (!strcasecmp ("ice-bitrate", var->name))
                                bytes = snprintf (ptr, remaining, "icy-br:%s\r\n", var->value);
                            else
                                bytes = snprintf (ptr, remaining, "icy%s:%s\r\n",
                                        var->name + 3, var->value);
                    }
                    else 
                        if (!strncasecmp ("icy-", var->name, 4))
                        {
                            bytes = snprintf (ptr, remaining, "icy%s:%s\r\n",
                                    var->name + 3, var->value);
                        }
                }
            }

            remaining -= bytes;
            ptr += bytes;
            if (next)
                node = avl_get_next (node);
        }
        avl_tree_unlock (plugin->parser->vars);
    }

    config = config_get_config();
    bytes = snprintf (ptr, remaining, "Server: %s\r\n", config->server_id);
    config_release_config();
    remaining -= bytes;
    ptr += bytes;

    /* prevent proxy servers from caching */
    bytes = snprintf (ptr, remaining, "Cache-Control: no-cache, no-store\r\nPragma: no-cache\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Headers: Origin, Accept, X-Requested-With, Content-Type\r\n"
            "Access-Control-Allow-Methods: GET, OPTIONS, HEAD\r\n"
            "Connection: close\r\n"
            "Expires: Mon, 26 Jul 1997 05:00:00 GMT\r\n");
    remaining -= bytes;
    ptr += bytes;

    bytes = snprintf (ptr, remaining, "\r\n%s", junk ? junk : "");
    remaining -= bytes;
    ptr += bytes;

    client->refbuf->len = 4096 - remaining;
    client->refbuf->flags |= WRITE_BLOCK_GENERIC;
    free (junk);
    return 0;
}

