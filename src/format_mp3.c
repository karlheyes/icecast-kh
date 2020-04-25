/* -*- c-basic-offset: 4; -*- */
/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2010-2019, Karl Heyes <karl@kheyes.plus.com>,
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org>,
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

/* format_mp3.c
**
** format plugin for mp3
**
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#include "refbuf.h"
#include "source.h"
#include "client.h"

#include "stats.h"
#include "format.h"
#include "httpp/httpp.h"

#include "logging.h"

#include "format_mp3.h"
#include "flv.h"
#include "mpeg.h"
#include "global.h"

#define CATMODULE "format-mp3"

/* Note that this seems to be 8192 in shoutcast - perhaps we want to be the
 * same for compability with crappy clients?
 */
#define ICY_METADATA_INTERVAL 16000

static void format_mp3_free_plugin(format_plugin_t *plugin, client_t *client);
static refbuf_t *mp3_get_filter_meta (source_t *source);
static refbuf_t *mp3_get_no_meta (source_t *source);

static int  format_mp3_create_client_data (format_plugin_t *plugin, client_t *client);
static void free_mp3_client_data (client_t *client);
static int  format_mp3_write_buf_to_client(client_t *client);
static int  write_mpeg_buf_to_client (client_t *client);
static void write_mp3_to_file (struct source_tag *source, refbuf_t *refbuf);
static void mp3_set_tag (format_plugin_t *plugin, const char *tag, const char *in_value, const char *charset);
static void format_mp3_apply_settings (format_plugin_t *format, mount_proxy *mount);
static int  mpeg_process_buffer (client_t *client, format_plugin_t *plugin);
static void swap_client (client_t *new_client, client_t *old_client);
static void mpeg_apply_client (format_plugin_t *plugin, client_t *client);
static void size_up_qblock (source_t *source);


/* client format flags */
#define CLIENT_INTERNAL_FORMAT          (CLIENT_FORMAT_BIT << 4)
#define CLIENT_IN_METADATA              (CLIENT_INTERNAL_FORMAT)
#define CLIENT_USING_BLANK_META         (CLIENT_INTERNAL_FORMAT<<1)

#ifndef ICY_DEFAULT_CHARSET
#define ICY_DEFAULT_CHARSET             "UTF-8"
#endif

static refbuf_t blank_icy = { 0 , 1, NULL, NULL, "\001StreamTitle='';", 17 };
static struct metadata_block blank_meta = { 1, 1, &blank_icy, NULL, NULL, NULL };


static void metadata_blk_release (struct metadata_block *mb)
{
    if (mb)
    {
        if (mb->count > 0)
            mb->count--;
        if (mb->count == 0)
        {
            refbuf_release (mb->icy);
            refbuf_release (mb->iceblock);
            refbuf_release (mb->flv);
            refbuf_release (mb->id3);
            free (mb);
        }
    }
}


static void metadata_blk_ref_inc (struct metadata_block *mb)
{
    if (mb)
        mb->count++;
}


static struct metadata_block * metadata_blk_copy (struct metadata_block *mb)
{
    struct metadata_block *r = calloc (1, sizeof (*r));
    if (mb)
    {
        r->icy = refbuf_copy (mb->icy);
        r->iceblock = refbuf_copy (mb->iceblock);
        r->flv = refbuf_copy (mb->flv);
        if (mb->id3)
            r->id3 = refbuf_copy (mb->id3);
    }
    r->count = 1;
    return r;
}


void format_mpeg_detach_qb (source_t *source, refbuf_t *block)
{
    if (block)
    {
        struct metadata_block *meta = block->associated;
        block->associated = NULL;
        metadata_blk_release (meta);
    }
}


refbuf_t *format_mpeg_qblock_copy (refbuf_t *orig)
{
    refbuf_t *ret = refbuf_copy (orig);

    if (orig->associated)
        ret->associated = metadata_blk_copy (orig->associated);
    return ret;
}


int format_mp3_get_plugin (format_plugin_t *plugin)
{
    mp3_state *state = calloc(1, sizeof(mp3_state));

    plugin->get_buffer = mp3_get_no_meta;
    plugin->write_buf_to_client = write_mpeg_buf_to_client;
    plugin->write_buf_to_file = write_mp3_to_file;
    plugin->create_client_data = format_mp3_create_client_data;
    plugin->free_plugin = format_mp3_free_plugin;
    plugin->align_buffer = mpeg_process_buffer;
    plugin->swap_client = swap_client;
    plugin->set_tag = mp3_set_tag;
    plugin->apply_settings = format_mp3_apply_settings;
    plugin->apply_client = mpeg_apply_client;
    plugin->detach_queue_block = format_mpeg_detach_qb;
    plugin->qblock_copy = format_mpeg_qblock_copy;
    plugin->_state = state;
    state->max_send_size = 0;
    state->interval = -1;
    INFO1 ("Created format details for %s", plugin->mount);
    return 0;
}


static void mpeg_apply_client (format_plugin_t *plugin, client_t *client)
{
    mp3_state *source_mp3 = plugin->_state;
    const char *s;
    const char *metadata;
    refbuf_t *meta;

    source_mp3->interval = -1;
    source_mp3->offset = 0;
    source_mp3->build_metadata_len = 0;

    metadata_blk_release (source_mp3->metadata);
    source_mp3->metadata = NULL;
    refbuf_release (source_mp3->read_data);
    source_mp3->read_data = NULL;
    source_mp3->read_count = 0;
    free (plugin->contenttype);
    plugin->contenttype = NULL;

    if (client == NULL)
        return;

    if (plugin->contenttype == NULL)
    {
        s = httpp_getvar (plugin->parser, "content-type");
        if (s)
            plugin->contenttype = strdup (s);
        else
            /* We default to MP3 audio for old clients without content types */
            plugin->contenttype = strdup ("audio/mpeg");
    }

    meta = refbuf_new (17);
    memcpy (meta->data, "\001StreamTitle='';", 17);
    source_mp3->metadata = metadata_blk_copy (NULL);
    source_mp3->metadata->icy = meta;
    source_mp3->interval = -1;

    mpeg_cleanup (client->format_data);

    metadata = httpp_getvar (plugin->parser, "icy-metaint");
    if (metadata)
    {
        client->flags |= CLIENT_META_INSTREAM;
        source_mp3->inline_metadata_interval = atoi (metadata);
        if (source_mp3->inline_metadata_interval > 0)
        {
            source_mp3->offset = 0;
            plugin->get_buffer = mp3_get_filter_meta;
            if (source_mp3->inline_metadata_interval > 7999 && source_mp3->inline_metadata_interval < 32001)
                source_mp3->interval = source_mp3->inline_metadata_interval;
            else
                source_mp3->interval = ICY_METADATA_INTERVAL;
            INFO2 ("icy metadata format expected on %s, interval %d", plugin->mount, source_mp3->interval);
        }
    }
    if (plugin->type == FORMAT_TYPE_AAC || plugin->type == FORMAT_TYPE_MPEG)
    {
        if (client->format_data == NULL)
            client->format_data = malloc (sizeof (mpeg_sync));
        mpeg_setup (client->format_data, client->connection.ip);
        plugin->write_buf_to_client = write_mpeg_buf_to_client;
    }
    if (source_mp3->read_data == NULL)
    {
        source_mp3->read_data = refbuf_new (8000);
        source_mp3->read_count = 0;
    }
}


static void mp3_set_tag (format_plugin_t *plugin, const char *tag, const char *in_value, const char *charset)
{
    mp3_state *source_mp3 = plugin->_state;
    char *value = NULL;

    if (charset && (strcasecmp (charset, "utf-8") == 0 || strcasecmp (charset, "utf8") == 0))
        charset = NULL;

    if (tag==NULL)
    {
        source_mp3->update_metadata = charset ? 3 : 1;
        return;
    }

    if (in_value)
    {
        if (charset)
            value = util_conv_string (in_value, charset, "UTF8");
        if (value == NULL)
            value = strdup (in_value);
    }

    if (strcmp (tag, "title") == 0)
    {
        free (source_mp3->url_title);
        source_mp3->url_title = value;
    }
    else if (strcmp (tag, "artist") == 0)
    {
        free (source_mp3->url_artist);
        source_mp3->url_artist = value;
    }
    else if (strcmp (tag, "url") == 0)
    {
        free (source_mp3->inline_url);
        source_mp3->inline_url = value;
    }
    else
        free (value);
}


static int parse_icy_metadata (const char *name, mp3_state *source_mp3)
{
    int meta_len = source_mp3->build_metadata_len, extra_len = 0;
    char *extra = NULL;
    char *metadata = source_mp3->build_metadata;

    if (meta_len <= 1 || source_mp3->metadata == NULL)
        return 0;       // nothing to compare

    refbuf_t *icy = source_mp3->metadata->icy;
    if (meta_len == icy->len && memcmp (metadata, icy->data, meta_len) == 0)
        return 0;       // no change

    if (metadata == NULL || meta_len < 16 || meta_len > 4081)
        return -1;
    if (*(unsigned char*)metadata * 16 + 1 != meta_len)
        return -1;
    metadata++;
    meta_len--;
    do
    {
        char *s, *end = NULL;
        int len, term_len = 2;
        if (strncmp (metadata, "StreamTitle='", 13) == 0)
        {
            if ((end = strstr (metadata+13, "';")) == NULL)
                break;
            len = end - metadata - 12;
            s = malloc (len);
            snprintf (s, len, "%.*s", len-1, metadata+13);
            free (source_mp3->url_title);
            source_mp3->url_title = s;
            INFO2 ("incoming title for %s %s", name, s);
            if (source_mp3->url_artist)
            {
                free (source_mp3->url_artist);
                source_mp3->url_artist = NULL;
            }
        }
        else if (strncmp (metadata, "StreamUrl='", 11) == 0)
        {
            if ((end = strstr (metadata+11, "';")) == NULL)
                break;
            len = end - metadata - 10;
            s = malloc (len);
            snprintf (s, len, "%.*s", len-1, metadata+11);
            free (source_mp3->inline_url);
            source_mp3->inline_url = s;
            INFO2 ("incoming URL for %s %s", name, s);
        }
        else if ((end = strstr (metadata, "';")) == NULL)
            break;
        else
        {
            len = end - metadata + 2;
            s = realloc (extra, extra_len + len + 1);
            if (s)
            {
                sprintf (s + extra_len, "%.*s", len, metadata);
                extra_len += len;
                extra = s;
            }
            else
            {
                WARN1 ("realloc failed for %d", extra_len + len + 1);
                break;
            }
        }
        meta_len -= (end - metadata + term_len);
        metadata = end + term_len;
        source_mp3->update_metadata = 1;
    } while (meta_len > 0);
    if (extra)
        INFO2 ("extra meta for %s (%s)", name, extra);
    free (source_mp3->extra_icy_meta);
    source_mp3->extra_icy_meta = extra;
    return 0;
}


static void format_mp3_apply_settings (format_plugin_t *format, mount_proxy *mount)
{
    mp3_state *source_mp3 = format->_state;

    if (source_mp3 == NULL)
        return;
    source_mp3->interval = -1;
    free (format->charset);
    format->charset = NULL;

    source_mp3->qblock_sz = 4096;
    source_mp3->max_send_size = 0;
    format->flags &= ~FORMAT_FL_ALLOW_HTTPCHUNKED;
    if (mount)
    {
        if (mount->max_send_size)
            source_mp3->max_send_size = mount->max_send_size;
        if (mount->mp3_meta_interval >= 0)
            source_mp3->interval = mount->mp3_meta_interval;
        if (mount->charset)
            format->charset = strdup (mount->charset);
        if (mount->allow_chunked)
           format->flags |= FORMAT_FL_ALLOW_HTTPCHUNKED;
    }
    if (source_mp3->interval < 0)
    {
        const char *metadata = httpp_getvar (format->parser, "icy-metaint");
        source_mp3->interval = ICY_METADATA_INTERVAL;
        if (metadata)
        {
            int interval = atoi (metadata);
            if (interval > 7999 && interval < 32000)
                source_mp3->interval = interval;
        }
    }
    if (format->charset == NULL)
        format->charset = strdup (ICY_DEFAULT_CHARSET);

    DEBUG1 ("sending metadata interval %d", source_mp3->interval);
    DEBUG1 ("charset %s", format->charset);
}


/* called from the source thread when the metadata has been updated.
 * The artist title are checked and made ready for clients to send
 */
static void mp3_set_title (source_t *source)
{
    const char streamtitle[] = "StreamTitle='";
    const char streamurl[] = "StreamUrl='";
    size_t size;
    unsigned char len_byte;
    unsigned int len = sizeof(streamtitle) + 2; /* the StreamTitle, quotes, ; and null */
    mp3_state *source_mp3 = source->format->_state;
    char *charset = NULL;

    if (source_mp3->metadata && (source_mp3->metadata->on_queue) == 0 && source->queue_size)
    {
         WARN1 ("ignoring this update to metadata on %s, as previous update has not had chance", source->mount);
         return;
    }
    /* work out message length */
    if (source_mp3->url_artist)
        len += strlen (source_mp3->url_artist);
    if (source_mp3->url_title)
        len += strlen (source_mp3->url_title);
    if (source_mp3->url_artist && source_mp3->url_title)
        len += 3;
    if (source_mp3->inline_url)
        len += strlen (source_mp3->inline_url) + strlen (streamurl) + 2;
    else if (source_mp3->url)
        len += strlen (source_mp3->url) + strlen (streamurl) + 2;
    if (source_mp3->extra_icy_meta)
        len += strlen (source_mp3->extra_icy_meta);
#define MAX_META_LEN 255*16
    if (len > MAX_META_LEN)
    {
        WARN1 ("Metadata too long at %d chars", len);
        return;
    }
    if (source_mp3->update_metadata == 1) // 1 lookup for conversion, 3 already converted
        charset = source->format->charset;

    /* work out the metadata len byte */
    len_byte = (len-1) / 16 + 1;

    /* now we know how much space to allocate, +1 for the len byte */
    size = len_byte * 16 + 1;

    refbuf_t *icy = refbuf_new (size);
    if (icy)
    {
        refbuf_t *flvmeta = flv_meta_allocate (4000);
        refbuf_t *iceblock = refbuf_new (4096);
        mpeg_sync *mpeg_sync = source->client->format_data;
        mp3_state *source_mp3 = source->format->_state;
        char *ibp = iceblock->data + 2;
        int r, n, ib_len = iceblock->len - 2;

        xmlSetStructuredErrorFunc (source->mount, config_xml_parse_failure);
        memset (icy->data, '\0', size);
        stats_lock (source->stats, source->mount);

        n = snprintf (ibp, ib_len, "%cmode=updinfo\n", 0);
        if (n > 0 || n < ib_len) { ibp += n; ib_len -= n; }

        if (mpeg_sync)
        {
            char *str = stats_retrieve (source->stats, "server_name");
            if (str) 
            {
                flv_meta_append_string (flvmeta, "name", str);
                free (str);
            }
            str = stats_retrieve (source->stats, "server_description");
            if (str) 
            {
                flv_meta_append_string (flvmeta, "description", str);
                free (str);
            }
            flv_meta_append_number (flvmeta, "audiodatarate", syncframe_bitrate (mpeg_sync));
            flv_meta_append_number (flvmeta, "audiosamplerate", syncframe_samplerate (mpeg_sync));
            flv_meta_append_bool (flvmeta, "stereo", syncframe_channels (mpeg_sync) == 2 ? 1 : 0);
            flv_meta_append_number (flvmeta, "audiocodecid",
                            (double)(mpeg_get_type (mpeg_sync) == FORMAT_TYPE_AAC ? 10 : 2));
        }
        const char *title;
        if (source_mp3->url_artist && source_mp3->url_title)
        {
            title = source_mp3->url_title;
            stats_set_conv (source->stats, "artist", source_mp3->url_artist, charset);
            stats_set_conv (source->stats, "title", source_mp3->url_title, charset);
            r = snprintf (icy->data, size, "%c%s%s - %s", len_byte, streamtitle,
                    source_mp3->url_artist, source_mp3->url_title);
            flv_meta_append_string (flvmeta, "artist", source_mp3->url_artist);

            n = snprintf (ibp, ib_len, "artist=%s\n", source_mp3->url_artist);
            if (n > 0 || n < ib_len) { ibp += n; ib_len -= n; }
        }
        else
        {
            title = source_mp3->url_title ? source_mp3->url_title : "";
            r = snprintf (icy->data, size, "%c%s%s", len_byte, streamtitle, title);
            stats_set_conv (source->stats, "title", icy->data+14, charset);
            stats_set (source->stats, "artist", NULL);
        }
        logging_playlist (source->mount, icy->data+14, source->listeners);
        strcat (icy->data+14, "';");
        flv_meta_append_string (flvmeta, "title", title);

        n = snprintf (ibp, ib_len, "title=%s\n", title);
        if (n > 0 || n < ib_len) { ibp += n; ib_len -= n; }

        if (r > 0)
        {
            r += 2;
            if (source_mp3->inline_url && size-r > strlen (source_mp3->inline_url)+13)
            {
                r += snprintf (icy->data+r, size-r, "StreamUrl='%s';", source_mp3->inline_url);
                flv_meta_append_string (flvmeta, "URL", source_mp3->inline_url);
                stats_set (source->stats, "metadata_url", source_mp3->inline_url);

                n = snprintf (ibp, ib_len, "URL=%s\n", source_mp3->inline_url);
                if (n > 0 || n < ib_len) { ibp += n; ib_len -= n; }
            }
            else if (source_mp3->url)
            {
                r += snprintf (icy->data+r, size-r, "StreamUrl='%s';", source_mp3->url);
                flv_meta_append_string (flvmeta, "URL", source_mp3->url);
                stats_set (source->stats, "metadata_url", source_mp3->url);
                n = snprintf (ibp, ib_len, "URL=%s\n", source_mp3->url);
                if (n > 0 || n < ib_len) { ibp += n; ib_len -= n; }
            }
            if (source_mp3->extra_icy_meta)
            {
                r += snprintf (icy->data+r, size-r, "%s", source_mp3->extra_icy_meta);
            }
        }
        DEBUG1 ("icy metadata as %.80s...", icy->data+1);
        yp_touch (source->mount, source->stats);

        flv_meta_append_string (flvmeta, NULL, NULL);

        if (ib_len > 0) ib_len--; // add nul char to help parsing
        iceblock->len -= ib_len;
        iceblock->data[iceblock->len-1] = 0;
        iceblock->data[0] = ((iceblock->len >> 8) & 0x7F) | 0x80;
        iceblock->data[1] = iceblock->len & 0xFF;

        metadata_blk_release (source_mp3->metadata);
        struct metadata_block *mb = metadata_blk_copy (NULL);
        mb->icy = icy;
        mb->flv = flvmeta;
        mb->iceblock = iceblock;

        source_mp3->metadata = mb;
        stats_set_time (source->stats, "metadata_updated", STATS_GENERAL, source->client->worker->current_time.tv_sec);
        stats_release (source->stats);
    }
}


/* send the appropriate metadata, and return the number of bytes written
 * which is 0 or greater.  Check the client in_metadata value afterwards
 * to see if all metadata has been sent
 */
static int send_icy_metadata (client_t *client, refbuf_t *refbuf)
{
    int ret = 0, len;
    char *metadata = NULL;
    int meta_len, block_len;
    struct metadata_block *mb = refbuf->associated;
    refbuf_t *icy = NULL;
    mp3_client_data *client_mp3 = client->format_data;
    struct connection_bufs bufs;

    if (mb == NULL || mb->icy == NULL)
        mb = &blank_meta;       // the default block
    if (mb == client_mp3->associated && (client->flags & CLIENT_IN_METADATA) == 0)
    {
        // metadata the same as before so send nul btye
        metadata = "\0";
        meta_len = 1;
    }
    icy = mb->icy;

    if (metadata == NULL)  // in cases of short send
    {
        if (client->flags & CLIENT_IN_METADATA && client_mp3->metadata_offset >= icy->len)
        {
            ERROR3 ("mismatch in meta block (%s,%d, %d)", client->mount,
                    client_mp3->metadata_offset, icy->len);
            client->connection.error = 1;
            return 0;
        }
        metadata = icy->data + client_mp3->metadata_offset;
        meta_len = icy->len - client_mp3->metadata_offset;
    }
    block_len = refbuf->len - client->pos;

    if (block_len > client_mp3->interval)
        block_len = client_mp3->interval; // handle small intervals

    connection_bufs_init (&bufs, 2);
    len = connection_bufs_append (&bufs, metadata, meta_len);
    if (block_len)
        len = connection_bufs_append (&bufs, refbuf->data + client->pos, block_len);

    ret = connection_bufs_send (&client->connection, &bufs, 0);
    connection_bufs_release (&bufs);

    if (ret >= meta_len)
    {
        int queue_bytes = ret - meta_len;
        client->queue_pos += queue_bytes;
        client->counter += queue_bytes;
        client_mp3->since_meta_block = queue_bytes;
        client->pos += queue_bytes;
        client->flags &= ~CLIENT_IN_METADATA;
        client_mp3->metadata_offset = 0;
        client_mp3->associated = mb; // change prev meta block
        if (ret < len)
            client->schedule_ms += 10 + (client->throttle * ((ret < 0) ? 10 : 6));
    }
    else
    {
        if (ret > 0)
        {
            client->flags |= CLIENT_IN_METADATA;
            client_mp3->metadata_offset += ret;
        }
        client->schedule_ms += 10 + (client->throttle * ((ret < 0) ? 10 : 6));
    }
    return ret;
}


/* Handler for writing mp3 data to a client, taking into account whether
 * client has requested shoutcast style metadata updates
 */
static int format_mp3_write_buf_to_client (client_t *client) 
{
    int ret = -1, len;
    mp3_client_data *client_mp3 = client->format_data;
    refbuf_t *refbuf = client->refbuf;

    if (client_mp3->interval && client_mp3->interval == client_mp3->since_meta_block)
        return send_icy_metadata (client, refbuf);

    len = refbuf->len - client->pos;
    if (client_mp3->interval && len > client_mp3->interval - client_mp3->since_meta_block)
        len = client_mp3->interval - client_mp3->since_meta_block;
    if (len > 100000)
        len = 100000; // do not send a huge amount out in one go

    if (len)
    {
        char *buf = refbuf->data + client->pos;

        if (client->flags & CLIENT_CHUNKED)
        {
            int overall;
            char chunk_hdr [CHUNK_HDR_SZ];
            struct connection_bufs bufs;

            connection_bufs_init (&bufs, 4);
            connection_chunk_start (&client->connection, &bufs, chunk_hdr, len);
            connection_bufs_append (&bufs, buf, len);
            overall = connection_chunk_end (&client->connection, &bufs, chunk_hdr, len);

            ret = connection_bufs_send (&client->connection, &bufs, client->connection.chunk_pos);
            //if (ret != overall)
                //DEBUG2 ("test, ret %d, overall %d", ret, overall);
            if (ret > 0)
            {
                client->connection.chunk_pos += ret;
                if (client->connection.chunk_pos > bufs.total) abort();
            }
            if (client->connection.chunk_pos == overall)
            {
                client->connection.chunk_pos = 0;
                ret = len; // move on to next block
            }
            else
                ret = -1; // trigger a delay
            connection_bufs_release (&bufs);
        }
        else
            ret = client_send_bytes (client, buf, len);

        if (ret > 0)
        {
            client_mp3->since_meta_block += ret;
            client->pos += ret;
            client->queue_pos += ret;
            client->counter += ret;
        }
        if (ret < len)
        {
            client->schedule_ms += 10 + (client->throttle * ((ret < 0) ? 10 : 6));
        }
    }
    return ret;
}


static int send_iceblock_to_client (client_t *client) 
{
    int ret = -1, len = 0, skip = 0;
    mp3_client_data *client_mpg = client->format_data;
    refbuf_t *refbuf = client->refbuf;
    unsigned char lengthbytes[2];
    struct connection_bufs v;

    connection_bufs_init (&v, 3);
    if (refbuf->associated != client_mpg->associated)
    {
        struct metadata_block *mb = refbuf->associated;
        if (mb && mb->iceblock)
        {
            refbuf_t *meta = mb->iceblock;
            // may need to skip the single byte identifier for this client
            int off = (client->flags & CLIENT_WANTS_META1) ? 1 : 0;
            connection_bufs_append (&v, meta->data+off, meta->len-off);
        }
    }
    skip = connection_bufs_append (&v, lengthbytes, 2);
    len = connection_bufs_append (&v, refbuf->data, refbuf->len);

    lengthbytes[0] = ((refbuf->len+2) >> 8) & 0x7F;
    lengthbytes[1] = (refbuf->len+2) & 0xFF;
    ret = connection_bufs_send (&client->connection, &v, client_mpg->metadata_offset);
    connection_bufs_release (&v);

    if (ret > 0)
    {
        client->queue_pos += ret;
        if (client_mpg->metadata_offset < skip)
            client->queue_pos -= (skip - client_mpg->metadata_offset);
        client_mpg->metadata_offset += ret;
    }

    if (client_mpg->metadata_offset >= len)
    {
        client->pos = refbuf->len;
        if (refbuf->associated != client_mpg->associated)
            client_mpg->associated = refbuf->associated;
        client_mpg->metadata_offset = 0;
    }
    if (ret < len)
    {
        client->schedule_ms += 10 + (client->throttle * ((ret < 0) ? 10 : 6));
    }
    return ret;
}


static int write_mpeg_buf_to_client (client_t *client) 
{
    if (client->flags & CLIENT_WANTS_META)
        return send_iceblock_to_client (client);
    if (client->flags & CLIENT_WANTS_FLV)
        return write_flv_buf_to_client (client);
    if (client->format_data)
        return format_mp3_write_buf_to_client (client);
    return format_generic_write_to_client (client);
}


static void format_mp3_free_plugin (format_plugin_t *plugin, client_t *client)
{
    /* free the plugin instance */
    mp3_state *format_mp3 = plugin->_state;

    if (client)
    {
        mpeg_cleanup (client->format_data);
        free (client->format_data);
        client->format_data = NULL;
    }
    free (format_mp3->url_artist);
    free (format_mp3->url_title);
    free (format_mp3->inline_url);
    free (format_mp3->url);
    free (format_mp3->extra_icy_meta);
    metadata_blk_release (format_mp3->metadata);
    refbuf_release (format_mp3->read_data);
    free (format_mp3);
}


/* This does the actual reading, making sure the read data is packaged in
 * blocks of 1400 bytes (near the common MTU size). This is because many
 * incoming streams come in small packets which could waste a lot of 
 * bandwidth with many listeners due to headers and such like.
 */
static int complete_read (source_t *source)
{
    format_plugin_t *format = source->format;
    mp3_state *source_mp3 = format->_state;
    client_t *client = source->client;

    if (source_mp3->read_data == NULL)
    {
        size_up_qblock (source);
        source_mp3->read_data = refbuf_new (source_mp3->qblock_sz);
        source_mp3->read_count = 0;
    }
    if (format->read_bytes > 20000 && source_mp3->update_metadata) // only update after 20k received
    {
        mp3_set_title (source);
        source_mp3->update_metadata = 0;
    }
    if (source_mp3->read_count < source_mp3->read_data->len)
    {
        char *buf = source_mp3->read_data->data + source_mp3->read_count;
        int read_in = source_mp3->read_data->len - source_mp3->read_count;
        int bytes = client_read_bytes (client, buf, read_in);

        if (bytes > 0)
        {
            rate_add (source->in_bitrate, bytes, client->worker->current_time.tv_sec);
            source_mp3->read_count += bytes;
            format->read_bytes += bytes;
            // increase retry delay on small read, to reduce rescheduling
            if (read_in - bytes > 700)
                client->schedule_ms += 10;
        }
    }
    if (source_mp3->read_count < source_mp3->read_data->len)
        return 0;
    if (source->incoming_rate && source->incoming_rate < 65536)
        client->schedule_ms += (65536/source->incoming_rate);
    else
        client->schedule_ms += 1;
    return 1;
}


int mpeg_process_buffer (client_t *client, format_plugin_t *plugin)
{
    refbuf_t *refbuf = client->refbuf;
    mp3_client_data *client_mp3 = client->format_data;
    int unprocessed = -1;

    if (refbuf)
    {
        if (client->flags & CLIENT_WANTS_FLV)
            return flv_process_buffer (client->format_data, refbuf);
        unprocessed = mpeg_complete_frames (client_mp3->specific, refbuf, 0);
    }
    return unprocessed;
}

static void size_up_qblock (source_t *source)
{
    mp3_state *source_mp3 = source->format->_state;
    int multi = 6;
    if (source->incoming_rate)
        multi = (source->incoming_rate/100000) + 1;
    source_mp3->qblock_sz = 1400 * (multi < 17 ? multi : 17);

    // if ((source->buffer_count & 15) == 15)
        // DEBUG3 ("mount %s, incoming %ld, multi %d", source->mount, source->incoming_rate, source_mp3->qblock_sz);
}


/* validate the frames, sending any partial frames either back for reading or
 * keep them for later mpeg parsing.
 */
static int validate_mpeg (source_t *source, refbuf_t *refbuf)
{
    client_t *client = source->client;
    mp3_state *source_mp3 = source->format->_state;
    mpeg_sync *mpeg_sync = client->format_data;

    int unprocessed = mpeg_complete_frames (mpeg_sync, refbuf, 0);

    if (unprocessed < 0 || unprocessed > 20000) /* too much unprocessed really, may not be parsing */
    {
        if (unprocessed > 0 && refbuf->len)
            return 0;
        WARN2 ("no frames detected for %s (%d)", source->mount, mpeg_sync->resync_count);
        source->flags &= ~SOURCE_RUNNING;
        return -1;
    }
    if (mpeg_has_changed (mpeg_sync))
    {
        format_plugin_t *plugin = source->format;
        int rate = mpeg_get_samplerate (mpeg_sync);
        char buf [30];

        source_mp3->qblock_sz = 1400;
        if (rate == 0 && strcmp (plugin->contenttype, "video/MP2T") != 0)
        {
            free (plugin->contenttype);
            plugin->contenttype = strdup ("video/MP2T");
        }
        stats_lock (source->stats, NULL);
        snprintf (buf, sizeof buf, "%d", mpeg_get_type (mpeg_sync) == FORMAT_TYPE_AAC ? 10 : 2);
        stats_set_flags (source->stats, "audio_codecid", buf, STATS_HIDDEN);
        snprintf (buf, sizeof buf, "%d", rate);
        stats_set_flags (source->stats, "mpeg_samplerate", buf, STATS_HIDDEN);
        snprintf (buf, sizeof buf, "%d", mpeg_get_channels (mpeg_sync));
        stats_set_flags (source->stats, "mpeg_channels", buf, STATS_HIDDEN);
        stats_release (source->stats);
    }
    if (unprocessed > 0)
    {
        size_t len;
        refbuf_t *leftover;

        if (mpeg_block_expanded (mpeg_sync))
        {
            source_mp3->read_data = refbuf_new (0);
            source_mp3->read_data->data = refbuf->data;
            source_mp3->read_data->len = refbuf->len;
            source_mp3->read_count = unprocessed;
            refbuf->data = NULL;
            client->pos = unprocessed;
            return -1;
        }

        if (source_mp3->inline_metadata_interval > 0)
        {
            if (source_mp3->inline_metadata_interval <= source_mp3->offset)
            {
                // reached meta but we have a frame fragment, so keep it for later
                leftover = refbuf_new (unprocessed);
                memcpy (leftover->data, refbuf->data + refbuf->len, unprocessed);
                mpeg_data_insert (mpeg_sync, leftover);
                client->pos = 0;
                return refbuf->len ? 0 : -1;
            }
            // not reached the metadata block so save and rewind for completing the read
            source_mp3->offset -= unprocessed;
        }
        size_up_qblock (source);
        len = source_mp3->qblock_sz;
        if (len < unprocessed + 40) // avoid extreme block shrinkage
        {
            WARN3 ("source %s, len %ld, unprocessed %d", source->mount, (long)len, unprocessed);
            len = unprocessed + 1000;
        }
        leftover = refbuf_new (len);
        memcpy (leftover->data, refbuf->data + refbuf->len, unprocessed);
        source_mp3->read_data = leftover;
        source_mp3->read_count = unprocessed;
    }

    return refbuf->len ? 0 : -1;
}


/* read an mp3 stream which does not have shoutcast style metadata */
static refbuf_t *mp3_get_no_meta (source_t *source)
{
    refbuf_t *refbuf;
    mp3_state *source_mp3 = source->format->_state;
    client_t *client = source->client;  // maybe move mp3_state into client instead of plugin?

    if (complete_read (source) == 0)
        return NULL;

    refbuf = source_mp3->read_data;
    refbuf->len = source_mp3->read_count;
    source_mp3->read_count = 0;
    source_mp3->read_data = NULL;

    if (client->format_data && validate_mpeg (source, refbuf) < 0)
    {
        refbuf_release (refbuf);
        return NULL;
    }
    source->client->queue_pos += refbuf->len;
    refbuf->associated = source_mp3->metadata;
    metadata_blk_ref_inc (source_mp3->metadata);
    source_mp3->metadata->on_queue = 1;
    refbuf->flags |= SOURCE_BLOCK_SYNC;
    return refbuf;
}


/* read mp3 data with inlined metadata from the source. Filter out the
 * metadata so that the mp3 data itself is store on the queue and the
 * metadata is is associated with it
 */
static refbuf_t *mp3_get_filter_meta (source_t *source)
{
    refbuf_t *refbuf;
    format_plugin_t *plugin = source->format;
    mp3_state *source_mp3 = plugin->_state;
    client_t *client = source->client;  // maybe move mp3_state into client instead of plugin?
    unsigned char *src;
    unsigned int bytes, mp3_block, copy_meta = 1;

    if (complete_read (source) == 0)
        return NULL;

    refbuf = source_mp3->read_data;
    source_mp3->read_data = NULL;
    src = (unsigned char *)refbuf->data;

    /* fill the buffer with the read data */
    bytes = source_mp3->read_count;
    refbuf->len = 0;

    while (bytes > 0)
    {
        unsigned int metadata_remaining;

        mp3_block = source_mp3->inline_metadata_interval - source_mp3->offset;

        /* is there only enough to account for mp3 data */
        if (bytes <= mp3_block)
        {
            refbuf->len += bytes;
            source_mp3->offset += bytes;
            break;
        }
        /* we have enough data to get to the metadata
         * block, but only transfer upto it */
        if (mp3_block)
        {
            src += mp3_block;
            bytes -= mp3_block;
            refbuf->len += mp3_block;
            source_mp3->offset += mp3_block;
            continue;
        }

        /* process the inline metadata, len == 0 indicates not seen any yet */
        if (source_mp3->build_metadata_len == 0)
        {
            copy_meta = (*src) ? 1 : 0; // is there any length to the metadata
            if (copy_meta)
                memset (source_mp3->build_metadata, 0, sizeof (source_mp3->build_metadata));
            source_mp3->build_metadata_offset = 0;
            source_mp3->build_metadata_len = 1 + (*src * 16);
        }

        metadata_remaining = source_mp3->build_metadata_len - source_mp3->build_metadata_offset;
        if (bytes < metadata_remaining)
        {
            // incomplete short meta block
            if (copy_meta)
                memcpy (source_mp3->build_metadata + source_mp3->build_metadata_offset, src, bytes);
            source_mp3->build_metadata_offset += bytes;
            break;
        }
        if (copy_meta)
        {
            /* copy all bytes except the last one, that way we know a null byte terminates the message */
            memcpy (source_mp3->build_metadata + source_mp3->build_metadata_offset, src, metadata_remaining-1);

            if (source_mp3->build_metadata_len > 1 && parse_icy_metadata (source->mount, source_mp3) < 0)
            {
                WARN1 ("Unable to parse metadata insert for %s", source->mount);
                source->flags &= ~SOURCE_RUNNING;
                refbuf_release (refbuf);
                return NULL;
            }
        }
        source_mp3->offset = 0;
        source_mp3->build_metadata_len = 0;
        bytes -= metadata_remaining;
        memmove (src, src+metadata_remaining, bytes); /* overwrite meta block */
    }
    /* the data we have just read may of just been metadata */
    if (refbuf->len <= 0)
    {
        refbuf_release (refbuf);
        return NULL;
    }
    if (client->format_data && validate_mpeg (source, refbuf) < 0)
    {
        refbuf_release (refbuf);
        return NULL;
    }
    source->client->queue_pos += refbuf->len;
    refbuf->associated = source_mp3->metadata;
    metadata_blk_ref_inc (source_mp3->metadata);
    source_mp3->metadata->on_queue = 1;
    refbuf->flags |= SOURCE_BLOCK_SYNC;

    return refbuf;
}


static int format_mp3_create_client_data (format_plugin_t *plugin, client_t *client)
{
    mp3_client_data *client_mp3;
    mp3_state *source_mp3 = plugin->_state;
    const char *metadata;
    size_t  remaining;
    char *ptr;
    int bytes;

    if (client->flags & CLIENT_WANTS_FLV)
    {
        flv_create_client_data (plugin, client); // special case
        return 0;
    }
    client->free_client_data = free_mp3_client_data;
    client_mp3 = calloc(1,sizeof(mp3_client_data));
    if (client_mp3 == NULL)
        return -1;

    client->format_data = client_mp3;
    if (plugin->type == FORMAT_TYPE_AAC || plugin->type == FORMAT_TYPE_MPEG)
    {
        client_mp3->specific = calloc (1, sizeof(mpeg_sync));
        mpeg_setup (client_mp3->specific, client->connection.ip);
        mpeg_check_numframes (client_mp3->specific, 1);
        if (httpp_getvar (client->parser, "__FILESIZE"))
            mpeg_set_flags (client_mp3->specific, MPEG_KEEP_META);
    }
    if (source_mp3->max_send_size)
        client_mp3->max_send_size = source_mp3->max_send_size;
    else
        client_mp3->max_send_size = 24000; // largest single write, block very unlikely to be larger

    if (client->refbuf == NULL)
        client->refbuf = refbuf_new (4096);
    client->refbuf->len = 0;

    metadata = httpp_getvar(client->parser, "icy-metadata");
    if (metadata && atoi(metadata))
        httpp_setvar (client->parser, HTTPP_VAR_VERSION, "1.0"); // hack force 1.0 if icy metadata requested

    if (format_general_headers (plugin, client) < 0)
        return -1;

    if ((client->flags & CLIENT_AUTHENTICATED) == 0)
        return 0;

    client->refbuf->len -= 2;
    remaining = 4096 - client->refbuf->len;
    ptr = client->refbuf->data + client->refbuf->len;

    if (httpp_getvar (client->parser, "iceblocks"))
    {
        client->flags |= CLIENT_WANTS_META;
        bytes = snprintf (ptr, remaining, "IceBlocks: 1.1\r\n");
        remaining -= bytes;
        ptr += bytes;
    }
    else
    {
        /* check for shoutcast style metadata inserts */
        if (metadata && atoi(metadata))
        {
            if (source_mp3->interval >= 0)
                client_mp3->interval = source_mp3->interval;
            else
                client_mp3->interval = ICY_METADATA_INTERVAL;
            if (client_mp3->interval)
            {
                bytes = snprintf (ptr, remaining, "icy-metaint:%u\r\n",
                        client_mp3->interval);
                if (bytes > 0)
                {
                    remaining -= bytes;
                    ptr += bytes;
                }
            }
        }
    }
    bytes = snprintf (ptr, remaining, "\r\n");
    remaining -= bytes;
    ptr += bytes;

    client->refbuf->len = 4096 - remaining;

    return 0;
}


static void swap_client (client_t *new_client, client_t *old_client)
{
    mpeg_sync *mpeg_sync = old_client->format_data;
    unsigned len = 0;

    new_client->format_data = mpeg_sync;
    old_client->format_data = NULL;
    if (mpeg_sync)
    {
        mpeg_sync->reference = new_client->connection.ip;
        if (mpeg_sync->surplus)
        {
            len = mpeg_sync->surplus->len;
            refbuf_release (mpeg_sync->surplus);
        }
        mpeg_sync->surplus = NULL;
    }
    DEBUG1 ("moving mpeg sync over to new client, and flushing %d", len);
}


static void free_mp3_client_data (client_t *client)
{
    mp3_client_data *client_mp3 = client->format_data;

    if (client->flags & CLIENT_WANTS_FLV)
    {
        free_flv_client_data (client);
        abort ();
    }
    mpeg_cleanup (client_mp3->specific);
    free (client_mp3->specific);
    client_mp3->associated = NULL;
    free (client->format_data);
    client->format_data = NULL;
}


static void write_mp3_to_file (struct source_tag *source, refbuf_t *refbuf)
{
    if (refbuf->len == 0)
        return;
    if (fwrite (refbuf->data, 1, refbuf->len, source->dumpfile) < refbuf->len)
    {
        WARN0 ("Write to dump file failed, disabling");
        fclose (source->dumpfile);
        source->dumpfile = NULL;
    }
}

