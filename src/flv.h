/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2009-2010,         Karl Heyes <karl@xiph.org>
 * Copyright 2010-2022,         Karl Heyes <karl@kheyes.plus.com>
 */

/* flv.c
 *
 * routines for processing an flv container
 *
 */

#include "format.h"
#include "client.h"
#include "mpeg.h"


struct flv
{
    uint32_t prev_tagsize;
    uint32_t block_pos;
    uint16_t flags;
    uint16_t wrapper_offset;
    unsigned int samples_in_buffer;
    refbuf_t *wrapper;
    client_t *client;
    uint64_t prev_ms;
    int64_t samples;
    struct metadata_block *seen_metadata;
    sync_callback_t cb;
    mpeg_sync mpeg_sync;
    struct connection_bufs bufs;
    unsigned char tag[30];
};

#define FLV_CHK_META                    (1<<0)

int  write_flv_buf_to_client (client_t *client);
int  flv_create_client_data (format_plugin_t *plugin, ice_http_t *http, client_t *client);
void free_flv_client_data (client_t *client);
int  flv_process_buffer (struct flv *flv, refbuf_t *refbuf);

refbuf_t *flv_meta_allocate (size_t len);
void flv_meta_append_string (refbuf_t *buffer, const char *tag, const char *value);
void flv_meta_append_number (refbuf_t *buffer, const char *tag, double value);
void flv_meta_append_bool (refbuf_t *buffer, const char *tag, int value);
void flv_meta_append_end_marker (refbuf_t *buffer);
