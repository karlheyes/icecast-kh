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

/* format_mp3.h
**
** mp3 format plugin
**
*/
#ifndef __FORMAT_MP3_H__
#define __FORMAT_MP3_H__

#include "format.h"
#include "mpeg.h"

#define CLIENT_WANTS_FLV            (CLIENT_FORMAT_BIT<<1)
#define CLIENT_WANTS_META           (CLIENT_FORMAT_BIT<<2)
#define CLIENT_WANTS_META1          (CLIENT_FORMAT_BIT<<3)



typedef struct {
    void *associated;
    unsigned short interval;
    short metadata_offset;
    unsigned short since_meta_block;
    unsigned short max_send_size;
    void         *specific;
} mp3_client_data;


// block attached to queue blocks for metadata updates in different protocols
struct metadata_block
{
    unsigned int count;
    char on_queue;
    refbuf_t *icy;
    refbuf_t *iceblock;
    refbuf_t *flv;
    refbuf_t *id3;
};


typedef struct {
    /* These are for inline metadata */
    int32_t inline_metadata_interval;
    int32_t interval;
    int32_t offset;
    short update_metadata;

    char *url_artist;
    char *url_title;
    char *url;
    char *inline_url;
    char *extra_icy_meta;

    struct metadata_block *metadata;
    refbuf_t *read_data;
    int read_count;
    unsigned short qblock_sz;
    unsigned short max_send_size;

    unsigned short build_metadata_len;
    unsigned build_metadata_offset;
    char build_metadata[4081];
} mp3_state;

int format_mp3_get_plugin (format_plugin_t *plugin);

#endif  /* __FORMAT_MP3_H__ */
