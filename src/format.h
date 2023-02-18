/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2009-2023, Karl Heyes <karl@kheyes.plus.com>
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org>,
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

/* format.h
**
** format plugin header
**
*/
#ifndef __FORMAT_H__
#define __FORMAT_H__

#include <inttypes.h>
typedef uint8_t format_type_t;

#include "client.h"
#include "refbuf.h"
#include "params.h"

struct source_tag;
struct _mount_proxy;

#define FORMAT_TYPE_UNDEFINED       0   /* No format determined */
#define FORMAT_TYPE_OGG             1
#define FORMAT_TYPE_AAC             2   // for AAC/ADTS style content
#define FORMAT_TYPE_MPEG            3   // for MPEG1/2/ADTS type content
#define FORMAT_TYPE_MP4             4
#define FORMAT_TYPE_EBML            5
#define FORMAT_TYPE_USAC            6   // USAC/LOAS framed aac


typedef struct _format_plugin_tag format_plugin_t;

// possible flags for format_plugin
#define FORMAT_FL_ALLOW_HTTPCHUNKED             1


typedef struct format_check_t
{
    icefile_handle fd;
    format_type_t type;
    unsigned short channels;
    const char *desc;
    long offset;
    unsigned int bitrate; // detected Kbit/s
    unsigned int srate; // detected samplerate
} format_check_t;


struct _format_plugin_tag
{
    format_type_t type;
    unsigned int flags;

    /* we need to know the mount to report statistics */
    char *mount;

    char *contenttype;
    char *charset;
    http_parser_t *parser;
    uint64_t read_bytes;
    uint64_t sent_bytes;

    refbuf_t *(*get_buffer)(struct source_tag *);
    int (*write_buf_to_client)(client_t *client);
    void (*write_buf_to_file)(struct source_tag *source, refbuf_t *refbuf);
    int (*create_client_data)(format_plugin_t *plugin, ice_http_t *http, client_t *client);
    void (*set_tag)(struct _format_plugin_tag *plugin, const char *tag, const char *value, const char *charset);
    void (*free_plugin)(struct _format_plugin_tag *self, client_t *client);
    void (*apply_client)(struct _format_plugin_tag *self, client_t *client);
    void (*apply_settings)(struct _format_plugin_tag *format, struct _mount_proxy *mount);
    int  (*align_buffer)(client_t *client, format_plugin_t *plugin);
    int  (*get_image)(client_t *client, struct _format_plugin_tag *format);
    void (*swap_client)(client_t *new_cient, client_t *old_client);
    void (*detach_queue_block)(struct source_tag *source, refbuf_t *refbuf);
    refbuf_t *(*qblock_copy)(refbuf_t *refbuf);

    /* for internal state management */
    void *_state;
};

format_type_t format_get_type(const char *contenttype);
int format_get_plugin (format_plugin_t *plugin);
int format_generic_write_to_client (client_t *client);

int format_check_frames (struct format_check_t *c);
int format_file_read (client_t *client, format_plugin_t *plugin, icefile_handle f);
int format_client_headers (format_plugin_t *plugin, ice_http_t *http, client_t *client);

void format_plugin_clear (format_plugin_t *format, client_t *client);
void format_apply_client (format_plugin_t *format, client_t *client);

#endif  /* __FORMAT_H__ */

