/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2009-2010,  Karl Heyes <karl@xiph.org>
 * Copyright 2009-2018,  Karl Heyes <karl@kheyes.plus.com>
 */

/* mpeg.c
 *
 * routines to handle locating the frame sync markers for mpeg/1/2/3/aac streams.
 *
 */
#ifndef __MPEG_SYNC_H
#define __MPEG_SYNC_H

#include "refbuf.h"

struct mpeg_sync;

typedef uint8_t frame_type_t;

#define FORMAT_TYPE_UNDEFINED       0   /* No format determined */
#define FORMAT_TYPE_OGG             1
#define FORMAT_TYPE_AAC             2   // for AAC/ADTS style content
#define FORMAT_TYPE_MPEG            3   // for MPEG1/2/ADTS type content
#define FORMAT_TYPE_MP4             4
#define FORMAT_TYPE_EBML            5
#define FORMAT_TYPE_USAC            6   // USAC/LOAS framed aac


typedef struct sync_callback_t
{
    void *callback_key;
    int (*frame_callback)(struct mpeg_sync *mp, struct sync_callback_t *cb, unsigned char *p, unsigned int len, unsigned int offset);
} sync_callback_t;

typedef struct mpeg_sync
{
    uint64_t settings;

    uint32_t mask;
    uint32_t match;

    unsigned short resync_count;
    unsigned char marker;
    frame_type_t type;

    uint32_t tag_len;
    unsigned char *tag_data;

    uint64_t sample_count;

    int (*process_frame) (struct mpeg_sync *mp, sync_callback_t *cb, unsigned char *p, int len);

    refbuf_t *surplus;
    const char *reference;
} mpeg_sync;


#define MPEG_LOG_MESSAGES   (1)
#define MPEG_SKIP_SYNC      (1<<2)
#define MPEG_KEEP_META      (1<<3)
#define MPEG_COPY_META      (1<<4)

void mpeg_setup (mpeg_sync *mpsync, const char *mount);
void mpeg_cleanup (mpeg_sync *mpsync);
void mpeg_check_numframes (mpeg_sync *mpsync, unsigned count);
void mpeg_set_flags (mpeg_sync *mpsync, uint64_t flags);
frame_type_t mpeg_get_type (mpeg_sync *mp);

int  mpeg_complete_frames_cb (mpeg_sync *mp, sync_callback_t *cb, refbuf_t *new_block, unsigned offset);
#define mpeg_complete_frames(A,B,C)         mpeg_complete_frames_cb(A,NULL,B,C)

void mpeg_data_insert (mpeg_sync *mp, refbuf_t *inserted);

int  mpeg_get_bitrate (struct mpeg_sync *mp);
int  mpeg_get_channels (struct mpeg_sync *mp);
int  mpeg_get_samplerate (struct mpeg_sync *mp);
int  mpeg_has_changed (struct mpeg_sync *mp);
int  mpeg_block_expanded (struct mpeg_sync *mp);
int  mpeg_tag_found (mpeg_sync *mp, const unsigned char **p, unsigned int *l);

int syncframe_bitrate (mpeg_sync *mp);
int syncframe_channels (mpeg_sync *mp);
int syncframe_samplerate (mpeg_sync *mp);

#endif /* __MPEG_SYNC_H */
