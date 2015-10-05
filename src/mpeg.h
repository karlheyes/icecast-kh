/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2009-2010,  Karl Heyes <karl@xiph.org>
 */

/* mpeg.c
 *
 * routines to handle locating the frame sync markers for mpeg/1/2/3/aac streams.
 *
 */
#ifndef __MPEG_SYNC_H
#define __MPEG_SYNC_H

#include "refbuf.h"

typedef struct mpeg_sync
{
    int (*process_frame) (struct mpeg_sync *mp, unsigned char *p, int len);
    uint32_t mask;
    uint32_t match;

    unsigned short samplerate;
    unsigned char marker;
    unsigned char check_numframes;
    unsigned short settings;
    unsigned short resync_count;

    refbuf_t *surplus;
    long sample_count;
    void *callback_key;
    int (*frame_callback)(struct mpeg_sync *mp, unsigned char *p, unsigned int len, unsigned int offset);
    refbuf_t *raw;
    int raw_offset;
    const char *mount;
} mpeg_sync;

void mpeg_setup (mpeg_sync *mpsync, const char *mount);
void mpeg_cleanup (mpeg_sync *mpsync);
void mpeg_check_numframes (mpeg_sync *mpsync, unsigned count);
void mpeg_set_flags (mpeg_sync *mpsync, unsigned flags);

int  mpeg_complete_frames (mpeg_sync *mp, refbuf_t *new_block, unsigned offset);
void mpeg_data_insert (mpeg_sync *mp, refbuf_t *inserted);

int  mpeg_get_layer (struct mpeg_sync *mp);
int  mpeg_get_version (struct mpeg_sync *mp);
int  mpeg_get_channels (struct mpeg_sync *mp);
int  mpeg_has_changed (struct mpeg_sync *mp);


#define MPEG_AAC         0
#define MPEG_LAYER_3     0x1
#define MPEG_LAYER_2     0x2
#define MPEG_LAYER_1     0x3


#endif /* __MPEG_SYNC_H */
