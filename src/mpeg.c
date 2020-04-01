/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2009-2012,  Karl Heyes <karl@xiph.org>
 * Copyright 2012-2018,  Karl Heyes <karl@kheyes.plus.com>
 */

/* mpeg.c
 *
 * routines to handle locating the frame sync markers for mpeg/1/2/3/aac streams.
 *
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include "compat.h"
#include "mpeg.h"
#include "format_mp3.h"
#include "source.h"
#include "global.h"
#include "timing/timing.h"

#define CATMODULE "mpeg"
#include "logging.h"

int aacp_sample_freq[] = {
    96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 0, 0, 0, 0
};

int aacp_num_channels[] = {
    0, 1, 2, 3, 4, 5, 6, 8, 0, 0, 0, 0, 0, 0, 0, 0
};

int mpeg_samplerates [4][4] = {
    { 11025, 0, 22050, 44100 },
    { 12000, 0, 24000, 48000 },
    {  8000, 0, 16000, 32000 },
    { 0,0,0 } };

// settings is a bitmask 64
// codec specific
// MP/2/3
//  bit 59, 58      version
//  bit 57, 56      layer
// AAC
//  bit 57, 56      layer
//
// bits 52-55 (4)   number of frames to check on autodetect
// bits 32-51 (20)  samplerate, may use 5 bits later by use of lookup table
// bits 24-31 (8)   channels
// bits 8-23 (16)   bitrate
//
// bit 6            check for TAG frame next, avoid format resync
// bit 5            resize block to sample_count size
// bit 4            last ID3 frame cached
// bit 3            allow trailing tags, eg from file
// bit 2            skip processing
// bit 1            change detected
// bit 0            log messages

#define SYNC_CHANGED                    (1<<1)
#define SYNC_RESIZE                     (1<<5)
#define SYNC_CHK_TAG                    (1<<6)

#define SYNC_BITRATE_OFF                8
#define SYNC_CHANNELS_OFF               24
#define SYNC_SAMPLERATE_OFF             32
#define SYNC_CHKFRAMES_OFF              52

#define SYNC_BITRATE_MASK               ((uint64_t)0xFFFF << SYNC_BITRATE_OFF)
#define SYNC_CHAN_MASK                  ((uint64_t)0xFF << SYNC_CHANNELS_OFF)
#define SYNC_RATE_MASK                  ((uint64_t)0xFFFFF << SYNC_SAMPLERATE_OFF)
#define SYNC_CHKFRAME_MASK              ((uint64_t)0xF << SYNC_CHKFRAMES_OFF)

#define syncframe_set_samplerate(x,v)   do {x->settings&=~SYNC_RATE_MASK; x->settings|=((uint64_t)(v)<<SYNC_SAMPLERATE_OFF); } while(0)
#define syncframe_set_channels(x,v)     do {x->settings&=~SYNC_CHAN_MASK; x->settings|=((uint64_t)(v)<<SYNC_CHANNELS_OFF); } while(0)
#define syncframe_set_framecheck(x,v)   do {x->settings&=~SYNC_CHKFRAME_MASK; x->settings|=((uint64_t)(v)<<SYNC_CHKFRAMES_OFF); } while(0)
#define syncframe_set_bitrate(x,v)      do {x->settings&=~SYNC_BITRATE_MASK; x->settings|=((uint64_t)(v)<<SYNC_BITRATE_OFF); } while(0)

// mp/2/3/aac specific things
#define SYNC_MPEG_LAYER_OFF     56
#define SYNC_MPEG_VER_OFF       58

#define MPEG_AAC                0
#define MPEG_LAYER_3            0x1
#define MPEG_LAYER_2            0x2
#define MPEG_LAYER_1            0x3

#define MPEG_VER_1              0x3
#define MPEG_VER_2              0x2
#define MPEG_VER_25             0

#define get_mpegframe_layer(p)          ((p[1] & 0x6) >> 1)
#define get_mpegframe_version(p)        ((p[1] & 0x18) >> 3)


int syncframe_bitrate (mpeg_sync *mp)
{
    return (int)((mp->settings&SYNC_BITRATE_MASK) >> SYNC_BITRATE_OFF);
}

int syncframe_channels (mpeg_sync *mp)
{
    return (int)((mp->settings&SYNC_CHAN_MASK) >> SYNC_CHANNELS_OFF);
}

int syncframe_samplerate (mpeg_sync *mp)
{
    return (int)((mp->settings&SYNC_RATE_MASK) >> SYNC_SAMPLERATE_OFF);
}

static int syncframe_chkframes (mpeg_sync *mp)
{
    return (int)((mp->settings&SYNC_CHKFRAME_MASK) >> SYNC_CHKFRAMES_OFF);
}


int mpeg_has_changed (struct mpeg_sync *mp)
{
    int v = mp->settings & SYNC_CHANGED;
    if (v) mp->settings &= ~SYNC_CHANGED; // reset
    return v ? 1 : 0;
}

int mpeg_get_channels (struct mpeg_sync *mp)
{
    return syncframe_channels (mp); // this could go
}

int mpeg_get_samplerate (struct mpeg_sync *mp)
{
    return syncframe_samplerate (mp); // could go
}

int mpeg_get_bitrate (struct mpeg_sync *mp)
{
    return syncframe_bitrate (mp) * 1000; // could go
}

int mpeg_get_version (struct mpeg_sync *mp)
{
    return (mp->settings >> SYNC_MPEG_VER_OFF) & 0x3;
}


int mpeg_get_layer (struct mpeg_sync *mp)
{
    return (mp->settings >> SYNC_MPEG_LAYER_OFF) & 0x3;
}

void mpeg_set_flags (mpeg_sync *mpsync, uint64_t flags)
{
    mpsync->settings |= flags;
}


sync_callback_t *mpeg_alloc_callback (mpeg_sync *mp)
{
    if (mp->cb) return mp->cb;
    mp->cb = calloc (1, sizeof (*mp->cb));
    mp->cb->cached_p = &mp->cb->cached;
    return mp->cb;
}


static int get_aac_frame_len (unsigned char *p)
{
    return ((p[3] & 0x3) << 11) + (p[4] << 3) + ((p[5] & 0xE0) >> 5);
}

static int handle_aac_frame (struct mpeg_sync *mp, sync_callback_t *cb, unsigned char *p, int len)
{
    int frame_len = get_aac_frame_len (p);
    int blocks, header_len = 9;
    int samplerate_idx = (p[2] & 0x3C) >> 2, samplerate;
    if (len - frame_len < 0)
        return 0;

    samplerate = aacp_sample_freq [samplerate_idx];
    int cur_rate = syncframe_samplerate (mp);
    if (samplerate != cur_rate)
    {
        if (mp->settings & MPEG_LOG_MESSAGES)
            WARN3 ("detected samplerate change from %d to %d on %s", cur_rate, samplerate, mp->reference);
        syncframe_set_samplerate (mp, cur_rate);
    }

    blocks = (p[6] & 0x3) + 1;
    if (p[1] & 0x1) // no crc
        header_len -= 2;
    mp->sample_count = (blocks * 1024);

    if (cb && cb->frame_callback)
        if (cb->frame_callback (mp, cb, p, frame_len, header_len) < 0)
        {
            mp->sample_count = 0;
            return -1;
        }

    return frame_len;
}

static int get_mpegframe_samplerate (unsigned char *p)
{
    int ver = get_mpegframe_version (p);
    return mpeg_samplerates [(p[2]&0xC) >> 2][ver];
}

static int get_mpeg_bitrate (struct mpeg_sync *mp, unsigned char *p)
{
    int bitrate = -1;
    int bitrate_code = (p[2] & 0xF0) >> 4;
    int layer = get_mpegframe_layer (p);

    if (get_mpegframe_version (p) == MPEG_VER_1)
    {
        static int bitrates [3][16] = {
            { 0, 32, 40, 48,  56,  64,  80,  96, 112, 128, 160, 192, 224, 256, 320, -1 },
            { 0, 32, 48, 56,  64,  80,  96, 112, 128, 160, 192, 224, 256, 320, 348, -1 },
            { 0, 32, 54, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, -1 } };
        if (layer != MPEG_AAC)
            bitrate = bitrates [layer-1][bitrate_code];
    }
    else // MPEG v2/2.5
    {
        static int bitrates [2][16] = { 
            { 0,  8, 16, 24, 32, 40, 48,  56,  64,  80,  96, 112, 128, 144, 160, -1 },
            { 0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, -1 } };
        if (layer == MPEG_LAYER_1)
            bitrate = bitrates [1][bitrate_code];
        else
            bitrate = bitrates [0][bitrate_code];
    }
    return bitrate;
}


static int get_samples_per_mpegframe (int version, int layer)
{
    int samples_per_frame [4][4] = {
        { -1,  576, 1152, 384 },    /* v2.5 - L3, L2, L1 */
        { -1,   -1,   -1,  -1 },
        { -1,  576, 1152, 384 },    /* v2 - L3, L2, L1 */
        { -1, 1152, 1152, 576 }     /* v1 - L3, L2, L1 */
    };
    return samples_per_frame [version] [layer];
}


static int get_mpeg_frame_length (struct mpeg_sync *mp, unsigned char *p)
{
    int padding = (p[2] & 0x2) >> 1;
    int frame_len = 0;

    int64_t bitrate = get_mpeg_bitrate (mp, p);
    int layer = get_mpegframe_layer (p);
    int samples = get_samples_per_mpegframe (get_mpegframe_version (p), layer);
    int samplerate = get_mpegframe_samplerate (p);

    if (samplerate == 0 || (mp->mask && syncframe_samplerate (mp) != samplerate))
        return -1;
    mp->sample_count = samples;
    if (bitrate > 0 && samples > 0)
    {
        if (mp->type != FORMAT_TYPE_MPEG)  // detection phase
            syncframe_set_bitrate (mp, bitrate);

        bitrate *= 1000;
        if (layer == MPEG_LAYER_1)
        {
            frame_len = (int)(12 * bitrate / samplerate + padding) * 4; // ??
        }
        else
        {
            frame_len = (int)(samples / 8 * bitrate / samplerate + padding);
        }
    }
    return frame_len;
}


static int handle_mpeg_frame (struct mpeg_sync *mp, sync_callback_t *cb, unsigned char *p, int remaining)
{
    int frame_len = get_mpeg_frame_length (mp, p);

    if (frame_len <= 0)
    {
        if (frame_len < 0)
        {
            int samplerate = get_mpegframe_samplerate (p);
            if (samplerate)
            {
                if (mp->settings & MPEG_LOG_MESSAGES)
                    WARN2 ("detected samplerate change to %d on %s", samplerate, mp->reference);
                syncframe_set_samplerate (mp, samplerate);
                return handle_mpeg_frame (mp, cb, p, remaining);
            }
            if (mp->settings & MPEG_LOG_MESSAGES)
                INFO1 ("detected invalid frame on %s, skipping", mp->reference);
        }
        mp->sample_count = 0;
        return -1;
    }
    if (remaining - frame_len < 0)
        return 0;
    if (cb && cb->frame_callback)
        if (cb->frame_callback (mp, cb, p, frame_len, (p[1] & 0x1) ? 4 : 6) < 0)
        {
            mp->sample_count = 0;
            return -1;
        }
    return frame_len;
}


#ifdef HAVE_AV

#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(58,10,100)
__attribute__((constructor)) void mpeg_av_init (void)
{
    av_register_all();
}
#endif


struct demux_pos_info
{
    refbuf_t *current;
    uint64_t current_pos;
    int pos;
    int flush_pkts;
    int to_queue_pos;
    int need_more;
    int lag;
    mpeg_sync sync;
    refbuf_t *to_queue;
};


int do_preblock_checking (struct mpeg_sync *mp, struct sync_callback_t *cb, refbuf_t *block, int remaining);


static void mpts_reset_av (sync_callback_t *cb)
{
    if (cb == NULL) return;
    if (cb->fmt_ctx) // has been known to crash on NULL
    {
        avformat_close_input (&cb->fmt_ctx);
    }
    if (cb->ofmt_ctx)
    {
        av_freep (&cb->ofmt_ctx->pb->buffer);
        av_freep (&cb->ofmt_ctx->pb);
        avformat_free_context (cb->ofmt_ctx);
        cb->ofmt_ctx = NULL;
    }
    if (cb->avio_ctx)
    {
        av_freep (&cb->avio_ctx->buffer);
        av_freep (&cb->avio_ctx);
    }
    cb->post_process = do_preblock_checking;
}


static int mpts_read_packet(void *opaque, uint8_t *buf, int buf_size)
{
    // DEBUG1 ("buffer size is %d", buf_size);
    if (buf_size == 0) return AVERROR_EOF;
    struct demux_pos_info *info = opaque;
    long total = 0;

    while (buf_size)
    {
        refbuf_t *r = info->current;
        int last_block = r->next ? 0 : 1;

        if (info->pos >= r->len)
        {
            if (info->lag < 180000 || last_block)
            {
                // DEBUG3 ("Have read from %p need more (total %ld, lag %d)", r, total, info->lag);
                info->need_more = 1;
                if (total || last_block)
                    break;
            }
            // else
                // DEBUG3 ("Have read all from %p (total %ld, lag %d)", r, total, info->lag);
            info->current = r->next;
            info->current_pos += r->len;
            info->lag -= r->len;
            info->pos = 0;
            continue;
        }
        uint8_t *src = (uint8_t*)r->data + info->pos;
        int remain = FFMIN ((r->len - info->pos), buf_size);

        memcpy (buf, src, remain);
        info->pos += remain;
        buf_size -= remain;
        buf += remain;
        total += remain;
    }

    //static uint64_t alltotal = 0;
    //alltotal += total;
    //DEBUG3 ("total in blocks %ld, req %d, ret %ld", alltotal, buf_size, total);
    return total;
}


static int mpts_write_buffer (void *opaque, uint8_t *buf, int buf_size)
{
    struct sync_callback_t *cb = opaque;
    source_t *source = cb->callback_key;
    struct demux_pos_info *info = cb->aux_1;
    refbuf_t *r;

    // static uint64_t total = 0;
    int remaining = buf_size;

    while (remaining)
    {
        int append = 1;
        if (info->to_queue == NULL)
        {
            int len = info->flush_pkts ? remaining : 8084;

            info->to_queue = r = refbuf_new (len);
            info->to_queue_pos = 0;
        }
        else
        {
            r = info->to_queue;
        }
        int queued = 0;
        if (info->flush_pkts)
        {
            if (info->to_queue_pos)  // flush current part filled block, then loop back around
            {
                append = 0;
                r->len = info->to_queue_pos;
            }
            else if (cb->seen_key)
            {
                info->flush_pkts = 0;
                r->flags |= SOURCE_BLOCK_SYNC;
                cb->seen_key = 0;
                //DEBUG1 ("pushed block of %d with key", buf_size);
            }
            //else
            //DEBUG1 ("pushed block of %d", buf_size);
        }
        if (append)
        {
            char *dst = r->data + info->to_queue_pos;

            queued = FFMIN (remaining, (r->len - info->to_queue_pos));
            memcpy (dst, buf, queued);
            info->to_queue_pos += queued;
            buf += queued;

            if ((r->len - info->to_queue_pos < 200))
                r->len = info->to_queue_pos;

        }
        if (r->len == info->to_queue_pos)
        {
            refbuf_t *n = NULL;
            int remaining = mpeg_complete_frames (&info->sync, r, 0);
            if (remaining > 0)
            {
                n = refbuf_new (8084);
                memcpy (n->data, r->data+r->len, remaining);
            }
            // DEBUG4 ("pushed block of %d%s (bz %d, rem %d)", r->len, (r->flags&SOURCE_BLOCK_SYNC ? " with key":""), buf_size, remaining);
            // total += r->len;
            // DEBUG1 ("total in blocks for queuing %ld", total);
            source_add_queue_buffer (source, r);
            info->to_queue = n;
            info->to_queue_pos = n ? remaining : 0;
        }
        // else
            // DEBUG3 ("store  block of %d, mem %d, bz %d", info->to_queue_pos, r->len, buf_size);
        remaining -= queued;
    }
    return buf_size;
}


#if HAVE_AVSTREAM_CODECPAR
AVStream *copy_avstream (AVFormatContext *fmt_ctx, AVStream *s)
{
    AVStream *d = avformat_new_stream (fmt_ctx, NULL);
    int ret = avcodec_parameters_copy (d->codecpar, s->codecpar);
    if (ret < 0) {
        return NULL;
    }
    d->index = s->index;
    d->avg_frame_rate = s->avg_frame_rate;
    d->time_base = s->time_base;
    av_dict_copy (&d->metadata, s->metadata, 0);
    d->codecpar->codec_tag = 0;
    // printf ("copied codec %s\n", avcodec_get_name (d->codecpar->codec_id));
    return d;
}
#else
AVStream *copy_avstream (AVFormatContext *fmt_ctx, AVStream *s)
{
    AVStream *d = avformat_new_stream (fmt_ctx, s->codec->codec);
    //Copy the settings of AVCodecContext
    int ret = avcodec_copy_context (d->codec, s->codec);
    if (ret < 0)
    {
        INFO1 ("failed to copy context with %d", ret);
        return NULL;
    }
    d->time_base = s->time_base;
    av_dict_copy (&d->metadata, s->metadata, 0);
    d->codec->codec_tag = 0;
    if (fmt_ctx->oformat->flags & AVFMT_GLOBALHEADER)
        d->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
    return d;
}
#endif


static int add_cached_block (struct mpeg_sync *mp, struct demux_pos_info *info, refbuf_t *block, int remaining)
{
    struct sync_callback_t *cb = mp->cb;
    format_type_t fmt = mpeg_get_type (mp);

    if (cb->cached_len > 5000000 || (fmt != FORMAT_TYPE_UNDEFINED && fmt != FORMAT_TYPE_MPTS))
    {
        source_t *source = cb->callback_key;
        INFO2 ("mount %s, disable caching buffers, %"PRIu32, source->mount, cb->cached_len);
        mpts_reset_av (cb);
        while (cb->cached)
        {
            refbuf_t *r = cb->cached;
            cb->cached = r->next;
            r->next = NULL;
            refbuf_release (r);
        }
        free (cb);
        mp->cb = NULL;
        return -1;
    }
    // static uint64_t total = 0;
    //total += block->len;
    refbuf_t *cached = refbuf_new (0);
    cached->data = block->data;
    cached->len = block->len;

    //struct demux_pos_info *info = cb->aux_1;
    info->lag += block->len;

    //DEBUG2 ("total in blocks for caching %ld, lag %d", total, info->lag);
    block->data = malloc (remaining);
    block->len = 0;
    memcpy (block->data, cached->data + cached->len, remaining);
    *cb->cached_p = cached;
    cb->cached_p = &cached->next;
    cb->cached_len += cached->len;
    cb->cached_count++;
    if (cb->aux_2)
        rate_add (cb->aux_2, cached->len, timing_get_time());
    return 0;
}


static int demux_block (sync_callback_t *cb)
{
    source_t *source = cb->callback_key;
    struct demux_pos_info *info = cb->aux_1;
    AVPacket pkt;
    av_init_packet(&pkt);
    pkt.data = NULL;
    pkt.size = 0;
    int loop = 150;
    int ret = 0;
    do
    {
        loop--;
        if (info->need_more)
        {
            // DEBUG0 ("Getting more data before getting more packets");
            info->need_more = 0;
            break;
        }
        if ((ret = av_read_frame (cb->fmt_ctx, &pkt)) < 0)
        {
            if (ret == AVERROR_EOF)
            {
                WARN1 ("EOF case on %s", source->mount);
                avio_flush (cb->fmt_ctx->pb);
                avio_seek (cb->fmt_ctx->pb, 0, SEEK_SET);
            }
            break;
        }
        if (pkt.flags & AV_PKT_FLAG_CORRUPT)
        {
            DEBUG0 ("packet looks corrupt");
            continue;
        }
        if (pkt.stream_index >= cb->map_sz || cb->mapping [pkt.stream_index] < 0)
        {
            //if (pkt.stream_index >= cb->map_sz)
                //DEBUG1 ("Bad stream index %d", pkt.stream_index);
            av_packet_unref (&pkt);
            continue;
        }
        AVStream    *in_stream = cb->fmt_ctx->streams [pkt.stream_index];
        pkt.stream_index = cb->mapping [pkt.stream_index];

        if (pkt.stream_index == cb->video_stream_idx)
        {
            if (pkt.flags & AV_PKT_FLAG_KEY)
            {
                // DEBUG0 ("Seen keyframe");
                if (cb->seen_initial_key)
                {
                    ret = av_interleaved_write_frame (cb->ofmt_ctx, NULL);  // flush blocks before keyframe
                    if (ret < 0)
                    {
                        loop = 0;
                        // DEBUG1 ("flush failed with %s", av_err2str(ret));
                    }
                    info->flush_pkts = 1;
                }
#if 0
// only used for logging NAL codes
                {
                    const char start[] = { 00, 00, 00, 01 };
                    const uint8_t *s = pkt.data, *p;
                    unsigned len = pkt.size;
                    char out [32];

                    while (len > 4 && (p = memchr (s, '\0', len)))
                    {
                        len = (pkt.data + pkt.size) - p;
                        if (len < 6)
                            break;
                        if (memcmp (p, start, 4) != 0)
                        {
                           len--;
                           s = p + 1;
                           continue;
                        }
                        sprintf (out, "%X-%X-%X-%X-%X", p[0], p[1], p[2], p[3], p[4]);
                        DEBUG1 ("NAL %s", out);
                        //last_code = p[4];
                        len -= 5;
                        s = p + 5;
                    }
                }
#endif
                cb->seen_initial_key = 1;
                cb->seen_key = 1;
            }
        }
        // static uint64_t alltotal = 0;
        // alltotal += pkt.size > 0 ? pkt.size : 0;
        // DEBUG3 ("pkt size %d, %s, total %lu", pkt.size, (pkt.stream_index == cb->video_stream_idx?"Video":"non-video"), alltotal);
        if (cb->seen_initial_key)
        {
            AVStream *out_stream = cb->ofmt_ctx->streams [pkt.stream_index];
#if 1
            av_packet_rescale_ts(&pkt, in_stream->time_base, out_stream->time_base);
#else
            pkt.pts = av_rescale_q_rnd(pkt.pts, in_stream->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
            pkt.dts = av_rescale_q_rnd(pkt.dts, in_stream->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
            pkt.duration = av_rescale_q(pkt.duration, in_stream->time_base, out_stream->time_base);
#endif
            pkt.pos = -1;
            if ((ret = av_interleaved_write_frame (cb->ofmt_ctx, &pkt)) < 0)
                loop = 0;
        }
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(57,12,100)
        av_free_packet (&pkt);
#else
        av_packet_unref (&pkt);
#endif
        //static uint64_t purged = 0;
        for (int i = 0; i < 15; i++)
        {
            refbuf_t *r = cb->cached;
            if (r == info->current)
                break;
            cb->cached = r->next;
            cb->cached_len -= r->len;
            cb->cached_count--;
            r->next = NULL;
            //purged += r->len;
            refbuf_release (r);
        }
        //DEBUG3 ("purged on %s to %d, total %ld", source->mount, cb->cached_len, purged);
    } while (loop);
    if (ret < 0)
    {
        INFO2 ("error on %s is %s", source->mount, av_err2str(ret));
        mpts_reset_av (cb);
        return -1;
    }
    return 0;
}


int process_blocks (struct mpeg_sync *mp, struct sync_callback_t *cb, refbuf_t *block, int remaining)
{
    if (block->len == 0)  // undetected
        return remaining;
    struct demux_pos_info *info = cb->aux_1;

    if (add_cached_block (mp, cb->aux_1, block, remaining) < 0 || info->lag < 250000)
        return remaining;

    //DEBUG1 ("stream buffer added, %d queued", mp->cb->cached_len);
    demux_block (mp->cb);
    //DEBUG1 ("stream buffer processed, %d queued", mp->cb->cached_len);

    return remaining;
}


int do_preblock_checking (struct mpeg_sync *mp, struct sync_callback_t *cb, refbuf_t *block, int remaining)
{
    source_t *source = mp->cb->callback_key;
    if (block->len == 0)  // undetected
        return remaining;

    struct demux_pos_info *info = cb->aux_1;
    if (info == NULL)
    {
        info = calloc (1, sizeof (struct demux_pos_info));
        cb->aux_1 = info;
        mpeg_setup (&info->sync, "AV mux");
    }

    if (cb->aux_2 == NULL)
        cb->aux_2 = rate_setup (3000, 1000);

    if (add_cached_block (mp, info, block, remaining) < 0)
        return remaining;

    if (info->current == NULL)
        info->current = cb->cached;

    // the probe in the lib can take up to a few meg, which is fine for high bandwidth streams but can be
    // more of an issue for smaller bitrates. here we use an avg bitrate measure during this stage only to
    // come up with a scaling upper limit to avoid large data to be collected.
    long checkpoint = 3000000;
    if (cb->cached_len > 350000)
    {
        long t = (long)rate_avg(cb->aux_2);
        if (t > 0)
            checkpoint = t;
        // DEBUG3 ("checkpoint rate on %s is %ld, len id %d", source->mount, t, cb->cached_len);
    }
    if ((mp->cb->cached_len < checkpoint) || (mp->cb->cached_count & 0x1F))
        return remaining;   // skip

    //DEBUG2 ("checking with demux, total %u / %u", mp->cb->cached_len, cb->cached_count);
    int ret = 0, call = 0;
    AVFormatContext *fmt_ctx = mp->cb->fmt_ctx;
    AVIOContext *avio_ctx = mp->cb->avio_ctx;

    do
    {
        if (fmt_ctx)
            INFO1 ("Already have av format context on %s, reusing", source->mount);
        else
        {
            int avio_ctx_buffer_size = 8192;
            av_log_set_level (AV_LOG_QUIET);
            // av_log_set_level (AV_LOG_VERBOSE);
            // av_log_set_level (AV_LOG_TRACE);
            if ((fmt_ctx = avformat_alloc_context()) == NULL)
                break;
            cb->fmt_ctx = fmt_ctx;

            call++;
            uint8_t *avio_ctx_buffer = av_malloc (avio_ctx_buffer_size);
            call++;
            avio_ctx = avio_alloc_context (avio_ctx_buffer, avio_ctx_buffer_size,
                    0, info, &mpts_read_packet, NULL, NULL);
            if (avio_ctx == NULL) break;
            cb->avio_ctx = avio_ctx;

            fmt_ctx->pb = avio_ctx;
            fmt_ctx->probesize = cb->cached_len - 10000;
            fmt_ctx->flags |= (AVFMT_FLAG_NONBLOCK|AVFMT_FLAG_CUSTOM_IO);
            //fmt_ctx->max_delay = 50000;

            call++;
            ret = avformat_open_input (&cb->fmt_ctx, "", NULL, NULL);
            if (ret < 0) break;

            call++;
            ret = avformat_find_stream_info (cb->fmt_ctx, NULL);
            if (ret < 0) break;

            call++;
            ret = av_find_best_stream (cb->fmt_ctx, AVMEDIA_TYPE_VIDEO, -1, -1, NULL, 0);
            if (ret < 0) break;

            mp->cb->video_stream_idx = ret;
            // av_dump_format(fmt_ctx, 0, "streamed", 0);

            cb->map_sz = fmt_ctx->nb_streams;
            cb->mapping = (int*)av_mallocz_array (cb->map_sz, sizeof(*cb->mapping));

            call++;
            avformat_alloc_output_context2 (&cb->ofmt_ctx, NULL, fmt_ctx->iformat->name, NULL);
            // avformat_alloc_output_context2 (&ofmt_ctx, NULL, "mpegts", NULL);

            unsigned char* outbuffer=(unsigned char*)av_malloc(8084);
            call++;
            AVIOContext *avio_out = avio_alloc_context (outbuffer, 8084, 1, cb, NULL, mpts_write_buffer, NULL);
            if (avio_out == NULL) break;

            cb->ofmt_ctx->pb = avio_out;
            cb->ofmt_ctx->flags |= (AVFMT_FLAG_IGNDTS|AVFMT_FLAG_NONBLOCK);

            int i, streams=0;
            for (i = 0; i < fmt_ctx->nb_streams; i++)
            {
                //Create output AVStream according to input AVStream
                AVStream *in_stream = fmt_ctx->streams[i];
#if HAVE_AVSTREAM_CODECPAR
                AVCodecParameters *in_codecpar = in_stream->codecpar;

                if (in_codecpar->codec_type != AVMEDIA_TYPE_AUDIO &&
                        in_codecpar->codec_type != AVMEDIA_TYPE_VIDEO &&
                        in_codecpar->codec_type != AVMEDIA_TYPE_SUBTITLE)
                {
                    cb->mapping[i] = -1;
                    continue;
                }
#endif
                cb->mapping[i] = streams++;

                AVStream *out_stream = copy_avstream (cb->ofmt_ctx, in_stream);
                if (!out_stream) {
                    ret = AVERROR_UNKNOWN;
                    break;
                }
            }
            if (ret < 0)
                break;
            av_dict_copy (&cb->ofmt_ctx->metadata, cb->fmt_ctx->metadata, 0);
            call++;
            if (cb->fmt_ctx->nb_programs)
            {
                if (cb->fmt_ctx->programs[0]->metadata)
                    av_dict_copy (&cb->ofmt_ctx->metadata, cb->fmt_ctx->programs[0]->metadata, 0);
            }
        }
        //DEBUG1 ("initial stream prebuffers checked, %d queued", mp->cb->cached_len);
        rate_free (cb->aux_2);
        cb->aux_2 = NULL;
        mp->settings |= SYNC_CHANGED;
        cb->ofmt_ctx->max_delay = 120000;
#if HAVE_AVSTREAM_CODECPAR
        INFO2 ("Video codec detected on %s as %s", source->mount,
                avcodec_get_name (fmt_ctx->streams [mp->cb->video_stream_idx]->codecpar->codec_id));
#endif

        call++;
        AVDictionary *opts = NULL;
        av_dict_set (&opts, "pcr_period", "80", 0);
        // free opts;
        if ((ret = avformat_write_header (cb->ofmt_ctx, &opts)) < 0)
            break;
        av_dict_free (&opts);

        // av_dump_format (cb->ofmt_ctx, 0, "muxed", 1);

        if (demux_block (cb) >= 0)
        {
            cb->post_process = process_blocks;
            DEBUG2 ("purged initial stream prebuffers on %s, %d queued", source->mount, cb->cached_len);
        }
        return remaining;

    } while(0);
    mpts_reset_av (cb);
    if (cb->cached_len > 2000000)
    {
        if (cb && cb->aux_2)
        {
            rate_free (cb->aux_2);
            cb->aux_2 = NULL;
        }
        INFO3 ("Failed codec detection on %s: %d (%d)", source->mount, ret, call);
        cb->post_process = NULL;
        while (cb->cached)
        {
            refbuf_t *r = cb->cached;
            cb->cached = r->next;
            r->next = NULL;
            refbuf_release (r);
        }
        cb->aux_1 = NULL;
        free (info);
    }
    else
    {
        INFO4 ("codec detection failed with %d on %s: %d (%d), will retry", cb->cached_len, source->mount, ret, call);
        // drop these as the probe as not managed to detect fully all it needs.
        while (cb->cached && cb->cached != info->current)
        {
            refbuf_t *r = cb->cached;
            cb->cached = r->next;
            cb->cached_len -= r->len;
            r->next = NULL;
            refbuf_release (r);
        }
        info->current = NULL;
        info->current_pos = 0;
    }
    return remaining;
}


static void cleanup_cb (sync_callback_t *cb)
{
    if (cb == NULL) return;
    struct demux_pos_info *info = cb->aux_1;
    if (info)
    {
        refbuf_release (info->to_queue);
        mpeg_cleanup (&info->sync);
        free (info);
    }
    while (cb->cached)
    {
        refbuf_t *r = cb->cached;
        cb->cached = r->next;
        r->next = NULL;
        refbuf_release (r);
    }
    if (cb->fmt_ctx)
    {
        avformat_close_input (&cb->fmt_ctx);
        if (cb->avio_ctx)
        {
            av_freep (&cb->avio_ctx->buffer);
            av_freep (&cb->avio_ctx);
        }
        av_freep (&cb->mapping);
    }
    if (cb->ofmt_ctx)
    {
        av_freep (&cb->ofmt_ctx->pb->buffer);
        av_freep (&cb->ofmt_ctx->pb);
        avformat_free_context (cb->ofmt_ctx);
    }
    rate_free (cb->aux_2);
    free (cb);
}
#endif

static int handle_ts_frame (struct mpeg_sync *mp, sync_callback_t *cb, unsigned char *p, int remaining)
{
    int frame_len = syncframe_samplerate (mp);

    if (remaining - frame_len < 0)
        return 0;
    if (frame_len < remaining && p[frame_len] != 0x47)
    {
        if (mp->settings & MPEG_LOG_MESSAGES)
            INFO1 ("missing frame marker from %s", mp->reference);
        mp->sample_count = 0;
        frame_len = -1;
    }
    return frame_len;
}


static unsigned long getMSB4 (unsigned long v)
{
    unsigned long m = v;
    int c = 0;

    for (; m > 15; c++, m >>= 1)
        ;
    //DEBUG1 ("bitrate estimate mark %lu", m);
    if (m == 0xF)  // binary 1111 is not a normal bit pattern, adjust to 1000
        m = 0x10;
    if (m == 0xB)  // binary 1011 is not a normal bit pattern, adjust to 1100
        m = 0xC;
    return c ? m << c : m;
}


/* return -1 for no valid frame at this specified address, 0 for more data needed */
static int check_for_aac (struct mpeg_sync *mp, unsigned char *p, unsigned remaining)
{
    //nocrc = p[1] & 0x1;
    if (get_mpegframe_layer (p) == MPEG_AAC && (p[1] >= 0xF0) && (p[1] <= 0xF9))
    {
        int samplerate_idx = (p[2] & 0x3C) >> 2,
            channels_idx = (((p[2] << 8) + p[3]) & 0x1C0) >> 6;
        int id =  p[1] & 0x8;
        int checking = syncframe_chkframes (mp), channels, samplerate, aac_frames = 0;
        unsigned char *fh = p;
        long aac_bytes = 0;

        while (1) // check as many frames in the block
        {
            //DEBUG1 ("checking aac frames %d", aac_frames);
            int frame_len = get_aac_frame_len (fh);
            if (frame_len <= 0 || frame_len > 8192)
                return -1;
            if (frame_len+5 >= remaining)
            {
                if (checking > 0) return 0;
                break;
            }
            if (fh[frame_len] != 255 || fh[frame_len+1] != p[1] || fh[frame_len+2] != p[2]
                    || (fh[frame_len+3]&0xF0) != (p[3]&0xF0))
                return -1;
            int blocks = (fh[6] & 0x3) + 1;
            aac_frames += blocks;
            aac_bytes += (frame_len - 7);
            remaining -= frame_len;
            fh += frame_len;
            checking--;
        }
        // profile = p[1] & 0xC0;
        samplerate = aacp_sample_freq [samplerate_idx];
        channels = aacp_num_channels [channels_idx];
        if (samplerate == 0 || channels == 0)
        {
            if (mp->settings & MPEG_LOG_MESSAGES)
                DEBUG0 ("ADTS samplerate/channel setting invalid");
            return -1;
        }
        mp->marker = 0xFF;
        mp->mask = 0xFFFEFDC0; // match these bits from the marker
        syncframe_set_samplerate (mp, samplerate);
        syncframe_set_channels (mp, channels);

        // get 4 most significant bits for nearest common bitrates.
        long avg_bitrate = getMSB4 ((long)((aac_bytes * 1.028 / aac_frames) * (samplerate/1000.0)) * 8/1024);
        syncframe_set_bitrate (mp, avg_bitrate);

        if (mp->settings & MPEG_LOG_MESSAGES)
        {
            char attrib[40];
            snprintf (attrib, sizeof attrib, "%dHz %d channel(s) %ld kbps", samplerate, channels, avg_bitrate);
            INFO3 ("Detected AAC MPEG-%s, %s on %s", id ? "2" : "4", attrib, mp->reference);
        }
        mp->process_frame = handle_aac_frame;
        mp->type = FORMAT_TYPE_AAC;
        mp->settings |= SYNC_CHANGED;
        return 1;
    }
    return -1;
}

static int check_for_mp3 (struct mpeg_sync *mp, unsigned char *p, unsigned remaining)
{
    int layer = get_mpegframe_layer (p);
    if (layer != MPEG_AAC && (p[1] >= 0xE0))
    {
        const char *version[] = { "MPEG 2.5", NULL, "MPEG 2", "MPEG 1" };
        const char *layer_names[] = { NULL, "Layer 3", "Layer 2", "Layer 1" };
        int ver_id = get_mpegframe_version (p);
        if (version [ver_id] && layer_names [layer])
        {
            int checking = syncframe_chkframes (mp), samplerate, channels = 2, frames = 0;
            unsigned char *fh = p;
            unsigned long bitrate_acc = 0;

            // au.crc = (p[1] & 0x1) == 0;
            mp->settings |= ((uint64_t)ver_id << SYNC_MPEG_VER_OFF);
            samplerate = get_mpegframe_samplerate (p);
            if (samplerate == 0)
                return -1;
            syncframe_set_samplerate (mp, samplerate);
            do
            {
                int frame_len;

                if (remaining <= 4)
                    return 0;
                if (fh [0] != 255 || fh [1] != p[1])
                    return -1;
                frame_len = get_mpeg_frame_length (mp, fh);
                if (frame_len <= 0 || frame_len > 3000)
                {
                    //DEBUG2 ("checking frame %d, but len %d invalid", 5-checking, frame_len);
                    return -1;
                }
                if (frame_len > remaining)
                {
                    //DEBUG3 ("checking frame %d, but need more data (%d,%d)", 5-checking, frame_len, remaining);
                    return 0;
                }
                if (samplerate != get_mpegframe_samplerate (fh))
                    return -1;
                //DEBUG4 ("frame %d checked, next header codes are %x %x %x", 5-checking, fh[frame_len], fh[frame_len+1], fh[frame_len+2]);
                frames++;
                bitrate_acc += syncframe_bitrate (mp);
                remaining -= frame_len;
                fh += frame_len;
            } while (--checking);
            if  (((p[3] & 0xC0) >> 6) == 3)
                channels = 1;
            mp->marker = 0xFF;
            mp->mask = 0xFFFE0000;

            long avg_bitrate = bitrate_acc / frames;
            syncframe_set_bitrate (mp, avg_bitrate);
            if (mp->settings & MPEG_LOG_MESSAGES)
            {
                char stream_attrib[30];
                snprintf (stream_attrib, sizeof (stream_attrib), "%d %d %ld kbps", samplerate, channels, avg_bitrate);

                INFO4 ("%s %s Detected (%s) on %s", version [ver_id], layer_names[layer], stream_attrib, mp->reference);
            }
            syncframe_set_channels (mp, channels);
            mp->type = FORMAT_TYPE_MPEG;
            mp->process_frame = handle_mpeg_frame;
            mp->settings |= SYNC_CHANGED;
            return 1;
        }
    }
    return -1;
}


static int handle_usac_frame (struct mpeg_sync *mp, sync_callback_t *cb, unsigned char *p, int remaining)
{
    int frame_len = 3 + (((p[1]&0x1F) << 8) | p[2]);

    if (remaining - frame_len < 0)
        return 0;
    if (frame_len < remaining && p[frame_len] != 0x56)
    {
        INFO1 ("missing frame marker from %s", mp->reference);
        mp->sample_count = 0;
        frame_len = -1;
    }
    return frame_len;
}


static int check_for_usac (struct mpeg_sync *mp, unsigned char *p, unsigned remaining)
{
    int checking = syncframe_chkframes (mp), offset = 0;
    while (checking)
    {
        checking--;
        if (offset+2 > remaining) return 0;
        if (p[offset] == 0x56 && (p[offset+1] & 0xE0) == 0xE0)
        {
            int len = ((p[offset+1]&0x1F) << 8) | p[offset+2];
            offset += (len + 3);
            continue;
        }
        return -1;
    }
    INFO1 ("Detected USAC/LOAS on %s", mp->reference);
    mp->process_frame = handle_usac_frame;
    mp->type = FORMAT_TYPE_USAC;
    mp->mask = 0xFFE00000;
    mp->marker = 0x56;
    mp->settings |= SYNC_CHANGED;
    return 1;
}


static int check_for_ts (struct mpeg_sync *mp, unsigned char *p, unsigned remaining)
{
    int pkt_len = 188, checking;
    do
    {
        int offset = 0;
        checking = 4;
        while (checking)
        {
            if (offset > remaining) return 0;
            if (p [offset] != 0x47)
            {
                switch (pkt_len) {
                    case 204: pkt_len = 208; break;
                    case 188: pkt_len = 204; break;
                    default:  return -1;
                }
                break;
            }
            //DEBUG2 ("found 0x37 checking %d (%d)", checking, pkt_len);
            offset += pkt_len;
            checking--;
        }
    } while (checking);
    if (mp->settings & MPEG_LOG_MESSAGES)
        INFO2 ("Detected TS (%d) on %s", pkt_len, mp->reference);
    mp->process_frame = handle_ts_frame;
    mp->mask = 0xFF000000;
    mp->marker = 0x47;

    syncframe_set_samplerate (mp, pkt_len);
    mp->type = FORMAT_TYPE_MPTS;
#if HAVE_AV
    if (mp->cb)
    {
        mp->cb->post_process = do_preblock_checking;
    }
#endif
    return 1;
}


// this is only really called once, we need to return a length but reset for frame check
//
static int handle_id3_frame (struct mpeg_sync *mp, sync_callback_t *cb, unsigned char *p, int remaining)
{
    int frame_len = mp->sample_count;

    if (remaining < frame_len)
        return 0;
    if (mp->settings & MPEG_COPY_META)
    {
        DEBUG2 ("caching ID3 frame of %d on %s", frame_len, mp->reference);
        free (mp->tag_data);
        mp->tag_data = malloc (frame_len);
        mp->tag_len = frame_len;
        memcpy (mp->tag_data, p, frame_len);
        mp->settings |= SYNC_CHANGED;
    }
    if (mp->settings & MPEG_KEEP_META)
    {
        mp->mask = 0;
        return frame_len;
    }
    return -1;
}

static int check_for_id3 (struct mpeg_sync *mp, unsigned char *p, unsigned remaining)
{
    int ret = 0;

    do
    {
        if (remaining < 16) break;

        ret = 1;
        int set_callback = (mp->mask) ? 0 : 1;

        if (memcmp (p, "APETAGEX", 8) == 0)
        {
            unsigned int ver = p[8], len = p[12];

            ver += (p[9] << 8);
            ver += (p[10] << 16);
            ver += (p[11] << 24);
            ver /= 1000;

            len += (p[13] << 8);
            len += (p[14] << 16);
            len += (p[15] << 24);
            len += 32;

            if (len > remaining)
                return 0;
            if (mp->settings & MPEG_KEEP_META)
            {
                if (set_callback)
                {
                    mp->process_frame = handle_id3_frame;
                    mp->mask = 0xFF000000;
                    mp->marker = 0x41;  // match the 'A'
                }
                mp->sample_count = len;
                if (mp->settings & MPEG_LOG_MESSAGES)
                    DEBUG2 ("Detected APETAG v%u, length %u", ver, len);
            }
            else
            {
                if (mp->settings & MPEG_LOG_MESSAGES)
                    DEBUG2 ("Detected APETAG v%u, skipping %u bytes", ver, len);
                memset (p, 0, len);
            }
            break;
        }
        if (memcmp (p, "TAG", 3) == 0)
        {
            if (remaining < 128)
                return 0;       // placed at the end of files.
            if (mp->settings & MPEG_KEEP_META)
            {
                mp->process_frame = handle_id3_frame;
                mp->mask = 0xFF000000;
                mp->marker = 0x54;  // match the 'T'
                mp->sample_count = 128;
                if (mp->settings & MPEG_LOG_MESSAGES)
                    INFO0 ("Detected ID3v1, keeping");
            }
            else
            {
                if (mp->settings & MPEG_LOG_MESSAGES)
                    INFO0 ("Detected ID3v1, skipping 128 bytes");
                memset (p, 0, 128);
            }
            break;
        }
        if (memcmp (p, "ID3", 3) == 0)
        {
            if (p[3] < 0xFF && p[4] < 0xFF && (p[5] & 0xF) == 0)
            {
                int ver = p[3], rev = p[4];
                size_t size = (p[6] & 0x7f);
                size = (size << 7) + (p[7] & 0x7f);
                size = (size << 7) + (p[8] & 0x7f);
                size = (size << 7) + (p[9] & 0x7f);

                mp->sample_count = size + 10;
                if (size > remaining)
                {
                    mp->settings |= SYNC_RESIZE;
                    break;      // trigger a recheck
                }
                if (mp->settings & MPEG_LOG_MESSAGES)
                    INFO4 ("Detected ID3v2 (%d.%d), tag size %" PRIu64 " on %s", ver, rev, (uint64_t)size, mp->reference);
                if (set_callback)
                {
                    mp->process_frame = handle_id3_frame;
                    mp->mask = 0xFF000000;
                    mp->marker = 0x49;      // match the 'I'
                }
                break;
            }
        }
        ret = -1;
    } while (0);
    return ret;
}


static unsigned long make_val32 (unsigned char *p)
{
    unsigned long v = *p;
    int idx = 1;

    for (; idx < 4; idx++)
    {
        v <<= 8;
        v += p [idx];
    }
    return v;
}


/* return -1 for no valid frame at this specified address, 0 for more data needed */
static int get_initial_frame (struct mpeg_sync *mp, unsigned char *p, unsigned remaining)
{
    int ret = -1;

    if (mp->settings & MPEG_SKIP_SYNC)
        return 2; // we should skip processing

    // reset all but external options
    mp->settings &= (MPEG_LOG_MESSAGES|MPEG_KEEP_META|MPEG_COPY_META|SYNC_CHKFRAME_MASK);

    mp->type = FORMAT_TYPE_UNDEFINED;

    if (p[0] == 'I' || p[0] == 'T' || p[0] == 'A')
       ret = check_for_id3 (mp, p, remaining);
    if (memcmp (p, "\x1A\x45\xDF\xA3", 4) == 0)
    {
        if (mp->settings & MPEG_LOG_MESSAGES)
            INFO0 ("Detected Matroska, skipping");
        mp->settings |= MPEG_SKIP_SYNC;
        mp->type = FORMAT_TYPE_EBML;
        return 1;
    }
    if (memcmp (p, "OggS", 4) == 0)
    {
        if (mp->settings & MPEG_LOG_MESSAGES)
            INFO0 ("Detected possible Ogg page, skipping");
        mp->settings |= MPEG_SKIP_SYNC;
        mp->type = FORMAT_TYPE_OGG;
        return -1;
    }
    if (ret < 0 && p[0] == 0x47)
        ret = check_for_ts (mp, p, remaining);
    if (ret < 0 && p[1] >= 0xE0)
    {
        mp->settings |= ((uint64_t)get_mpegframe_layer (p) << SYNC_MPEG_LAYER_OFF); // layer setting
        ret = check_for_aac (mp, p, remaining);
        if (ret < 0)
            ret = check_for_mp3 (mp, p, remaining);
    }
    if (ret < 0 && p[0] == 0x56 && (p[1]&0xE0) == 0xE0)
        ret = check_for_usac(mp, p, remaining);
    if (ret > 0)
    {
        mp->resync_count = 0;
        mp->match = make_val32 (p) & mp->mask;
    }
    return ret;
}



static int match_syncbits (mpeg_sync *mp, unsigned char *p, unsigned remaining)
{
    unsigned long v = make_val32 (p);

    if ((v & mp->mask) != mp->match)
    {
        int ret = check_for_id3 (mp, p, remaining);
        if (ret < 0)
            return -1;
        mp->settings |= SYNC_CHK_TAG;
    }
    return 0;
}


/* return number from 0 to remaining */
static int find_align_sync (mpeg_sync *mp, unsigned char *start, int remaining, int prevent_move)
{
    int skip = remaining, singlebyte = mp->mask & 0xFFFFFF ? 0 : 1;
    unsigned char *p = NULL;

    if (mp->mask)
    {
        unsigned char *s = start;
        int r = remaining;

        do
        {
            if (r < 9) break;
            if (memcmp (s, "TAG", 3) == 0 || memcmp (s, "ID3", 3) == 0 || memcmp (s, "APETAGEX", 8) == 0)
            {
                if (mp->settings & MPEG_LOG_MESSAGES)
                    INFO1 ("Detected \"%.3s\" midstream", s);
                break;
            }
            p = start;
            while (r && (p = memchr (s, mp->marker, r)))
            {
                if (singlebyte)
                    break;
                r = remaining - (p - start);
                if (r < 4)
                    break;
                if (match_syncbits (mp, p, remaining) == 0)
                    break;
                s = p+1;
                r--;
            }
        } while (0);
        if (p == NULL)
            mp->mask = 0;
    }
    if (p == NULL)
    {
        p = start;
        if (remaining >= 8 && memcmp (p+4, "ftyp", 4) == 0)
        {
            mp->settings |= MPEG_SKIP_SYNC; // mp4 looks to be here, lets skip parsing
            mp->type = FORMAT_TYPE_MP4;
            return 0;
        }
        if (remaining >= 4 && memcmp (p, "\x1A\x45\xDF\xA3", 4) == 0)
        {
            mp->settings |= MPEG_SKIP_SYNC; // matroska looks to be here, lets skip parsing
            mp->type = FORMAT_TYPE_EBML;
            return 0;
        }
        else
        {
            int offset = remaining;
            do {
                if (offset < 3) break;
                if (*p == 0x47) break;   // MPEG TS
                if (*p == 0x56)
                    if ((p[1] & 0xE0) == 0xE0) break; // USAC
                if (*p == 0xFF)
                    if (p[1] != 0xFF || p[2] <= 0xFB) break;
                if (offset > 3 && memcmp (p, "OggS", 4) == 0)
                    break;
                if (memcmp (p, "ID3", 3) == 0 || memcmp (p, "TAG", 3) == 0)
                    break;
                if (offset > 7 && memcmp (p, "APETAGEX", 8) == 0)
                    break;
                p++;
                offset--;
            } while (1);
            if (offset == 0) p = NULL;
        }
    }
    if (p)
    {
        skip = p - start;
        remaining -= skip;
        if (remaining < 20000 && prevent_move == 0 && skip)
            memmove (start, p, remaining);
        mp->resync_count += skip;
    }
    return skip;
}


int mpeg_complete_frames_cb (mpeg_sync *mp, sync_callback_t *cb, refbuf_t *new_block, unsigned offset)
{
    unsigned char *start, *end;
    int remaining, frame_len = 0, ret, loop = 50;
    unsigned long samples = 0;

    if (mp == NULL || (mp->settings & MPEG_SKIP_SYNC))
        return 0;  /* leave as-is */
    
    mp->settings &= ~SYNC_RESIZE;
    mp->sample_count = 0;
    if (offset == 0)
    {
        if (new_block->flags&REFBUF_SHARED)
        {
            if (syncframe_chkframes (mp) > 1)
                syncframe_set_framecheck (mp, 1);
        }
        else
            if (syncframe_chkframes (mp) <= 1)
                syncframe_set_framecheck (mp, 4);
    }
    if (mp->surplus)
    {
        if (offset >= mp->surplus->len)
            offset -= mp->surplus->len;
        else
        {
            int new_len = mp->surplus->len + new_block->len;
            unsigned char *p = realloc (mp->surplus->data, new_len);

            memcpy (p+mp->surplus->len, new_block->data, new_block->len);
            mp->surplus->data = new_block->data;
            new_block->data = (void*)p;
            new_block->len = new_len;
        }
        refbuf_release (mp->surplus);
        mp->surplus = NULL;
    }
    start = (unsigned char *)new_block->data + offset;
    while (loop)
    {
        end = (unsigned char*)new_block->data + new_block->len;
        remaining = end - start;
        //DEBUG2 ("block size %d, remaining now %d", new_block->len, remaining);
        if (remaining < 10) /* make sure we have some bytes to check */
            break;
        if (mp->mask && match_syncbits (mp, start, remaining) == 0)
        {
            if (mp->settings & SYNC_CHK_TAG)
            {
                // tags can be injected midstream, so avoid a full resync as they would be only a frame, but handle
                // the possible resizing of the block.
                if (mp->settings & SYNC_RESIZE)
                {
                    unsigned old_len = new_block->len;
                    unsigned new_len = old_len - remaining + (mp->sample_count ? mp->sample_count : 5000);
                    unsigned char *p = realloc (new_block->data, new_len);
                    new_block->data = (void*)p;
                    new_block->len = new_len;
                    mp->settings &= ~SYNC_CHK_TAG;
                    return old_len;
                }
                frame_len = handle_id3_frame (mp, cb, start, remaining);
            }
            else
                frame_len = mp->process_frame (mp, cb, start, remaining);
            if (frame_len == 0)
                break;
            if (frame_len > 0)
            {
                samples += mp->sample_count;
                start += frame_len;
                mp->resync_count = 0;
                mp->settings &= ~SYNC_CHK_TAG;
                continue;
            }
            if ((mp->settings & SYNC_CHK_TAG) == 0)
            {
                if (mp->sample_count == 0 || remaining < mp->sample_count)
                    mp->sample_count = 1;
                mp->mask = 0;
            }
            if ((new_block->flags & REFBUF_SHARED) == 0)
            {
                memmove (start, start+mp->sample_count, remaining-mp->sample_count);
                new_block->len -= mp->sample_count;
            }
            else
                start += mp->sample_count;
            mp->sample_count = 0;
            mp->settings &= ~SYNC_CHK_TAG;
            continue;
        }

        // no frame header match, let look elsewhere.
        ret = find_align_sync (mp, start, remaining, new_block->flags&REFBUF_SHARED);
        if (ret)
        {
            if (ret == remaining && ret > 800)
               mp->mask = 0;
            if (mp->resync_count > 100000)
            {
                if (mp->settings & MPEG_LOG_MESSAGES)
                    INFO1 ("no frame sync after 100k on %s", mp->reference);
                mp->settings |= MPEG_SKIP_SYNC; // lets skip parsing
                mp->type = FORMAT_TYPE_UNDEFINED;
                return 0;
            }
            if ((new_block->flags & REFBUF_SHARED) == 0)
            {
                if (mp->settings & MPEG_LOG_MESSAGES)
                    DEBUG3 ("no frame sync on %s, re-checking after skipping %d (%d)", mp->reference, ret, new_block->len);
                new_block->len -= ret;
            }
            samples = 0;
            continue;
        }
        if (mp->mask == 0)
        {
            int ret = get_initial_frame (mp, start, remaining);
            if (ret < 0)
            {
                // failed to detect a complete frame, try another search
                *start = 0;
                mp->settings &= ~MPEG_SKIP_SYNC;
                continue;
            }
            if (ret == 0)
            {
                if (remaining > 100000)
                    return -1;
                if ((new_block->flags & REFBUF_SHARED) == 0 && (mp->settings & SYNC_RESIZE))
                {
                    unsigned new_len = mp->sample_count ? mp->sample_count : new_block->len + 5000;
                    unsigned char *p = realloc (new_block->data, new_len);
                    new_block->data = (void*)p;
                    new_block->len = new_len;
                }
                else
                    new_block->len = offset;
                return remaining;
            }
            if (ret > 1) // detected case but avoid parsing
                return 0;
            if ((new_block->flags & REFBUF_SHARED) == 0)
            {
                if ((mp->settings & SYNC_RESIZE) && mp->sample_count < 2000000)
                {
                    unsigned new_len = mp->sample_count + (new_block->len - remaining);
                    unsigned char *p = realloc (new_block->data, new_len);

                    new_block->data = (void*)p;
                    new_block->len = new_len;
                    return remaining;
                }
            }
        }
        loop--;
    }
    if (remaining < 0 || remaining > new_block->len)
    {
        if (mp->settings & MPEG_LOG_MESSAGES)
            ERROR2 ("block inconsistency (%d, %d)", remaining, new_block->len);
        abort();
    }
    if (remaining && (new_block->flags & REFBUF_SHARED) == 0)
        new_block->len -= remaining;
    mp->sample_count = samples;
    if (mp->cb)
    {
        cb = mp->cb;
        if (cb->post_process)
            return cb->post_process (mp, cb, new_block, remaining);
    }
    return remaining;
}


int mpeg_tag_found (mpeg_sync *mp, const unsigned char **p, unsigned int *l)
{
    int r = -1;
    if (p && l)
    {
       *p = mp->tag_data;
       *l = mp->tag_len;
       r = 0;
    }
    return r;
}


int mpeg_block_expanded (mpeg_sync *mp)
{
    return (mp && (mp->settings & SYNC_RESIZE)) ? 1 : 0;
}

void mpeg_data_insert (mpeg_sync *mp, refbuf_t *inserted)
{
    if (mp)
        mp->surplus = inserted;
}


void mpeg_setup_key (mpeg_sync *mpsync, const char *reference, void *key)
{
    memset (mpsync, 0, sizeof (mpeg_sync));
    syncframe_set_framecheck (mpsync, 4);
    mpsync->settings |= MPEG_LOG_MESSAGES;
    mpsync->reference = reference;
    if (key)
    {
        sync_callback_t *cb = mpeg_alloc_callback (mpsync);
        cb->callback_key = key;
    }
}


frame_type_t mpeg_get_type (struct mpeg_sync *mp)
{
    return mp->type;
}

void mpeg_check_numframes (mpeg_sync *mpsync, unsigned count)
{
    if (count && count < 100)
        syncframe_set_framecheck (mpsync, count);
    if (count == 1)  // client processing, reduce heavy logging
        mpsync->settings &= ~MPEG_LOG_MESSAGES;
}

void mpeg_cleanup (mpeg_sync *mpsync)
{
    if (mpsync)
    {
        if (mpsync->cb)
            cleanup_cb (mpsync->cb);
        free (mpsync->tag_data);
        refbuf_release (mpsync->surplus);
        mpsync->reference = NULL;
    }
}
