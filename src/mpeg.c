/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2009-2012,  Karl Heyes <karl@xiph.org>
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
#include "global.h"

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

//  settings is a bitmask
//  bit 15         skip processing
//  bit 14         log messages
//  bit 8          allow trailing tags, eg from file
//  bit 7          settings changed
//  bit 6, 5, 4    channels
//  bit 3, 2       version
//  bit 1, 0       layer


int mpeg_has_changed (struct mpeg_sync *mp)
{
    int v = mp->settings & 0x80;
    if (v) mp->settings &= ~0x80; // reset
    return v ? 1 : 0;
}

int mpeg_get_channels (struct mpeg_sync *mp)
{
    return (mp->settings & 0x70) >> 4;
}


int mpeg_get_version (struct mpeg_sync *mp)
{
    return (mp->settings & 0xC) >> 2;
}


int mpeg_get_layer (struct mpeg_sync *mp)
{
    return (mp->settings & 0x3);
}

void mpeg_set_flags (mpeg_sync *mpsync, unsigned flags)
{
    mpsync->settings |= flags;
}


static int get_aac_frame_len (unsigned char *p)
{
    return ((p[3] & 0x3) << 11) + (p[4] << 3) + ((p[5] & 0xE0) >> 5);
}

static int handle_aac_frame (struct mpeg_sync *mp, unsigned char *p, int len)
{
    int frame_len = get_aac_frame_len (p);
    int blocks, header_len = 9;
    int samplerate_idx = (p[2] & 0x3C) >> 2, samplerate;
    if (len - frame_len < 0)
        return 0;

    samplerate = aacp_sample_freq [samplerate_idx];
    if (samplerate != mp->samplerate)
    {
        if (mp->settings & MPEG_LOG_MESSAGES)
            WARN3 ("detected samplerate change from %d to %d on %s", mp->samplerate, samplerate, mp->mount);
        mp->samplerate = samplerate;
    }

    blocks = (p[6] & 0x3) + 1;
    if (p[1] & 0x1) // no crc
        header_len -= 2;
    mp->sample_count = (blocks * 1024);

    if (mp->frame_callback)
        if (mp->frame_callback (mp, p, frame_len, header_len) < 0)
            return -1;

    return frame_len;
}

static int get_mpegframe_samplerate (unsigned char *p)
{
    int ver = (p[1] & 0x18) >> 3;
    return mpeg_samplerates [(p[2]&0xC) >> 2][ver];
}

static int get_mpeg_bitrate (struct mpeg_sync *mp, unsigned char *p)
{
    int bitrate = -1;
    int bitrate_code = (p[2] & 0xF0) >> 4;
    int layer = mpeg_get_layer (mp);

    if (mpeg_get_version (mp) == 0x3) // MPEG1
    {
        static int bitrates [3][16] = {
            { 0, 32, 40, 48,  56,  64,  80,  96, 112, 128, 160, 192, 224, 256, 320, -1 },
            { 0, 32, 48, 56,  64,  80,  96, 112, 128, 160, 192, 224, 256, 320, 348, -1 },
            { 0, 32, 54, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, -1 } };
        if (layer != MPEG_AAC)
            bitrate = bitrates [layer-1][bitrate_code];
    }
    else // MPEG2/2.5
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
    int layer = mpeg_get_layer (mp);
    int samples = get_samples_per_mpegframe (mpeg_get_version (mp), layer);
    int samplerate = get_mpegframe_samplerate (p);

    if (samplerate == 0 || (mp->mask && mp->samplerate != samplerate))
        return -1;
    mp->sample_count = samples;
    if (bitrate > 0 && samples > 0)
    {
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


static int handle_mpeg_frame (struct mpeg_sync *mp, unsigned char *p, int remaining)
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
                    WARN2 ("detected samplerate change to %d on %s", samplerate, mp->mount);
                mp->samplerate = samplerate;
                return handle_mpeg_frame (mp, p, remaining);
            }
            if (mp->settings & MPEG_LOG_MESSAGES)
                INFO1 ("detected invalid frame on %s, skipping", mp->mount);
        }
        return -1;
    }
    if (remaining - frame_len < 0)
        return 0;
    if (mp->frame_callback)
        if (mp->frame_callback (mp, p, frame_len, (p[1] & 0x1) ? 4 : 6) < 0)
            return -1;
    return frame_len;
}


static int handle_ts_frame (struct mpeg_sync *mp, unsigned char *p, int remaining)
{
    int frame_len = mp->container.raw_offset;

    if (remaining - frame_len < 0)
        return 0;
    if (frame_len < remaining && p[frame_len] != 0x47)
        if (mp->settings & MPEG_LOG_MESSAGES)
            INFO1 ("missing frame marker from %s", mp->mount);
    return frame_len;
}


/* return -1 for no valid frame at this specified address, 0 for more data needed */
static int check_for_aac (struct mpeg_sync *mp, unsigned char *p, unsigned remaining)
{
    //nocrc = p[1] & 0x1;
    if (mpeg_get_layer (mp) == 0 && (p[1] >= 0xF0) && (p[1] <= 0xF9))
    {
        int samplerate_idx = (p[2] & 0x3C) >> 2,
            channels_idx = (((p[2] << 8) + p[3]) & 0x1C0) >> 6;
        int id =  p[1] & 0x8;
        int checking = mp->check_numframes, channels;
        unsigned char *fh = p;

        while (checking)
        {
            //DEBUG1 ("checking frame %d", 5-checking);
            int frame_len = get_aac_frame_len (fh);
            if (frame_len <= 0 || frame_len > 8192)
                return -1;
            if (frame_len+5 >= remaining)
                return 0;
            if (fh[frame_len] != 255 || fh[frame_len+1] != p[1] || fh[frame_len+2] != p[2]
                    || (fh[frame_len+3]&0xF0) != (p[3]&0xF0))
                return -1;
            remaining -= frame_len;
            fh += frame_len;
            checking--;
        }
        // profile = p[1] & 0xC0;
        mp->samplerate = aacp_sample_freq [samplerate_idx];
        channels = aacp_num_channels [channels_idx];
        if (mp->samplerate == 0 || channels == 0)
        {
            if (mp->settings & MPEG_LOG_MESSAGES)
                DEBUG0 ("ADTS samplerate/channel setting invalid");
            return -1;
        }
        mp->marker = 0xFF;
        mp->mask = 0xFFFEFDC0; // match these bits from the marker
        mp->settings |= (channels << 4);
        if (mp->check_numframes > 1)
            if (mp->settings & MPEG_LOG_MESSAGES)
                INFO4 ("detected AAC MPEG-%s, rate %d, channels %d on %s", id ? "2" : "4", mp->samplerate, channels, mp->mount);
        mp->process_frame = handle_aac_frame;
        mp->settings |= 0x80;
        return 1;
    }
    return -1;
}

static int check_for_mp3 (struct mpeg_sync *mp, unsigned char *p, unsigned remaining)
{
    int layer = mpeg_get_layer (mp);
    if (layer != MPEG_AAC && (p[1] >= 0xE0))
    {
        const char *version[] = { "MPEG 2.5", NULL, "MPEG 2", "MPEG 1" };
        const char *layer_names[] = { NULL, "Layer 3", "Layer 2", "Layer 1" };
        int ver_id = (p[1] & 0x18) >> 3;
        if (version [ver_id] && layer_names [layer])
        {
            int checking = mp->check_numframes, samplerate, channels = 2;
            unsigned char *fh = p;
            char stream_type[20];

            // au.crc = (p[1] & 0x1) == 0;
            mp->settings |= (ver_id << 2);
            samplerate = get_mpegframe_samplerate (p);
            if (samplerate == 0)
                return -1;
            mp->samplerate = samplerate;
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
                remaining -= frame_len;
                fh += frame_len;
            } while (--checking);
            if  (((p[3] & 0xC0) >> 6) == 3)
                channels = 1;
            mp->settings |= (channels << 4);
            mp->marker = 0xFF;
            mp->mask = 0xFFFE0000;
            snprintf (stream_type, sizeof (stream_type), "%s %s", version [ver_id], layer_names[layer]);
            if (mp->settings & MPEG_LOG_MESSAGES)
                INFO4 ("%s Detected (%d, %d) on %s", stream_type, mp->samplerate, channels, mp->mount);
            mp->settings |= 0x80;
            mp->process_frame = handle_mpeg_frame;
            return 1;
        }
    }
    return -1;
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
        INFO2 ("Detected TS (%d) on %s", pkt_len, mp->mount);
    mp->process_frame = handle_ts_frame;
    mp->mask = 0xFF000000;
    mp->marker = 0x47;
    mp->container.raw_offset = pkt_len;
    mp->settings |= 0x80;
    return 1;
}


// this is only really called once, we need to return a length but reset for frame check
//
static int handle_id3_frame (struct mpeg_sync *mp, unsigned char *p, int remaining)
{
    int frame_len = mp->container.raw_offset;

    if (remaining - frame_len < 0)
        return 0;
    mp->mask = 0;
    return frame_len;
}

static int check_for_id3 (struct mpeg_sync *mp, unsigned char *p, unsigned remaining)
{
    int ret = 0;

    do
    {
        if (remaining < 16) break;

        ret = 1;
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
            if (mp->settings & (1<<8))
            {
                mp->process_frame = handle_id3_frame;
                mp->mask = 0xFF000000;
                mp->marker = 0x41;  // match the 'A'
                mp->container.raw_offset = len;
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
                return 0;
            if (mp->settings & MPEG_KEEP_EOF_TAGS)
            {
                mp->process_frame = handle_id3_frame;
                mp->mask = 0xFF000000;
                mp->marker = 0x54;  // match the 'T'
                mp->container.raw_offset = 128;
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

                if (mp->settings & MPEG_LOG_MESSAGES)
                    INFO3 ("Detected ID3v2 (%d.%d), tag size %" PRIu64, ver, rev, (uint64_t)size);
                mp->process_frame = handle_id3_frame;
                mp->mask = 0xFF000000;
                mp->marker = 0x49;      // match the 'I'
                mp->container.raw_offset = size + 10;
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
    mp->settings = mp->settings & 0xff00;

    if (p[0] == 'I' || p[0] == 'T' || p[0] == 'A')
       ret = check_for_id3 (mp, p, remaining);
    if (memcmp (p, "\x1A\x45\xDF\xA3", 4) == 0)
    {
        if (mp->settings & MPEG_LOG_MESSAGES)
            INFO0 ("Detected Matroska, skipping");
        mp->settings |= MPEG_SKIP_SYNC;
        mp->container.skipped_type = FORMAT_TYPE_EBML;
        return -1;
    }
    if (memcmp (p, "OggS", 4) == 0)
    {
        if (mp->settings & MPEG_LOG_MESSAGES)
            INFO0 ("Detected Ogg, skipping");
        mp->settings |= MPEG_SKIP_SYNC;
        mp->container.skipped_type = FORMAT_TYPE_OGG;
        return -1;
    }
    if (ret < 0 && p[0] == 0x47)
        ret = check_for_ts (mp, p, remaining);
    if (ret < 0)
    {
        if (p[1] < 0xE0)
            return -1;
        mp->settings |= ((p[1] & 0x6) >> 1);
        ret = check_for_aac (mp, p, remaining);
        if (ret < 0)
            ret = check_for_mp3 (mp, p, remaining);
    }
    if (ret > 0)
    {
        mp->resync_count = 0;
        mp->match = make_val32 (p) & mp->mask;
    }
    return ret;
}



static int match_syncbits (mpeg_sync *mp, unsigned char *p)
{
    unsigned long v = make_val32 (p);

    if ((v & mp->mask) != mp->match)
        return -1;
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
                if (match_syncbits (mp, p) == 0)
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
            mp->container.skipped_type = FORMAT_TYPE_MP4;
            return 0;
        }
        if (remaining >= 4 && memcmp (p, "\x1A\x45\xDF\xA3", 4) == 0)
        {
            mp->settings |= MPEG_SKIP_SYNC; // matroska looks to be here, lets skip parsing
            mp->container.skipped_type = FORMAT_TYPE_EBML;
            return 0;
        }
        else
        {
            int offset = remaining;
            do {
                if (offset < 3) break;
                if (*p == 0x47) break;
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


int mpeg_complete_frames (mpeg_sync *mp, refbuf_t *new_block, unsigned offset)
{
    unsigned char *start, *end;
    int remaining, frame_len = 0, ret, loop = 50;

    if (mp == NULL || (mp->settings & MPEG_SKIP_SYNC))
        return 0;  /* leave as-is */
    
    mp->sample_count = 0;
    if (offset == 0)
    {
        if (new_block->flags&REFBUF_SHARED)
        {
            if (mp->check_numframes > 1)
                mp->check_numframes = 1;
        }
        else
            if (mp->check_numframes == 1)
                mp->check_numframes = 4;
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
        if (mp->mask && match_syncbits (mp, start) == 0) 
        {
            frame_len = mp->process_frame (mp, start, remaining);
            if (frame_len == 0)
                break;
            if (frame_len > 0)
            {
                start += frame_len;
                mp->resync_count = 0;
                continue;
            }
            if ((new_block->flags & REFBUF_SHARED) == 0)
            {
                memmove (start, start+1, remaining-1);
                new_block->len--;
            }
            else
                start++;
            continue;
        }

        // no frame header match, let look elsewhere.
        ret = find_align_sync (mp, start, remaining, new_block->flags&REFBUF_SHARED);
        if (ret)
        {
            if (ret == remaining && ret > 800)
               mp->mask = 0;
            if (mp->resync_count > 20000)
            {
                if (mp->settings & MPEG_LOG_MESSAGES)
                    INFO1 ("no frame sync after 20k on %s", mp->mount);
                mp->settings |= MPEG_SKIP_SYNC; // lets skip parsing
                mp->container.skipped_type = FORMAT_TYPE_UNDEFINED;
                return 0;
            }
            if ((new_block->flags & REFBUF_SHARED) == 0)
            {
                if (mp->settings & MPEG_LOG_MESSAGES)
                    DEBUG3 ("no frame sync on %s, re-checking after skipping %d (%d)", mp->mount, ret, new_block->len);
                new_block->len -= ret;
            }
            continue;
        }
        if (mp->mask == 0)
        {
            int ret = get_initial_frame (mp, start, remaining);
            if (ret < 0)
            {
                // failed to detect a complete frame, try another search
                *start = 0;
                continue;
            }
            if (ret == 0)
            {
                if (remaining > 20000)
                    return -1;
                if ((new_block->flags & REFBUF_SHARED) == 0)
                    new_block->len = offset;
                return remaining;
            }
            if (ret > 1) // detected case but avoid parsing
                return 0;
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
    return remaining;
}


void mpeg_data_insert (mpeg_sync *mp, refbuf_t *inserted)
{
    if (mp)
        mp->surplus = inserted;
}

void mpeg_setup (mpeg_sync *mpsync, const char *mount)
{
    memset (mpsync, 0, sizeof (mpeg_sync));
    mpsync->check_numframes = 4;
    mpsync->settings = MPEG_LOG_MESSAGES;
    mpsync->mount = mount;
}

frame_type_t mpeg_get_type (struct mpeg_sync *mp)
{
    if (mp->settings & MPEG_SKIP_SYNC)
        return mp->container.skipped_type;
    if (mp->process_frame == handle_mpeg_frame)
        return FORMAT_TYPE_MPEG;
    if (mp->process_frame == handle_ts_frame)
        return FORMAT_TYPE_MPEG;
    if (mp->process_frame == handle_aac_frame)
        return FORMAT_TYPE_AAC;
    return FORMAT_TYPE_UNDEFINED;
}

void mpeg_check_numframes (mpeg_sync *mpsync, unsigned count)
{
    if (count && count < 100)
        mpsync->check_numframes = count;
    if (count == 1)  // client processing, reduce heavy logging
        mpsync->settings &= ~MPEG_LOG_MESSAGES;
}

void mpeg_cleanup (mpeg_sync *mpsync)
{
    if (mpsync)
    {
        refbuf_release (mpsync->surplus);
        refbuf_release (mpsync->raw);
        mpsync->mount = NULL;
    }
}
