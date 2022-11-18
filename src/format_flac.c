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


/* Ogg codec handler for FLAC logical streams */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <ogg/ogg.h>
#include <string.h>

typedef struct source_tag source_t;

#include "refbuf.h"
#include "format_ogg.h"
#include "client.h"
#include "stats.h"
#include "global.h"

#define CATMODULE "format-flac"
#include "logging.h"


static void flac_codec_free (ogg_state_t *ogg_info, ogg_codec_t *codec)
{
    DEBUG0 ("freeing FLAC codec");
    stats_event (ogg_info->mount, "FLAC_version", NULL);
    ogg_stream_clear (&codec->os);
    free (codec);
}


/* Here, we just verify the page is ok and then add it to the queue */
static refbuf_t *process_flac_page (ogg_state_t *ogg_info, ogg_codec_t *codec, ogg_page *page)
{
    refbuf_t * refbuf;

    if (codec->headers)
    {
        int loop = 3;
        ogg_packet packet;
        if (ogg_stream_pagein (&codec->os, page) < 0)
        {
            ogg_info->error = 1;
            return NULL;
        }
        while (loop)
        {
            int pkt = ogg_stream_packetout (&codec->os, &packet);

            if (pkt > 0)
            {
                int type = packet.packet[0];
                if (type == 0xFF) // seen audio pkt, drop to normal processing
                {
                    codec->headers = 0;
                    break;
                }
                codec->headers--;
                // other valid header pkts are fine
                if (type >= 1 && type <= 0x7E)
                    continue;
                if (type >= 0x81 && type <= 0xFE)
                    continue;
                // something odd
                ogg_info->error = 1;
                return NULL;
            }
            loop = (pkt < 0) ? (loop-1) : 0;
        }
        if (codec->headers)
        {
            DEBUG0("Adding header page");
            format_ogg_attach_header (codec, page);
            return NULL;
        }
    }
    refbuf = make_refbuf_with_page (codec, page);
    return refbuf;
}


/* Check for flac header in logical stream */

ogg_codec_t *initial_flac_page (format_plugin_t *plugin, ogg_page *page)
{
    ogg_state_t *ogg_info = plugin->_state;
    ogg_codec_t *codec = calloc (1, sizeof (ogg_codec_t));
    ogg_packet packet;

    ogg_stream_init (&codec->os, ogg_page_serialno (page));
    ogg_stream_pagein (&codec->os, page);

    ogg_stream_packetout (&codec->os, &packet);

    DEBUG0("checking for FLAC codec");
    do
    {
        unsigned char *parse = packet.packet;
        // format 0x7F F L A C, '1' x  y y f L a C zzzzz
        // x   1 byte minor number
        // y   2 BE byte count of header packets
        // z   StreamINFO structure

        if (page->header_len + page->body_len != 79)
            break;
        if (parse[0] != 0x7F)
            break;

        if (memcmp (parse+1, "FLAC", 4) != 0)
            break;

        if (parse[5] != 1)
        {
            WARN1 ("Unknown Ogg FLAC version %d, skipping", parse[5]);
            break;
        }
        int headers = (parse[7]<<8) + parse[8];
        if (headers == 0)
        {
            WARN0 ("FLAC stream has unknown number of headers, skipping");
            break;
        }
        if (memcmp (parse+9, "fLaC", 4) != 0)
            break;
        uint32_t samplerate = (((parse[9+10] << 8) + parse[9+11]) << 4) + (parse[9+12]>>4);
        if (samplerate == 0)
            INFO0 ("seen initial FLAC header");
        else
        {
            uint32_t channels = ((parse[9+12]>>1) & 0x7) + 1;
            INFO2 ("seen initial FLAC header (hint %dHz, channels %d)", samplerate, channels);
        }
        stats_event_args (ogg_info->mount, "FLAC_version", "%d.%d",  parse[5], parse[6]);
        codec->process_page = process_flac_page;
        codec->codec_free = flac_codec_free;
        codec->headers = headers;
        codec->parent = ogg_info;
        codec->name = "FLAC";

        format_ogg_attach_header (codec, page);
        return codec;
    } while (0);

    ogg_stream_clear (&codec->os);
    free (codec);
    return NULL;
}

