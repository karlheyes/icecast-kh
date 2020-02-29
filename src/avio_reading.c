/*
 * Copyright (c) 2014 Stefano Sabatini
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * @file
 * libavformat AVIOContext API example.
 *
 * Make libavformat demuxer access media content through a custom
 * AVIOContext read callback.
 * @example avio_reading.c
 */

#include <stdio.h>

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavformat/avio.h>
#include <libavutil/file.h>

struct buffer_data {
    uint8_t *base;
    uint8_t *ptr;
    size_t size; ///< size left in the buffer
};

char *input_filename = NULL;
FILE *f = NULL;
long offset = 0;

static int read_packet(void *opaque, uint8_t *buf, int buf_size)
{
    //struct buffer_data *bd = (struct buffer_data *)opaque;
    //buf_size = FFMIN(buf_size, bd->size);

    if (!buf_size)
        return AVERROR_EOF;

    if (f == NULL)
        if ((f = fopen (input_filename, "rb")) == NULL)
        {
            printf ("fopen %s: %s", input_filename, strerror(errno));
            return AVERROR_EOF;
        }
    /* copy internal buffer data to buf */
    int ret = fread (buf, 1, buf_size, f);
    if (ret == 0)
    {
        printf ("EOF on input file, closing\n");
        fclose (f);
        f = NULL;
    }
    if (ret < 0)
    {
        printf ("error on input file\n");
        fclose (f);
        f = NULL;
        return AVERROR_EOF;
    }
    printf("off %ld req:%d, acq %d\n", offset, buf_size, ret);
    offset += ret;
    //memcpy(buf, bd->ptr, ret);
    //bd->ptr  += ret; // buf_size;
    //bd->size -= ret; // buf_size;

    return ret; // buf_size;
}

int main(int argc, char *argv[])
{
    AVFormatContext *fmt_ctx = NULL;
    AVIOContext *avio_ctx = NULL;
    uint8_t *buffer = NULL, *avio_ctx_buffer = NULL;
    size_t buffer_size, avio_ctx_buffer_size = 4096;
    int ret = 0;
    struct buffer_data bd = { 0 };

    if (argc != 2) {
        fprintf(stderr, "usage: %s input_file\n"
                "API example program to show how to read from a custom buffer "
                "accessed through AVIOContext.\n", argv[0]);
        return 1;
    }
    input_filename = argv[1];

    /* slurp file content into buffer */
    //ret = av_file_map(input_filename, &buffer, &buffer_size, 0, NULL);
    //if (ret < 0)
        //goto end;

    /* fill opaque structure used by the AVIOContext read callback */
    //bd.ptr  = buffer;
    //bd.size = buffer_size;
    //bd.ptr = av_malloc (8192);
    //bd.size = 8192;

    if (!(fmt_ctx = avformat_alloc_context())) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    avio_ctx_buffer = av_malloc(avio_ctx_buffer_size);
    if (!avio_ctx_buffer) {
        ret = AVERROR(ENOMEM);
        goto end;
    }
    avio_ctx = avio_alloc_context(avio_ctx_buffer, avio_ctx_buffer_size,
                                  0, &bd, &read_packet, NULL, NULL);
    if (!avio_ctx) {
        ret = AVERROR(ENOMEM);
        goto end;
    }
    fmt_ctx->pb = avio_ctx;

    ret = avformat_open_input(&fmt_ctx, NULL, NULL, NULL);
    if (ret < 0) {
        fprintf(stderr, "Could not open input\n");
        goto end;
    }

    ret = avformat_find_stream_info(fmt_ctx, NULL);
    if (ret < 0) {
        fprintf(stderr, "Could not find stream information\n");
        goto end;
    }

// lookup video codec handling
    ret = av_find_best_stream (fmt_ctx, AVMEDIA_TYPE_VIDEO, -1, -1, NULL, 0);
    if (ret < 0)
    {
        fprintf(stderr, "Could not find %s stream in input\n", av_get_media_type_string(AVMEDIA_TYPE_VIDEO));
        goto end;
    }
    int video_stream_idx = ret;
    AVStream *video_stream = fmt_ctx->streams[video_stream_idx];

    #if 0
    /* find decoder for the stream */
    AVCodec *dec = avcodec_find_decoder(video_stream->codecpar->codec_id);
    if (!dec) {
        fprintf (stderr, "Failed to find %s codec\n", av_get_media_type_string(AVMEDIA_TYPE_VIDEO));
        goto end;
    }
    /* Allocate a codec context for the decoder */
    AVCodecContext *dec_ctx = avcodec_alloc_context3(dec);
    if (!dec_ctx) {
        fprintf (stderr, "Failed to allocate the %s codec context\n", av_get_media_type_string(AVMEDIA_TYPE_VIDEO));
        goto end;
    }
    /* Copy codec parameters from input stream to output codec context */
    if ((ret = avcodec_parameters_to_context (dec_ctx, video_stream->codecpar)) < 0) {
        fprintf(stderr, "Failed to copy %s codec parameters to decoder context\n", av_get_media_type_string(AVMEDIA_TYPE_VIDEO));
        goto end;
    }
    // dict opts needed?
    if ((ret = avcodec_open2 (dec_ctx, dec, NULL)) < 0)
    {
        fprintf(stderr, "Failed to open %s codec\n", av_get_media_type_string(AVMEDIA_TYPE_VIDEO));
        goto end;
    }
#endif
    av_dump_format(fmt_ctx, 0, input_filename, 0);

    AVFrame *frame = av_frame_alloc();
    if (!frame) {
        fprintf(stderr, "Could not allocate frame\n");
        goto end;
    }

    printf ("checking for packets\n");
    AVPacket pkt;
    /* initialize packet, set data to NULL, let the demuxer fill it */
    av_init_packet(&pkt);
    pkt.data = NULL;
    pkt.size = 0;

   do
   {
       char msg [100];
       //flush video
       if (av_read_frame(fmt_ctx, &pkt) < 0)
           break;
       if (pkt.stream_index == video_stream_idx)
       {
           sprintf (msg, "Video%s", pkt.flags & AV_PKT_FLAG_KEY ? ", Key" : "");
       }
       else
           sprintf (msg, "Other, %d", pkt.stream_index);

       printf ("demux pkt size %d at %ld (%s)\n", pkt.size, pkt.pos, msg);
       av_packet_unref (&pkt);
   } while (1);

end:
    avformat_close_input (&fmt_ctx);
    /* note: the internal buffer could have changed, and be != avio_ctx_buffer */
    if (avio_ctx)
    {
        av_freep(&avio_ctx->buffer);
        av_freep(&avio_ctx);
    }
    // av_file_unmap(buffer, buffer_size);

    if (ret < 0) {
        fprintf(stderr, "Error occurred: %s\n", av_err2str(ret));
        return 1;
    }

    return 0;
}
