/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2012, Jack Moffitt <jack@xiph.org, 
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

/* format_ebml.c
 *
 * format plugin for EBML
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "refbuf.h"
#include "source.h"
#include "client.h"

#include "stats.h"
#include "format.h"
#include "format_ebml.h"

#include "logging.h"

#define CATMODULE "format-ebml"

#define EBML_DEBUG 0
#define EBML_HEADER_MAX_SIZE 131072
#define EBML_SLICE_SIZE 4096

#define EBML_CLUSTER_BYTE1 0x1F
#define EBML_CLUSTER_BYTE2 0x43
#define EBML_CLUSTER_BYTE3 0xB6
#define EBML_CLUSTER_BYTE4 0x75

typedef struct ebml_client_data_st ebml_client_data_t;

struct ebml_client_data_st {

    refbuf_t *header;
    int header_pos;

};

struct ebml_st {

    char cluster_mark[4];

    uint64_t position;
    uint64_t read_position;
    int buffer_position;
    uint64_t cluster_position;

    int header_read;

    int header_size;
    int header_position;
    int header_read_position;

    unsigned char *input_buffer;
    unsigned char *buffer;
    unsigned char *header;

    uint64_t found;
    uint64_t matched_byte_num;
    unsigned char match_byte;

    int last_was_cluster_end;
    int this_was_cluster_start;

};

static void ebml_free_plugin (format_plugin_t *plugin, client_t *client);
static refbuf_t *ebml_get_buffer (source_t *source);
static int  ebml_write_buf_to_client (client_t *client);
static void  ebml_write_buf_to_file (source_t *source, refbuf_t *refbuf);
static int ebml_create_client_data (format_plugin_t *format, client_t *client);
static void ebml_free_client_data (client_t *client);

static ebml_t *ebml_create();
static void ebml_destroy(ebml_t *ebml);
static size_t ebml_read_space(ebml_t *ebml);
static int ebml_read(ebml_t *ebml, char *buffer, int len);
static int ebml_last_was_sync(ebml_t *ebml);
static char *ebml_write_buffer(ebml_t *ebml, int len);
static int ebml_wrote(ebml_t *ebml, int len);
static void ebml_debug(ebml_t *ebml);
static unsigned char ebml_get_next_match_byte(unsigned char match_byte, uint64_t position,
                                              uint64_t *matched_byte_num, uint64_t *found);

int format_ebml_get_plugin (format_plugin_t *plugin, client_t *client)
{

    ebml_source_state_t *ebml_source_state = calloc(1, sizeof(ebml_source_state_t));

    plugin->get_buffer = ebml_get_buffer;
    plugin->write_buf_to_client = ebml_write_buf_to_client;
    plugin->create_client_data = ebml_create_client_data;
    plugin->free_plugin = ebml_free_plugin;
    plugin->write_buf_to_file = ebml_write_buf_to_file;
    plugin->set_tag = NULL;
    plugin->apply_settings = NULL;

    plugin->contenttype = strdup (httpp_getvar (plugin->parser, "content-type"));

    plugin->_state = ebml_source_state;

    ebml_source_state->ebml = ebml_create();
    return 0;
}

static void ebml_free_plugin (format_plugin_t *plugin, client_t *client)
{

    ebml_source_state_t *ebml_source_state = plugin->_state;

    refbuf_release (ebml_source_state->header);
    ebml_destroy(ebml_source_state->ebml);
    free (ebml_source_state);
    free (plugin);

}

static int send_ebml_header (client_t *client)
{

    ebml_client_data_t *ebml_client_data = client->format_data;
    int len = EBML_SLICE_SIZE;
    int ret;

    if (ebml_client_data->header->len - ebml_client_data->header_pos < len) 
    {
        len = ebml_client_data->header->len - ebml_client_data->header_pos;
    }
    ret = client_send_bytes (client, 
                             ebml_client_data->header->data + ebml_client_data->header_pos,
                             len);

    if (ret > 0)
    {
        ebml_client_data->header_pos += ret;
    }

    return ret;

}

static int ebml_write_buf_to_client (client_t *client)
{

    ebml_client_data_t *ebml_client_data = client->format_data;

    if (ebml_client_data->header_pos != ebml_client_data->header->len)
    {
        return send_ebml_header (client);
    }
    else
    {
        return format_generic_write_to_client(client);
    }

}

static refbuf_t *ebml_get_buffer (source_t *source)
{

    ebml_source_state_t *ebml_source_state = source->format->_state;
    format_plugin_t *format = source->format;
    char *data = NULL;
    int bytes = 0;
    refbuf_t *refbuf;
    int ret;

    while (1)
    {
    
        if (EBML_DEBUG) {
            ebml_debug(ebml_source_state->ebml);
        }

        if ((bytes = ebml_read_space(ebml_source_state->ebml)) > 0)
        {
            refbuf = refbuf_new(bytes);
            ebml_read(ebml_source_state->ebml, refbuf->data, bytes);

            if (ebml_source_state->header == NULL)
            {
                ebml_source_state->header = refbuf;
                continue;
            }

            if (ebml_last_was_sync(ebml_source_state->ebml))
            {
                refbuf->flags |= SOURCE_BLOCK_SYNC;
            }
            return refbuf;

        }
        else
        {

            data = ebml_write_buffer(ebml_source_state->ebml, EBML_SLICE_SIZE);
            bytes = client_read_bytes (source->client, data, EBML_SLICE_SIZE);
            if (bytes <= 0)
            {
                ebml_wrote (ebml_source_state->ebml, 0);
                return NULL;
            }
            format->read_bytes += bytes;
            ret = ebml_wrote (ebml_source_state->ebml, bytes);
            if (ret != bytes) {
                ERROR0 ("Problem processing stream");
                source->flags &= ~SOURCE_RUNNING;
                return NULL;
            }
        }
    }
}

static int ebml_create_client_data (format_plugin_t *format, client_t *client)
{

    ebml_client_data_t *ebml_client_data = calloc(1, sizeof(ebml_client_data_t));
    ebml_source_state_t *ebml_source_state = format->_state;

    int ret = -1;

    if ((ebml_client_data) && (ebml_source_state->header))
    {
        ebml_client_data->header = ebml_source_state->header;
        refbuf_addref (ebml_client_data->header);
        client->format_data = ebml_client_data;
        client->free_client_data = ebml_free_client_data;
        ret = 0;
    }

    return ret;

}


static void ebml_free_client_data (client_t *client)
{

    ebml_client_data_t *ebml_client_data = client->format_data;

    refbuf_release (ebml_client_data->header);
    free (client->format_data);
    client->format_data = NULL;
}


static void ebml_write_buf_to_file_fail (source_t *source)
{
    WARN0 ("Write to dump file failed, disabling");
    fclose (source->dumpfile);
    source->dumpfile = NULL;
}


static void ebml_write_buf_to_file (source_t *source, refbuf_t *refbuf)
{

    ebml_source_state_t *ebml_source_state = source->format->_state;

    if (ebml_source_state->file_headers_written == 0)
    {
        if (fwrite (ebml_source_state->header->data, 1,
                    ebml_source_state->header->len, 
                    source->dumpfile) != ebml_source_state->header->len)
            ebml_write_buf_to_file_fail(source);
        else
            ebml_source_state->file_headers_written = 1;
    }

    if (fwrite (refbuf->data, 1, refbuf->len, source->dumpfile) != refbuf->len)
    {
        ebml_write_buf_to_file_fail(source);
    }

}


/* internal ebml parsing */

static void ebml_debug(ebml_t *ebml) {
    printf("EBML Stream Write Position: %zu Read Position: %zu Buffer Position: %d "
           "Cluster Position: %zu Header Read: %d Header Size: %d Header Write "
           "Position: %d Header Read Position: %d\n",
           ebml->position,
           ebml->read_position,
           ebml->buffer_position,
           ebml->cluster_position,
           ebml->header_read,
           ebml->header_size,
           ebml->header_position,
           ebml->header_read_position);
}


static unsigned char ebml_get_next_match_byte(unsigned char match_byte, uint64_t position, 
                                              uint64_t *matched_byte_num, uint64_t *found) {

    if (found != NULL) {
        *found = 0;
    }

    if (matched_byte_num != NULL) {
        if (match_byte == EBML_CLUSTER_BYTE1) {
            if (matched_byte_num != NULL) {
                *matched_byte_num = position;
            }
            return EBML_CLUSTER_BYTE2;
        }

        if ((*matched_byte_num == position - 1) && (match_byte == EBML_CLUSTER_BYTE2)) {
            return EBML_CLUSTER_BYTE3;
        }

        if ((*matched_byte_num == position - 2) && (match_byte == EBML_CLUSTER_BYTE3)) {
            return EBML_CLUSTER_BYTE4;
        }

        if ((*matched_byte_num == position - 3) && (match_byte == EBML_CLUSTER_BYTE4)) {
            if (found != NULL) {
                *found = *matched_byte_num;
            }
            *matched_byte_num = 0;
            return EBML_CLUSTER_BYTE1;
        }

        *matched_byte_num = 0;
    }

    return EBML_CLUSTER_BYTE1;

}

static void ebml_destroy(ebml_t *ebml) {

    free(ebml->header);
    free(ebml->input_buffer);
    free(ebml->buffer);
    free(ebml);

}

static ebml_t *ebml_create() {

    ebml_t *ebml = calloc(1, sizeof(ebml_t));

    ebml->header = calloc(1, EBML_HEADER_MAX_SIZE);
    ebml->buffer = calloc(1, EBML_SLICE_SIZE);
    ebml->input_buffer = calloc(1, EBML_SLICE_SIZE);

    ebml->cluster_mark[0] = EBML_CLUSTER_BYTE1;
    ebml->cluster_mark[1] = EBML_CLUSTER_BYTE2;
    ebml->cluster_mark[2] = EBML_CLUSTER_BYTE3;
    ebml->cluster_mark[3] = EBML_CLUSTER_BYTE4;

    return ebml;

}

static size_t ebml_read_space(ebml_t *ebml) {

    size_t read_space;

    if (ebml->header_read == 1) {
        read_space = (ebml->position - ebml->header_size) - ebml->read_position;

        return read_space;
    } else {
        if (ebml->header_size != 0) {
            return ebml->header_size - ebml->header_read_position;
        } else {
            return 0;
        }
    }


}

static int ebml_read(ebml_t *ebml, char *buffer, int len) {

    size_t read_space;
    size_t read_space_to_cluster;
    int to_read;

    read_space_to_cluster = 0;

    if (len < 1) {
        return 0;
    }

    if (ebml->header_read == 1) {
        read_space = (ebml->position - ebml->header_size) - ebml->read_position;

        if (read_space < 1) {
            return 0;
        }

        if (read_space >= len ) {
            to_read = len;
        } else {
            to_read = read_space;
        }

        if (ebml->cluster_position != 0) {
            read_space_to_cluster = 
            (ebml->cluster_position - ebml->header_size) - ebml->read_position;
            if ((read_space_to_cluster != 0) && (read_space_to_cluster <= to_read)) {
                to_read = read_space_to_cluster;
                ebml->cluster_position = 0;
                ebml->last_was_cluster_end = 1;
            } else {
                if (read_space_to_cluster == 0) {
                    ebml->this_was_cluster_start = 1;
                }
            }
        }

        memcpy(buffer, ebml->buffer, to_read);
        ebml->read_position += to_read;
        memmove(ebml->buffer, ebml->buffer + to_read, ebml->buffer_position - to_read);
        ebml->buffer_position -= to_read;

    } else {
        if (ebml->header_size != 0) {

            read_space = ebml->header_size - ebml->header_read_position;

            if (read_space >= len ) {
                to_read = len;
            } else {
                to_read = read_space;
            }

            memcpy(buffer, ebml->header, to_read);
            ebml->header_read_position += to_read;

            if (ebml->header_read_position == ebml->header_size) {
                ebml->header_read = 1;
            }

        } else {
            return 0;
        }
    }


    return to_read;

}

static int ebml_last_was_sync(ebml_t *ebml) {

    if (ebml->last_was_cluster_end == 1) {
        ebml->last_was_cluster_end = 0;
        ebml->this_was_cluster_start = 1;
    }

    if (ebml->this_was_cluster_start == 1) {
        ebml->this_was_cluster_start = 0;
        return 1;
    }

    return 0;

}

static char *ebml_write_buffer(ebml_t *ebml, int len) {

    return (char *)ebml->input_buffer;

}


static int ebml_wrote(ebml_t *ebml, int len) {

    int b;

    for (b = 0; b < len; b++) {
        if ((ebml->input_buffer[b] == ebml->match_byte) || (ebml->matched_byte_num > 0)) {
            ebml->match_byte = ebml_get_next_match_byte(ebml->input_buffer[b],
                                                        ebml->position + b,
                                                        &ebml->matched_byte_num,
                                                        &ebml->found);
            if (ebml->found > 0) {
                if (ebml->header_size == 0) {
                    if (b > 0) {
                        if ((ebml->header_position + b) > EBML_HEADER_MAX_SIZE) {
                            ERROR0("EBML Header to large, failing");
                            return -1;
                        }
                        memcpy(ebml->header + ebml->header_position, ebml->input_buffer, b);
                        ebml->header_position += b;
                    }
                    ebml->header_size = (ebml->header_position - 4) + 1;
                    if (EBML_DEBUG) {
                        printf("EBML: Got header %d bytes\n", ebml->header_size);
                    }
                    /* first cluster */
                    memcpy(ebml->buffer, ebml->cluster_mark, 4);
                    ebml->buffer_position += 4;
                    if ((b + 1) < len) {
                        if ((ebml->buffer_position + (len - (b + 1))) > EBML_SLICE_SIZE) {
                            ERROR0("EBML Overflow, failing");
                            return -1;
                        }
                        memcpy(ebml->buffer + ebml->buffer_position, 
                               ebml->input_buffer + (b + 1),
                               len - (b + 1));
                        ebml->buffer_position += len - (b + 1);
                    }
                    if (EBML_DEBUG) {
                        printf("EBML: Found first cluster starting at offset: %zu\n",
                               ebml->found);
                    }
                    ebml->cluster_position = ebml->found;
                    ebml->position += len;
                    return len;

                }
                if (EBML_DEBUG) {
                    printf("EBML: Found cluster starting at offset: %zu\n", ebml->found);
                }
                ebml->cluster_position = ebml->found;
            }
        }
    }

    if (ebml->header_size == 0) {
        if ((ebml->header_position + len) > EBML_HEADER_MAX_SIZE) {
            ERROR0("EBML Header to large, failing");
            return -1;
        }
        if (EBML_DEBUG) {
            printf("EBML: Adding to header, ofset is %d size is %d adding %d\n", 
                   ebml->header_size, ebml->header_position, len);
        }
        memcpy(ebml->header + ebml->header_position, ebml->input_buffer, len);
        ebml->header_position += len;
    } else {
        if ((ebml->buffer_position + len) > EBML_SLICE_SIZE) {
            ERROR0("EBML Overflow, failing");
            return -1;
        }
        memcpy(ebml->buffer + ebml->buffer_position, ebml->input_buffer, len);
        ebml->buffer_position += len;
    }

    ebml->position += len;

    return len;
}
