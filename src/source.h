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

#ifndef __SOURCE_H__
#define __SOURCE_H__

#include "cfgfile.h"
#include "yp.h"
#include "util.h"
#include "format.h"
#include "fserve.h"

#include <stdio.h>

typedef struct source_tag
{
    char *mount;
    unsigned int flags;
    int listener_send_trigger;
    char wakeup;

    rwlock_t lock;

    client_t *client;
    time_t client_stats_update;

    struct _format_plugin_tag *format;

    avl_tree *clients;

    /* name of a file, whose contents are sent at listener connection */
    char *intro_filename;
    icefile_handle intro_file;
    long intro_start;
    int preroll_log_id;

    char *dumpfilename; /* Name of a file to dump incoming stream to */
    FILE *dumpfile;

    fbinfo fallback;

    int skip_duration;
    int incoming_adj;
    long limit_rate;
    time_t wait_time;

    long termination_count;
    unsigned long peak_listeners;
    unsigned long listeners;
    unsigned long prev_listeners;
    long incoming_rate;
    struct rate_calc *in_bitrate;
    struct rate_calc *out_bitrate;

    int yp_public;

    /* per source burst handling for connecting clients */
    unsigned int default_burst_value;
    unsigned int queue_len_value;
    unsigned int min_queue_len_value;

    unsigned int default_burst_size;

    refbuf_t *min_queue_point;
    unsigned int min_queue_offset;
    unsigned int min_queue_size;
    unsigned int queue_size;
    unsigned int queue_size_limit;

    spin_t shrink_lock;
    uint64_t shrink_pos;
    uint64_t shrink_time;

    unsigned buffer_count;
    unsigned timeout;  /* source timeout in seconds */
    uint64_t bytes_sent_at_update;
    uint64_t bytes_read_since_update;

    int intro_skip_replay;
    int stats_interval;
    long stats;

    time_t last_read;

    refbuf_t *stream_data;
    refbuf_t *stream_data_tail;

    util_dict *audio_info;

    cache_file_contents *intro_ipcache;
} source_t;

#define SOURCE_RUNNING              1
#define SOURCE_ON_DEMAND            (1<<1)
#define SOURCE_SHOUTCAST_COMPAT     (1<<2)
#define SOURCE_PAUSE_LISTENERS      (1<<3)
#define SOURCE_TERMINATING          (1<<4)
#define SOURCE_LISTENERS_SYNC       (1<<5)
#define SOURCE_TIMEOUT              (1<<6)
#define SOURCE_RESERVED             (1<<7)

#define source_available(x)     (((x)->flags & (SOURCE_RUNNING|SOURCE_ON_DEMAND)) && ((x)->flags & SOURCE_LISTENERS_SYNC) == 0)
#define source_running(x)       (((x)->flags & (SOURCE_TERMINATING|SOURCE_RUNNING)) == SOURCE_RUNNING)

source_t *source_reserve (const char *mount, int ret_exist);
void *source_client_thread (void *arg);
int  source_startup (client_t *client, const char *uri);
void source_update_settings (ice_config_t *config, source_t *source, mount_proxy *mountinfo);
void source_clear_listeners (source_t *source);
void source_clear_source (source_t *source);
source_t *source_find_mount(const char *mount);
source_t *source_find_mount_raw(const char *mount);
client_t *source_find_client(source_t *source, uint64_t id);
int source_compare_sources(void *arg, void *a, void *b);
void source_free_source(source_t *source);
void source_main(source_t *source);
void source_recheck_mounts (int update_all);
int  source_add_listener (const char *mount, mount_proxy *mountinfo, client_t *client);
int  source_read (source_t *source);
void source_setup_listener (source_t *source, client_t *client);
void source_init (source_t *source);
void source_shutdown (source_t *source, int with_fallback);
void source_set_fallback (source_t *source, const char *dest_mount);
int source_set_intro (source_t *source, const char *file_pattern);
int  source_format_init (source_t *source);
void source_listeners_wakeup (source_t *source);

int check_duplicate_logins (const char *mount, avl_tree *tree, client_t *client, auth_t *auth);

#define SOURCE_BLOCK_SYNC           01
#define SOURCE_QUEUE_BLOCK          REFBUF_SHARED

#endif


