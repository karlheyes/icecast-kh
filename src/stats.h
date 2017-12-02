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

#ifndef __STATS_H__
#define __STATS_H__

#include "cfgfile.h"
#include "connection.h"
#include "httpp/httpp.h"
#include "client.h"
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#define STATS_HIDDEN   1
#define STATS_SLAVE    2
#define STATS_GENERAL  4
#define STATS_COUNTERS 8
#define STATS_PUBLIC   (STATS_GENERAL|STATS_COUNTERS)
#define STATS_REGULAR   01000
#define STATS_ALL      ~0

typedef uintptr_t stats_handle_t;

void stats_initialize(void);
void stats_shutdown(void);

void stats_global(ice_config_t *config);
void stats_get_streamlist (char *buffer, size_t remaining);
refbuf_t *stats_get_streams (int prepend);
void stats_purge (time_t mark);
void stats_clients_wakeup (void);

void stats_event(const char *source, const char *name, const char *value);
void stats_event_conv(const char *mount, const char *name,
        const char *value, const char *charset);
void stats_event_args(const char *source, char *name, char *format, ...);
void stats_event_inc(const char *source, const char *name);
void stats_event_add(const char *source, const char *name, unsigned long value);
void stats_event_sub(const char *source, const char *name, unsigned long value);
void stats_event_dec(const char *source, const char *name);
void stats_event_flags (const char *source, const char *name, const char *value, int flags);
void stats_event_time (const char *mount, const char *name, int flags);

void *stats_connection(void *arg);
void stats_add_listener (client_t *client, int hidden_level);
void stats_global_calc (time_t now);

int  stats_transform_xslt(client_t *client, const char *uri);
void stats_sendxml(client_t *client);
xmlDocPtr stats_get_xml(int flags, const char *show_mount);
char *stats_get_value(const char *source, const char *name);

stats_handle_t stats_handle (const char *mount);
stats_handle_t stats_lock (stats_handle_t handle, const char *mount);
void stats_release (stats_handle_t handle);
void stats_flush (stats_handle_t handle);
void stats_set (stats_handle_t handle, const char *name, const char *value);
void stats_set_expire (stats_handle_t stats, time_t mark);
void stats_set_inc (stats_handle_t handle, const char *name);
void stats_set_args (stats_handle_t handle, const char *name, const char *format, ...);
void stats_set_flags (stats_handle_t handle, const char *name, const char *value, int flags);
void stats_set_conv (stats_handle_t handle, const char *name, const char *value, const char *charset);
void stats_set_time (stats_handle_t handle, const char *name, int flags, time_t tm);
char *stats_retrieve (stats_handle_t handle, const char *name);

void stats_listener_to_xml (client_t *listener, xmlNodePtr parent);

#endif  /* __STATS_H__ */

