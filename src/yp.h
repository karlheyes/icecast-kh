/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2010-2022, Karl Heyes <karl@kheyes.plus.com>
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org>,
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

/* -*- c-basic-offset: 4; indent-tabs-mode: nil; -*- */
#ifndef __YP_H__
#define __YP_H__

#ifdef USE_YP
#include "stats.h"
void yp_add (const char *mount);
void yp_remove (const char *mount);
void yp_touch (const char *mount, stats_handle_t stats);
void yp_recheck_config (ice_config_t *config);
void yp_initialize (ice_config_t *config);
void yp_shutdown(void);
void yp_thread_startup (void);
void yp_stop (void);

#else

#define yp_add(x)               do{}while(0)
#define yp_remove(x)            do{}while(0)
#define yp_touch(x,y)           do{}while(0)
#define yp_recheck_config(x)    do{}while(0)
#define yp_initialize(x)        WARN0("YP server handling has been disabled")
#define yp_shutdown()           do{}while(0)
#define yp_thread_startup()     do{}while(0)
#define yp_stop()               do{}while(0)

#endif /* USE_YP */

#endif


