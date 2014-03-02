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

#ifndef __FSERVE_H__
#define __FSERVE_H__

#include <stdio.h>
#include "cfgfile.h"

#define icefile_handle   int


#include "format.h"

typedef void (*fserve_callback_t)(client_t *, void *);

typedef struct _fbinfo
{
    int flags;
    unsigned int limit;
    char *mount;
    char *fallback;
    format_type_t type;
} fbinfo;

#define FS_USE_ADMIN            (1)
#define FS_DELETE               (1<<1)
#define FS_FALLBACK             (1<<2)
#define FS_FALLBACK_EOF         (1<<3)
#define FS_OVERRIDE             (1<<4)

void fserve_initialize(void);
void fserve_shutdown(void);
int fserve_client_create(client_t *httpclient, const char *path);
char *fserve_content_type (const char *path);
void fserve_recheck_mime_types (ice_config_t *config);

int  fserve_setup_client (client_t *client);
int  fserve_setup_client_fb (client_t *client, fbinfo *finfo);
int  fserve_set_override (const char *mount, const char *dest, format_type_t type);
int  fserve_list_clients (client_t *client, const char *mount, int response, int show_listeners);
int  fserve_list_clients_xml (xmlNodePtr srcnode, fbinfo *finfo);
int  fserve_kill_client (client_t *client, const char *mount, int response);
int  fserve_query_count (fbinfo *finfo);
void fserve_write_mime_ext (const char *mimetype, char *buf, unsigned int len);

int  file_in_use (icefile_handle f);
int  file_open (icefile_handle *f, const char *fn);
void file_close (icefile_handle *f);
#ifndef HAVE_PREAD
ssize_t pread (icefile_handle f, void *data, size_t count, off_t offset);
#endif
void fserve_scan (time_t now);
int  fserve_contains (const char *name);


extern int fserve_running;

#endif


