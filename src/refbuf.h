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

/* refbuf.h
**
** reference counting data buffer
**
*/
#ifndef __REFBUF_H__
#define __REFBUF_H__

#include <stdarg.h>
#include <sys/types.h>

typedef struct _refbuf_tag
{
    unsigned int flags;
    unsigned int _count;
    struct _refbuf_tag *next;
    void *associated;
    char *data;
    unsigned int len;

} refbuf_t;

void refbuf_initialize(void);
void refbuf_shutdown(void);

#ifdef MY_ALLOC
refbuf_t *refbuf_new_s(unsigned int size, const char *file, int line);
#define refbuf_new(X)   refbuf_new_s(X,__func__, __LINE__)
#else
refbuf_t *refbuf_new(unsigned int size);
#endif
void refbuf_addref(refbuf_t *self);
void refbuf_release(refbuf_t *self);
refbuf_t *refbuf_copy(refbuf_t *orig);
refbuf_t *refbuf_copy_default (refbuf_t *orig);

int refbuf_appendv (refbuf_t *refbuf, int max_len, const char *fmt, va_list ap);
int refbuf_append (refbuf_t *refbuf, int max_len, const char *fmt, ...);



#define PER_CLIENT_REFBUF_SIZE          4096

#define WRITE_BLOCK_GENERIC             (1<<8)
#define REFBUF_SHARED                   (1<<9)
#define BUFFER_LOCAL_USE                (1<<10)
#define BUFFER_CONTAINS_HDR             (1<<11)

#endif  /* __REFBUF_H__ */

