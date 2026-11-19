/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2026, Karl Heyes <heyes.karl@gmail.com>
 */

/* wrapper for the strerror_r routine. As the GNU XPG and windows have slight variantions
 * in the routine, just hide it behind our routine in here to mimic the XPG one, as the
 * that seems consistent.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#undef _GNU_SOURCE
#include "compat.h"
#include <string.h>

#ifndef HAVE_STRERROR_R
#ifdef HAVE_STRERROR_S      // windows
int ic_strerror_r (int errnum, char *buf, size_t size)
{
    return strerror_s (buf, size, errnum);
}
#else
#include <stdio.h>
int ic_strerror_r (int errnum, char *buf, size_t size)
{
    char *msg;
    if (size > 2 && (msg = strerror (errnum)) != NULL)
        snprintf (buf,size, "%s", msg);
    return 0;
}
#endif
#else // STRERROR_R
int ic_strerror_r (int errnum, char *buf, size_t size)
{
    return strerror_r (errnum, buf, size);
}
#endif
