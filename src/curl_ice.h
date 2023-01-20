/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2022-2023, Karl Heyes <karl@kheyes.plus.com>
 */

/* general routines for icecast for all curl handles */

#ifndef __CURL_ICE_H__
#define __CURL_ICE_H__

#ifdef HAVE_CURL
#include <curl/curl.h>

CURL    *icecurl_easy_init ();       // basically curl_easy_init with some default settings
#endif
#endif


