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


#ifndef __FORMAT_THEORA_H
#define __FORMAT_THEORA_H

#include "format_ogg.h"

ogg_codec_t *initial_theora_page (format_plugin_t *plugin, ogg_page *page);

#endif /* __FORMAT_THEORA_H */
