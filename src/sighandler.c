/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2022-2023,  Karl Heyes <karl@kheyes.plus.com>
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org>,
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <signal.h>

#include "thread/thread.h"
#include "global.h"

void _sig_die(int signo)
{
    /* inform the server to start shutting down */
    global.running = ICE_HALTING;
}

#ifdef HAVE_SIGACTION
#include <string.h>

void _sig_hup(int signo)
{
    global . schedule_config_reread = 1;
}

void sighandler_initialize(void)
{
    struct sigaction sa;
    memset (&sa, 0, sizeof sa);
    sigfillset(&sa.sa_mask);
    sa.sa_handler = _sig_die;
    sa.sa_flags = SA_RESTART;
    sigaction (SIGINT, &sa, NULL);
    sigaction (SIGTERM, &sa, NULL);
    sa.sa_handler = _sig_hup;
    sigaction (SIGHUP, &sa, NULL);
}
#else

void _sig_hup(int signo)
{
    global . schedule_config_reread = 1;
    /* some OSes require us to reattach the signal handler */
    signal(SIGHUP, _sig_hup);
}


void _sig_ignore(int signo)
{
    signal(signo, _sig_ignore);
}

void sighandler_initialize(void)
{
    signal(SIGHUP, _sig_hup);
    signal(SIGINT, _sig_die);
    signal(SIGTERM, _sig_die);
    signal(SIGPIPE, SIG_IGN);
#ifdef SIGCHLD
    signal(SIGCHLD, _sig_ignore);
#endif
}

#endif
