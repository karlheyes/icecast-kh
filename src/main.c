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

/* -*- c-basic-offset: 4; indent-tabs-mode: nil; -*- */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#include <process.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_CURL
#include <curl/curl.h>
#endif
#include <git_hash.h>

#include "thread/thread.h"
#include "avl/avl.h"
#include "net/sock.h"
#include "net/resolver.h"
#include "httpp/httpp.h"

#ifdef CHUID
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#endif
#ifdef HAVE_GETRLIMIT
#include <sys/resource.h>
#endif

#include "cfgfile.h"
#include "sighandler.h"

#include "global.h"
#include "compat.h"
#include "connection.h"
#include "refbuf.h"
#include "client.h"
#include "slave.h"
#include "stats.h"
#include "logging.h"
#include "xslt.h"
#include "fserve.h"
#include "auth.h"

#include <libxml/xmlmemory.h>

#undef CATMODULE
#define CATMODULE "main"

static void _ch_root_uid_setup(void);

static int background;
static char *pidfile = NULL;

#define _fatal_error fatal_error
void fatal_error (const char *perr)
{
#if defined(WIN32)
    MessageBox(NULL, perr, NULL, MB_SERVICE_NOTIFICATION);
#else
    ERROR1("%s", perr);
#endif
}

static void _print_usage(void)
{
    printf("%s\n\n", ICECAST_VERSION_STRING);
    printf("usage: icecast [-b -v] -c <file>\n");
    printf("options:\n");
    printf("\t-c <file>\tSpecify configuration file\n");
    printf("\t-v\t\tDisplay version info\n");
    printf("\t-b\t\tRun icecast in the background\n");
    printf("\n");
}


void initialize_subsystems(void)
{
    global_initialize();
    thread_initialize();
    log_initialize_lib (thread_mtx_create_callback, thread_mtx_lock_callback);
    errorlog = log_open_file (stderr);
    sock_initialize();
    resolver_initialize();
    config_initialize();
    connection_initialize();
    refbuf_initialize();

    stats_initialize();
    xslt_initialize();
#ifdef HAVE_CURL_GLOBAL_INIT
    curl_global_init (CURL_GLOBAL_ALL);
#endif
}


void shutdown_subsystems(void)
{
    connection_shutdown();
    slave_shutdown();
    xslt_shutdown();

    config_shutdown();
    refbuf_shutdown();
    resolver_shutdown();
    sock_shutdown();

#ifdef HAVE_CURL
    curl_global_cleanup();
#endif

    /* Now that these are done, we can stop the loggers. */
    log_shutdown();
    global_shutdown();
    thread_shutdown();
}

static int _parse_config_opts(int argc, char **argv, char *filename, int size)
{
    int i = 1;
    int config_ok = 0;

    background = 0;
    if (argc < 2) return -1;

    while (i < argc) {
        if (strcmp(argv[i], "-b") == 0) {
#ifndef WIN32
            pid_t pid;
            fprintf(stdout, "Starting icecast2\nDetaching from the console\n");

            pid = fork();

            if (pid > 0) {
                /* exit the parent */
                exit(0);
            }
            else if(pid < 0) {
                fprintf(stderr, "FATAL: Unable to fork child!");
                exit(1);
            }
            background = 1;
#endif
        }
        if (strcmp(argv[i], "-v") == 0) {
            fprintf(stdout, "%s\n", ICECAST_VERSION_STRING "-" GIT_VERSION);
            exit(0);
        }

        if (strcmp(argv[i], "-c") == 0) {
            if (i + 1 < argc) {
                strncpy(filename, argv[i + 1], size-1);
                filename[size-1] = 0;
                config_ok = 1;
            } else {
                return -1;
            }
        }
        i++;
    }

    if(config_ok)
        return 1;
    else
        return -1;
}


/* bind the socket and start listening */
static int server_proc_init(void)
{
    ice_config_t *config = config_get_config_unlocked();

    if (init_logging (config) < 0)
        return 0;

    INFO2 ("%s server reading configuration from %s", ICECAST_VERSION_STRING, config->config_filename);

    if (connection_setup_sockets (config) == 0)
        return 0;

    _ch_root_uid_setup(); /* Change user id and root if requested/possible */

    /* recreate the pid file */
    if (config->pidfile)
    {
        FILE *f;
        pidfile = strdup (config->pidfile);
        if (pidfile && (f = fopen (config->pidfile, "w")) != NULL)
        {
            fprintf (f, "%d\n", (int)getpid());
            fclose (f);
        }
    }

    return 1;
}


/* this is the heart of the beast */
void server_process (void)
{
    INFO1 ("%s server started", ICECAST_VERSION_STRING);

    global.running = ICE_RUNNING;

    /* Do this after logging init */
    auth_initialise ();

    if (background)
    {
        fclose (stdin);
        fclose (stdout);
        fclose (stderr);
    }
    slave_initialize();
    INFO0("Shutting down");
    auth_shutdown();
}


/* unix traditionally defaults to 1024 open FDs max, which is often a restriction for icecast
 * so here (as root) we check the current limit against clients allowed and up it while we can
 */
static void check_open_file_limit (ice_config_t *config)
{
#ifdef HAVE_GETRLIMIT
    struct rlimit rlimit;
    if (getrlimit (RLIMIT_NOFILE, &rlimit) == 0)
    {
        if (rlimit.rlim_max < config->client_limit)
        {
            rlim_t old = rlimit.rlim_max;
            rlimit.rlim_cur = rlimit.rlim_max = config->client_limit;
            if (setrlimit (RLIMIT_NOFILE, &rlimit) < 0)
                fprintf (stderr, "failed to increase max number of open files from %lu to %lu\n",
                        (unsigned long)old, (unsigned long)config->client_limit);
        }
    }
#endif
}


/* chroot the process. Watch out - we need to do this before starting other
 * threads. Change uid as well, after figuring out uid _first_ */
static void _ch_root_uid_setup(void)
{
   ice_config_t *conf = config_get_config_unlocked();
#ifdef CHUID
   struct passwd *user;
   struct group *group;
   uid_t uid=-1;
   gid_t gid=-1;

   if(conf->chuid)
   {
       if(conf->user) {
           user = getpwnam(conf->user);
           if(user)
               uid = user->pw_uid;
           else
               fprintf(stderr, "Couldn't find user \"%s\" in password file\n", conf->user);
       }
       if(conf->group) {
           group = getgrnam(conf->group);

           if(group)
               gid = group->gr_gid;
           else
               fprintf(stderr, "Couldn't find group \"%s\" in groups file\n", conf->group);
       }
   }
#endif

   check_open_file_limit (conf);

#ifdef HAVE_CHROOT
   if (conf->chroot)
   {
       if(getuid()) /* root check */
       {
           fprintf(stderr, "WARNING: Cannot change server root unless running as root.\n");
       }
       if (chroot(conf->base_dir) < 0 || chdir ("/") < 0)
       {
           fprintf(stderr,"WARNING: Couldn't change server root: %s\n", strerror(errno));
           return;
       }
       else
           fprintf(stdout, "Changed root successfully to \"%s\".\n", conf->base_dir);

   }   
#endif
#ifdef CHUID

   if(conf->chuid)
   {
       if(getuid()) /* root check */
       {
           fprintf(stderr, "WARNING: Can't change user id unless you are root.\n");
           return;
       }

       if (gid != (gid_t)-1)
       {
           if (initgroups (conf->user, gid) < 0)
               fprintf (stdout, "Error changing supplementary groups: %s.\n", strerror(errno));
           else
               fprintf (stdout, "Changed supplementary groups based on user: %s.\n", conf->user);
#ifdef HAVE_SETRESGID
           if (setresgid (gid, gid, gid) < 0)
#else
           if (setgid (gid) < 0)
#endif
               fprintf (stdout, "Error changing groupid: %s.\n", strerror(errno));
           else
               fprintf (stdout, "Changed groupid to %i.\n", (int)gid);
       }

       if (uid != (uid_t)-1)
       {
#ifdef HAVE_SETRESUID
           if (setresuid (uid, uid, uid) < 0)
#else
           if (setuid (gid) < 0)
#endif
               fprintf (stdout, "Error changing userid: %s.\n", strerror(errno));
           else
               fprintf (stdout, "Changed userid to %i.\n", (int)uid);
       }
   }
#endif
}


int server_init (int argc, char *argv[])
{
    int  ret;
    char filename[512];
    char pbuf[1024];

    switch (_parse_config_opts (argc, argv, filename, 512))
    {
        case -1:
            _print_usage();
            return -1;
        default:
            /* parse the config file */
            config_get_config();
            ret = config_initial_parse_file(filename);
            config_release_config();
            if (ret < 0)
            {
                snprintf (pbuf, sizeof(pbuf), 
                        "FATAL: error parsing config file (%s)", filename);
                _fatal_error (pbuf);
                switch (ret)
                {
                    case CONFIG_EINSANE:
                        _fatal_error("filename was null or blank");
                        break;
                    case CONFIG_ENOROOT:
                        _fatal_error("no root element found");
                        break;
                    case CONFIG_EBADROOT:
                        _fatal_error("root element is not <icecast>");
                        break;
                    default:
                        _fatal_error("XML config parsing error");
                        break;
                }
                return -1;
            }
    }

    /* override config file options with commandline options */
    config_parse_cmdline(argc, argv);

    /* Bind socket, before we change userid */
    if (server_proc_init() == 0)
    {
        _fatal_error("Server startup failed. Exiting");
        return -1;
    }
    fserve_initialize();

#ifdef CHUID 
    /* We'll only have getuid() if we also have setuid(), it's reasonable to
     * assume */
    if (getuid() == 0) /* Running as root! Don't allow this */
    {
        fprintf (stderr, "ERROR: You should not run icecast2 as root\n");
        fprintf (stderr, "Use the changeowner directive in the config file\n");
        return -1;
    }
#endif
    /* setup default signal handlers */
    sighandler_initialize();

    if (start_logging (config_get_config_unlocked()) < 0)
    {
        _fatal_error("FATAL: Could not start logging");
        return -1;
    }
    return 0;
}


#ifndef _WIN32
int main (int argc, char *argv[])
{
    initialize_subsystems();

    if (server_init (argc, argv) == 0)
        server_process();

    shutdown_subsystems();

    if (pidfile)
    {
        remove (pidfile);
        free (pidfile);
    }
    return 0;
}
#endif

