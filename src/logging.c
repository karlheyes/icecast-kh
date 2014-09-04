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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "compat.h"
#include <stdio.h>
#include <string.h>

#include "thread/thread.h"
#include "httpp/httpp.h"

#include "connection.h"
#include "refbuf.h"
#include "client.h"

#include "cfgfile.h"
#include "logging.h"
#include "util.h"
#include "errno.h"

void fatal_error (const char *perr);

/* the global log descriptors */
int errorlog = 0;
int playlistlog = 0;

/* 
** ADDR IDENT USER DATE REQUEST CODE BYTES REFERER AGENT [TIME]
**
** ADDR = client->con->ip
** IDENT = always - , we don't support it because it's useless
** USER = client->username
** DATE = _make_date(client->con->con_time)
** REQUEST = build from client->parser
** CODE = client->respcode
** BYTES = client->con->sent_bytes
** REFERER = get from client->parser
** AGENT = get from client->parser
** TIME = timing_get_time() - client->con->con_time
*/
void logging_access_id (access_log *accesslog, client_t *client)
{
    const char *req = NULL;
    time_t now;
    time_t stayed;
    const char *referrer, *user_agent, *ip = "-";
    char *username = strdup("-");
    char datebuf[50];
    char reqbuf[256];

    if (client->flags & CLIENT_SKIP_ACCESSLOG)
        return;

    now = time(NULL);

    /* build the data */
    util_get_clf_time (datebuf, sizeof(datebuf), now);
    if (accesslog->qstr)
        req = httpp_getvar (client->parser, HTTPP_VAR_RAWURI);
    if (req == NULL)
        req = httpp_getvar (client->parser, HTTPP_VAR_URI);
    /* build the request */
    snprintf (reqbuf, sizeof(reqbuf), "%s %s %s/%s",
            httpp_getvar (client->parser, HTTPP_VAR_REQ_TYPE), req,
            httpp_getvar (client->parser, HTTPP_VAR_PROTOCOL),
            httpp_getvar (client->parser, HTTPP_VAR_VERSION));

    stayed = now - client->connection.con_time;

    // set username to '-' when client->username is empty
    if (client->username != NULL && strlen(client->username) > 0)
        username = strdup(client->username);

    referrer = httpp_getvar (client->parser, "referer");
    user_agent = httpp_getvar (client->parser, "user-agent");

    if (accesslog->log_ip)
        ip = client->connection.ip;

    if (accesslog->type == LOG_ACCESS_CLF_ESC)
    {
        char *un = util_url_escape (username),
             *rq = util_url_escape (reqbuf),
             *rf = referrer ? util_url_escape (referrer) : strdup ("-"),
             *ua = user_agent ? util_url_escape (user_agent) : strdup ("-");

        log_write_direct (accesslog->logid,
                "%s - %s %s %s %d %" PRIu64 " %.150s %.150s %lu",
                ip, username, datebuf, rq, client->respcode, client->connection.sent_bytes,
                rf, ua, (unsigned long)stayed);
        free (ua);
        free (rf);
        free (rq);
        free (un);
    }
    else
    {
        if (referrer == NULL)   referrer = "-";
        if (user_agent == NULL) user_agent = "-";

        log_write_direct (accesslog->logid,
                "%s - %s [%s] \"%s\" %d %" PRIu64 " \"%.150s\" \"%.150s\" %lu",
                ip, username, datebuf, reqbuf, client->respcode, client->connection.sent_bytes,
                referrer, user_agent, (unsigned long)stayed);
    }

    free(username);

    client->respcode = -1;
}


void logging_access (client_t *client)
{
    ice_config_t *config = config_get_config();
    logging_access_id (&config->access_log, client);
    config_release_config ();
}


/* This function will provide a log of metadata for each
   mountpoint.  The metadata *must* be in UTF-8, and thus
   you can assume that the log itself is UTF-8 encoded */
void logging_playlist(const char *mount, const char *metadata, long listeners)
{
    time_t now;
    char datebuf[128];

    if (playlistlog == -1) {
        return;
    }

    now = time(NULL);

    util_get_clf_time (datebuf, sizeof(datebuf), now);
    /* This format MAY CHANGE OVER TIME.  We are looking into finding a good
       standard format for this, if you have any ideas, please let us know */
    log_write_direct (playlistlog, "%s|%s|%ld|%s",
             datebuf,
             mount,
             listeners,
             metadata);
}


void log_parse_failure (void *ctx, const char *fmt, ...)
{
    char line [200];
    va_list ap;
    char *eol;

    va_start (ap, fmt);
    vsnprintf (line, sizeof (line), fmt, ap);
    eol = strrchr (line, '\n');
    if (eol) *eol='\0';
    va_end (ap);
    log_write (errorlog, 2, (char*)ctx, "", "%s", line);
}


static int recheck_log_file (ice_config_t *config, int *id, const char *file)
{
    char fn [FILENAME_MAX];

    if (file == NULL || strcmp (file, "-") == 0)
    {
        log_close (*id);
        *id = -1;
        return 0;
    }
    snprintf (fn, FILENAME_MAX, "%s%s%s", config->log_dir, PATH_SEPARATOR, file);
    if (*id < 0)
    {
        *id = log_open (fn);
        if (*id < 0)
        {
            char buf[1024];
            snprintf (buf,1024, "could not open log %s: %s", fn, strerror(errno));
            fatal_error (buf);
            return -1;
        }
        return 0;
    }
    log_set_filename (*id, fn);
    log_reopen (*id);
    return 0;
}


int restart_logging (ice_config_t *config)
{
    ice_config_t *current = config_get_config_unlocked();
    mount_proxy *m;
    int ret = 0;

    config->error_log.logid = current->error_log.logid;
    config->access_log.logid = current->access_log.logid;
    config->playlist_log.logid = current->playlist_log.logid;

    if (recheck_log_file (config, &config->error_log.logid, config->error_log.name) < 0)
        ret = -1;
    else
    {
        log_set_trigger (config->error_log.logid, config->error_log.size);
        log_set_reopen_after (config->error_log.logid, config->error_log.duration);
        log_set_lines_kept (config->error_log.logid, config->error_log.display);
        log_set_archive_timestamp (config->error_log.logid, config->error_log.archive);
        log_set_level (config->error_log.logid, config->error_log.level);
    }
    thread_use_log_id (config->error_log.logid);
    errorlog = config->error_log.logid; /* value stays static so avoid taking the config lock */

    if (recheck_log_file (config, &config->access_log.logid, config->access_log.name) < 0)
        ret = -1;
    else
    {
        log_set_trigger (config->access_log.logid, config->access_log.size);
        log_set_reopen_after (config->access_log.logid, config->access_log.duration);
        log_set_lines_kept (config->access_log.logid, config->access_log.display);
        log_set_archive_timestamp (config->access_log.logid, config->access_log.archive);
        log_set_level (config->access_log.logid, 4);
    }

    if (recheck_log_file (config, &config->playlist_log.logid, config->playlist_log.name) < 0)
        ret = -1;
    else
    {
        log_set_trigger (config->playlist_log.logid, config->playlist_log.size);
        log_set_reopen_after (config->playlist_log.logid, config->playlist_log.duration);
        log_set_lines_kept (config->playlist_log.logid, config->playlist_log.display);
        log_set_archive_timestamp (config->playlist_log.logid, config->playlist_log.archive);
        log_set_level (config->playlist_log.logid, 4);
    }
    playlistlog = config->playlist_log.logid;
    m = config->mounts;
    while (m)
    {
        if (recheck_log_file (config, &m->access_log.logid, m->access_log.name) < 0)
            ret = -1;
        else
        {
            log_set_trigger (m->access_log.logid, m->access_log.size);
            log_set_reopen_after (m->access_log.logid, m->access_log.duration);
            log_set_lines_kept (m->access_log.logid, m->access_log.display);
            log_set_archive_timestamp (m->access_log.logid, m->access_log.archive);
            log_set_level (m->access_log.logid, 4);
        }
        m = m->next;
    }
    return ret;
}


int start_logging (ice_config_t *config)
{
    if (strcmp (config->error_log.name, "-") == 0)
        errorlog = log_open_file (stderr);
    if (strcmp(config->access_log.name, "-") == 0)
        config->access_log.logid = log_open_file (stderr);
    return restart_logging (config);
}


void stop_logging(void)
{
    ice_config_t *config = config_get_config_unlocked();
    log_close (errorlog);
    log_close (config->access_log.logid);
    log_close (config->playlist_log.logid);
}

