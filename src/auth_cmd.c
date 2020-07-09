/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2012-2020, Karl Heyes <karl@kheyes.plus.com>
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org, 
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

/** 
 * Client authentication via command functions
 *
 * The stated program is started and via it's stdin it is passed
 * mountpoint\n
 * username\n
 * password\n
 * a return code of 0 indicates a valid user, authentication failure if
 * otherwise
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#ifndef WIN32
#include <sys/wait.h>
#endif
#ifdef HAVE_POLL
#include <poll.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#include "auth.h"
#include "util.h"
#include "source.h"
#include "client.h"
#include "cfgfile.h"
#include "httpp/httpp.h"
#include "global.h"

#include "logging.h"
#define CATMODULE "auth_cmd"

typedef struct {
    char *listener_add;
    char *listener_remove;
} auth_cmd;


typedef struct
{
    char *location;
    char errormsg [100];
} auth_thread_data;


static void cmd_clear(auth_t *self)
{
    auth_cmd *cmd = self->state;
    free (cmd->listener_add);
    free (cmd->listener_remove);
    free(cmd);
}

static void process_header (const char *p, auth_client *auth_user)
{
    client_t *client = auth_user->client;
    auth_thread_data *atd = auth_user->thread_data;

    if (strncasecmp (p, "Mountpoint: ",12) == 0)
    {
        char *new_mount = strdup (p+12);
        if (new_mount)
        {
            free (auth_user->mount);
            auth_user->mount = new_mount;
        }
        return;
    }
    if (strncasecmp (p, "icecast-slave:", 14) == 0)
        client->flags |= CLIENT_IS_SLAVE;
    if (strncasecmp (p, "Location: ", 10) == 0)
    {
        int len = strcspn ((char*)p+10, "\r\n");
        free (atd->location);
        atd->location = malloc (len+1);
        snprintf (atd->location, len+1, "%s", (char *)p+10);
    }
    if (strncasecmp (p, "ice-username: ", 14) == 0)
    {
        int len = strcspn ((char*)p+14, "\r\n");
        char *name = malloc (len+1);
        if (name)
        {
            snprintf (name, len+1, "%s", (char *)p+14);
            free (client->username);
            client->username = name;
        }
    }

    if (strncasecmp (p, "icecast-auth-user: ", 19) == 0)
    {
        if (strcmp (p+19, "withintro") == 0)
            client->flags |= CLIENT_AUTHENTICATED|CLIENT_HAS_INTRO_CONTENT;
        else if (strcmp (p+19, "1") == 0)
            client->flags |= CLIENT_AUTHENTICATED;
        return;
    }
    if (strncasecmp (p, "icecast-auth-timelimit: ", 24) == 0)
    {
        unsigned limit;
        sscanf (p+24, "%u", &limit);
        client->connection.discon.time = time(NULL) + limit;
    }
    if (strncasecmp (p, "icecast-auth-message: ", 22) == 0)
    {
        char *eol;
        snprintf (atd->errormsg, sizeof (atd->errormsg), "%s", (char*)p+22);
        eol = strchr (atd->errormsg, '\r');
        if (eol == NULL)
            eol = strchr (atd->errormsg, '\n');
        if (eol)
            *eol = '\0';
    }
}

static void process_body (int fd, pid_t pid, auth_client *auth_user)
{
    client_t *client = auth_user->client;

    if (client->flags & CLIENT_HAS_INTRO_CONTENT)
    {
        refbuf_t *head = client->refbuf, *r = head->next;
        client_t *client = auth_user->client;
        head->next = NULL;
        DEBUG0 ("Have intro content from command");

        while (1)
        {
            int ret;
            unsigned remaining = 4096 - r->len;
            char *buf = r->data + r->len;

#if HAVE_POLL
            struct pollfd response;
            response.fd = fd;
            response.events = POLLIN;
            response.revents = 0;
            ret = poll (&response, 1, 1000);
            if (ret == 0)
            {
                kill (pid, SIGTERM);
                WARN1 ("command timeout triggered for %s", auth_user->mount);
                return;
            }
            if (ret < 0)
                continue;
#endif
            ret = read (fd, buf, remaining);
            if (ret > 0)
            {
                r->len += ret;
                if (r->len == 4096)
                {
                    head->next = r;
                    head = r;
                    r = refbuf_new (4096);
                    r->len = 0;
                }
                continue;
            }
            break;
        }
        if (r->len)
            head->next = r;
        else
            refbuf_release (r);
        if (client->refbuf->next == NULL)
            client->flags &= ~CLIENT_HAS_INTRO_CONTENT;
    }
}

static void get_response (int fd, auth_client *auth_user, pid_t pid)
{
    client_t *client = auth_user->client;
    refbuf_t *r = client->refbuf;
    char *buf = r->data, *blankline;
    unsigned remaining = 4095; /* leave a nul char at least */
    int ret = 0;

    memset (r->data, 0, remaining+1);
    sock_set_blocking (fd, 0);
    while (remaining)
    {
#if HAVE_POLL
        struct pollfd response;
        response.fd = fd;
        response.events = POLLIN;
        response.revents = 0;
        ret = poll (&response, 1, 1000);
        if (ret == 0)
        {
            kill (pid, SIGTERM);
            WARN1 ("command timeout triggered for %s", auth_user->mount);
            return;
        }
        if (ret < 0)
            continue;
        ret = read (fd, buf, remaining);
#else
        if (ret < 0)
            thread_sleep (20000);
        ret = read (fd, buf, remaining);
#endif
        if (ret < 0)
        {
            if (sock_recoverable (sock_error()))
                continue;
            remaining = 0;
        }
        else
        {
            remaining -= ret;
            buf += ret;
        }
        if (buf == r->data)   // if no data at all
            break;
        blankline = strstr (r->data, "\n\n");
        if (blankline)
        {
            char *p = r->data;
            do {
                char *nl = strchr (p, '\n');
                *nl = '\0';
                process_header (p, auth_user);
                p = nl+1;
            } while (*p != '\n');
            if (client->flags & CLIENT_HAS_INTRO_CONTENT)
            {
                r->len = buf - (blankline + 2);
                if (r->len)
                    memmove (r->data, blankline+2, r->len);
                client->refbuf = refbuf_new (4096);
                client->refbuf->next = r;
            }
            process_body (fd, pid, auth_user);
            return;
        }
    }
    return;
}


static auth_result auth_cmd_client (auth_client *auth_user)
{
    int infd[2], outfd[2];
    pid_t pid;
    client_t *client = auth_user->client;
    auth_t *auth = auth_user->auth;
    auth_cmd *cmd = auth->state;
    auth_thread_data *atd = auth_user->thread_data;
    int status, len;
    const char *qargs;
    char *referer, *agent, str[512];

    atd->errormsg[0] = 0;
    if ((auth->flags & AUTH_RUNNING) == 0)
        return AUTH_FAILED;
    if (pipe (infd) < 0 || pipe (outfd) < 0)
    {
        ERROR1 ("pipe failed code %d", errno);
        return AUTH_FAILED;
    }
    pid = fork();
    switch (pid)
    {
        case 0: /* child */
            dup2 (outfd[0], 0);
            if (outfd[0] != 0)
                close (outfd[0]);
            dup2 (infd[1], 1);
            if (infd[1] != 1)
                close (infd[1]);
            close (outfd[1]);
            close (infd[0]);
#ifdef _XOPEN_SOURCE
            if (auth->flags & AUTH_CLEAN_ENV)
                unsetenv ("LD_PRELOAD");
#endif
            execl (cmd->listener_add, cmd->listener_add, NULL);
            exit (-1);
        case -1:
            ERROR1 ("Failed to create child process for %s", cmd->listener_add);
            break;
        default: /* parent */
            close (outfd[0]);
            close (infd[1]);
            qargs = httpp_getvar (client->parser, HTTPP_VAR_QUERYARGS);
            agent = (char*)httpp_getvar (client->parser, "user-agent");
            if (agent)
                agent = util_url_escape (agent);
            referer = (char*)httpp_getvar (client->parser, "referer");
            if (referer)
                referer = util_url_escape (referer);
            len = snprintf (str, sizeof(str),
                    "Mountpoint: %s%s\n"
                    "User: %s\n"
                    "Pass: %s\n"
                    "IP: %s\n"
                    "Agent: %s\n"
                    "Referer: %s\n\n",
                    auth_user->mount, qargs ? qargs : "",
                    client->username ? client->username : "",
                    client->password ? client->password : "",
                    client->connection.ip,
                    agent ? agent : "",
                    referer ? referer : "");
            free (agent);
            free (referer);
            write (outfd[1], str, len);
            close (outfd[1]);
            get_response (infd[0], auth_user, pid);
            close (infd[0]);
            status = -1;
            do
            {
                int wstatus = 0;
                DEBUG1 ("Waiting on pid %ld", (long)pid);
                if (waitpid (pid, &wstatus, 0) < 0)
                {
                    ERROR1("waitpid error %s", strerror(errno));
                    break;
                }
                if (WIFEXITED(wstatus))
                {
                    status = WEXITSTATUS(wstatus);  // should be 8 LSB
                    break;
                }
                else if (WIFSIGNALED(wstatus))
                    break;
            } while (1);

            if (status == -1)
            {
                ERROR1 ("unable to exec command \"%s\"", cmd->listener_add);
                return AUTH_FAILED;
            }

            if (client->flags & CLIENT_AUTHENTICATED)
                return AUTH_OK;
            break;
    }
    if (atd->errormsg[0])
    {
        INFO3 ("listener %s (%s) returned \"%s\"", client->connection.ip, cmd->listener_add, atd->errormsg);
        if (atoi (atd->errormsg) == 403)
        {
            auth_user->client = NULL;
            client_send_403 (client, atd->errormsg+4);
            return AUTH_FAILED;
        }
    }
    if (atd->location)
    {
        client_send_302 (client, atd->location);
        auth_user->client = NULL;
        free (atd->location);
        atd->location = NULL;
    }
    return AUTH_FAILED;
}

static auth_result auth_cmd_adduser(auth_t *auth, const char *username, const char *password)
{
    return AUTH_FAILED;
}

static auth_result auth_cmd_deleteuser (auth_t *auth, const char *username)
{
    return AUTH_FAILED;
}

static auth_result auth_cmd_listuser (auth_t *auth, xmlNodePtr srcnode)
{
    return AUTH_FAILED;
}


static void *alloc_thread_data (auth_t *auth)
{
    auth_thread_data *atd = calloc (1, sizeof (auth_thread_data));
    INFO0 ("...handler data initialized");
    return atd;
}


static void release_thread_data (auth_t *auth, void *thread_data)
{
    auth_thread_data *atd = thread_data;
    free (atd);
    DEBUG1 ("...handler destroyed for %s", auth->mount);
}


int auth_get_cmd_auth (auth_t *authenticator, config_options_t *options)
{
    auth_cmd *state;

    authenticator->authenticate = auth_cmd_client;
    authenticator->release = cmd_clear;
    authenticator->adduser = auth_cmd_adduser;
    authenticator->deleteuser = auth_cmd_deleteuser;
    authenticator->listuser = auth_cmd_listuser;
    authenticator->alloc_thread_data = alloc_thread_data;
    authenticator->release_thread_data = release_thread_data;

    state = calloc(1, sizeof(auth_cmd));

    while(options) {
        if (strcmp (options->name, "listener_add") == 0)
            state->listener_add = strdup (options->value);
        if (strcmp (options->name, "listener_remove") == 0)
            state->listener_remove = strdup (options->value);
        options = options->next;
    }
    if (state->listener_add == NULL)
    {
        ERROR0 ("No command specified for authentication");
        free (state);
        return -1;
    }
    authenticator->state = state;
    INFO0("external command based authentication setup");
    return 0;
}

