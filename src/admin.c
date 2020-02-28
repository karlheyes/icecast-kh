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

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "cfgfile.h"
#include "connection.h"
#include "refbuf.h"
#include "client.h"
#include "source.h"
#include "global.h"
#include "event.h"
#include "stats.h"
#include "compat.h"
#include "xslt.h"
#include "fserve.h"
#include "admin.h"
#include "slave.h"

#include "format.h"

#include "logging.h"
#include "auth.h"

#define CATMODULE "admin"


static int command_fallback(client_t *client, source_t *source, int response);
static int command_metadata(client_t *client, source_t *source, int response);
static int command_shoutcast_metadata(client_t *client, source_t *source);
static int command_show_listeners(client_t *client, source_t *source, int response);
static int command_move_clients(client_t *client, source_t *source, int response);
static int command_stats(client_t *client, const char *filename);
static int command_stats_mount (client_t *client, source_t *source, int response);
static int command_kill_client(client_t *client, source_t *source, int response);
static int command_reset_stats (client_t *client, source_t *source, int response);
static int command_manageauth(client_t *client, source_t *source, int response);
static int command_buildm3u(client_t *client, const char *mount);
static int command_show_image (client_t *client, const char* mount);
static int command_kill_source(client_t *client, source_t *source, int response);
static int command_updatemetadata(client_t *client, source_t *source, int response);
static int command_admin_function (client_t *client, int response);
static int command_list_log (client_t *client, int response);
static int command_manage_relay (client_t *client, int response);
#ifdef MY_ALLOC
static int command_alloc(client_t *client);
#endif

static int admin_handle_general_request(client_t *client, const char *command);


struct admin_command
{
    const char *request;
    admin_response_type response;
    union {
        void *x; /* not used but helps on initialisations */
        int (*source)(client_t *client, source_t *source, int response);
        int (*general)(client_t *client, int response);
    } handle;
};



static struct admin_command admin_general[] =
{
    { "managerelays",       RAW,    { command_manage_relay } },
    { "listmounts",         RAW,    { command_list_mounts } },
    { "function",           RAW,    { command_admin_function } },
#ifdef MY_ALLOC
    { "alloc",              RAW,    { command_alloc } },
#endif
    { "streamlist.txt",     TEXT,   { command_list_mounts } },
    { "streams",            TEXT,   { command_list_mounts } },
    { "showlog.txt",        TEXT,   { command_list_log } },
    { "showlog.xsl",        XSLT,   { command_list_log } },
    { "managerelays.xsl",   XSLT,   { command_manage_relay } },
    { "listmounts.xsl",     XSLT,   { command_list_mounts } },
    { "moveclients.xsl",    XSLT,   { command_list_mounts } },
    { "function.xsl",       XSLT,   { command_admin_function } },
    { "response.xsl",       XSLT },
    { NULL }
};



static struct admin_command admin_mount[] =
{
    { "fallback",           RAW,    { command_fallback } },
    { "metadata",           RAW,    { command_metadata } },
    { "listclients",        RAW,    { command_show_listeners } },
    { "updatemetadata",     RAW,    { command_updatemetadata } },
    { "killclient",         RAW,    { command_kill_client } },
    { "moveclients",        RAW,    { command_move_clients } },
    { "killsource",         RAW,    { command_kill_source } },
    { "stats",              RAW,    { command_stats_mount } },
    { "manageauth",         RAW,    { command_manageauth } },
    { "admin.cgi",          RAW,    { command_shoutcast_metadata } },
    { "resetstats",         XSLT,   { command_reset_stats } },
    { "metadata.xsl",       XSLT,   { command_metadata } },
    { "listclients.xsl",    XSLT,   { command_show_listeners } },
    { "updatemetadata.xsl", XSLT,   { command_updatemetadata } },
    { "killclient.xsl",     XSLT,   { command_kill_client } },
    { "moveclients.xsl",    XSLT,   { command_move_clients } },
    { "killsource.xsl",     XSLT,   { command_kill_source } },
    { "manageauth.xsl",     XSLT,   { command_manageauth } },
    { NULL }
};

/* build an XML doc containing information about currently running sources.
 * If a mountpoint is passed then that source will not be added to the XML
 * doc even if the source is running */
xmlDocPtr admin_build_sourcelist (const char *mount, int show_listeners)
{
    avl_node *node;
    source_t *source;
    xmlNodePtr xmlnode, srcnode;
    xmlDocPtr doc;
    char buf[22];
    time_t now = time(NULL);

    doc = xmlNewDoc(XMLSTR("1.0"));
    xmlnode = xmlNewDocNode(doc, NULL, XMLSTR("icestats"), NULL);
    xmlDocSetRootElement(doc, xmlnode);

    if (mount) {
        xmlNewChild(xmlnode, NULL, XMLSTR("current_source"), XMLSTR(mount));
    }

    node = avl_get_first(global.source_tree);
    while(node) {
        source = (source_t *)node->key;
        if (mount && strcmp (mount, source->mount) == 0)
        {
            node = avl_get_next (node);
            continue;
        }

        thread_rwlock_rlock (&source->lock);
        if (source_available (source))
        {
            ice_config_t *config;
            mount_proxy *mountinfo;

            srcnode = xmlNewChild (xmlnode, NULL, XMLSTR("source"), NULL);
            xmlSetProp (srcnode, XMLSTR("mount"), XMLSTR(source->mount));

            snprintf (buf, sizeof(buf), "%lu", source->listeners);
            xmlNewChild (srcnode, NULL, XMLSTR("listeners"), XMLSTR(buf));
            xmlNewChild (srcnode, NULL, XMLSTR("Listeners"), XMLSTR(buf)); // for backward compatability

            config = config_get_config();
            mountinfo = config_find_mount (config, source->mount);
            if (mountinfo)
            {
                if (mountinfo->auth)
                {
                    xmlNewChild (srcnode, NULL, XMLSTR("authenticator"), 
                            XMLSTR(mountinfo->auth->type));
                }
                if (mountinfo->fallback_mount)
                    xmlNewChild (srcnode, NULL, XMLSTR("fallback"), 
                            XMLSTR(mountinfo->fallback_mount));
            }
            config_release_config();

            if (source_running (source))
            {
                if (source->client)
                {
                    snprintf (buf, sizeof(buf), "%lu",
                            (unsigned long)(now - source->client->connection.con_time));
                    xmlNewChild (srcnode, NULL, XMLSTR("Connected"), XMLSTR(buf));
                }
                xmlNewChild (srcnode, NULL, XMLSTR("content-type"), 
                        XMLSTR(source->format->contenttype));
                if (show_listeners)
                    admin_source_listeners (source, srcnode);
            }
        }
        thread_rwlock_unlock (&source->lock);
        node = avl_get_next(node);
    }
    return(doc);
}


int admin_send_response (xmlDocPtr doc, client_t *client, 
        admin_response_type response, const char *xslt_template)
{
    int ret = -1;

    if (response == RAW)
    {
        xmlChar *buff = NULL;
        int len = 0;
        unsigned int buf_len;
        const char *http = "HTTP/1.0 200 OK\r\n"
               "Content-Type: text/xml\r\n"
               "Content-Length: ";
        xmlDocDumpFormatMemoryEnc (doc, &buff, &len, NULL, 1);
        buf_len = strlen (http) + len + 50;
        client_set_queue (client, NULL);
        client->refbuf = refbuf_new (buf_len);
        len = snprintf (client->refbuf->data, buf_len, "%s%d\r\n%s\r\n\r\n%s", http, len,
                client_keepalive_header (client), buff);
        client->refbuf->len = len;
        xmlFree(buff);
        xmlFreeDoc (doc);
        client->respcode = 200;
        return fserve_setup_client (client);
    }
    if (response == XSLT)
    {
        char *fullpath_xslt_template;
        int fullpath_xslt_template_len;
        ice_config_t *config = config_get_config();

        fullpath_xslt_template_len = strlen (config->adminroot_dir) + 
            strlen(xslt_template) + 2;
        fullpath_xslt_template = malloc(fullpath_xslt_template_len);
        snprintf(fullpath_xslt_template, fullpath_xslt_template_len, "%s%s%s",
            config->adminroot_dir, PATH_SEPARATOR, xslt_template);
        config_release_config();

        DEBUG1("Sending XSLT (%s)", fullpath_xslt_template);
        ret = xslt_transform (doc, fullpath_xslt_template, client);
        free(fullpath_xslt_template);
    }
    return ret;
}


static struct admin_command *find_admin_command (struct admin_command *list, const char *uri)
{
    for (; list->request; list++)
    {
        if (strcmp (list->request, uri) == 0)
            break;
    }
    if (list->request == NULL)
    {
        list = NULL;
        if (strcmp (uri, "stats.xml") != 0)
            DEBUG1("request (%s) not a builtin", uri);
    }
    return list;
}


// wrapper to free up memory allocated for moved client.
static void admin_client_destroy (client_t *client)
{
    free ((void*)client->aux_data);
    client_destroy (client);
}

struct _client_functions admin_mount_ops =
{
    admin_mount_request,
    admin_client_destroy
};


int admin_mount_request (client_t *client)
{
    source_t *source;
    const char *mount = client->mount;
    char *uri = (void*)client->aux_data;

    struct admin_command *cmd = find_admin_command (admin_mount, uri);

    if (cmd == NULL)
        return command_stats (client, uri);

    if (cmd == NULL || cmd->handle.source == NULL)
    {
        INFO0("mount request not recognised");
        return client_send_400 (client, "unknown request");
    }

    avl_tree_rlock(global.source_tree);
    source = source_find_mount_raw(mount);

    if (source == NULL)
    {
        avl_tree_unlock(global.source_tree);
        if (strncmp (cmd->request, "stats", 5) == 0)
            return command_stats (client, uri);
        if (strncmp (cmd->request, "listclients", 11) == 0)
            return fserve_list_clients (client, mount, cmd->response, 1);
        if (strncmp (cmd->request, "killclient", 10) == 0)
            return fserve_kill_client (client, mount, cmd->response);
        WARN1("Admin command on non-existent source %s", mount);
        free (uri);
        return client_send_400 (client, "Source does not exist");
    }
    else
    {
        int ret = 0;

        // see if we should move workers. avoid excessive write lock bubbles in worker run queue
        worker_t *src_worker = source->client->worker;
        if (src_worker != client->worker)
        {
            client->ops = &admin_mount_ops;
            avl_tree_unlock (global.source_tree);
            // DEBUG0 (" moving admin request to alternate worker");
            return client_change_worker (client, src_worker);
        }
        free (uri);
        thread_rwlock_wlock (&source->lock);
        if (source_available (source) == 0)
        {
            thread_rwlock_unlock (&source->lock);
            avl_tree_unlock (global.source_tree);
            INFO1("Received admin command on unavailable mount \"%s\"", mount);
            return client_send_400 (client, "Source is not available");
        }
        avl_tree_unlock(global.source_tree);
        ret = cmd->handle.source (client, source, cmd->response);
        return ret;
    }
}


int admin_handle_request (client_t *client, const char *uri)
{
    const char *mount = httpp_get_query_param(client->parser, "mount");

    if (strcmp (uri, "/admin.cgi") == 0)
    {
        const char *pass = httpp_get_query_param (client->parser, "pass");
        if (pass == NULL)
            return client_send_400 (client, "missing pass parameter");
        uri++;

        char *pass_copy = strdup(pass);
        char *login_end = pass_copy + strlen(pass_copy);
        char *login_pass = strchr(pass_copy, ':');
        char *login_mount = strchr(pass_copy, '@');

        if(login_pass) *login_pass++ = '\0';
        if(login_mount) *login_mount++ = '\0';

        client->username = strdup(login_pass && (!login_mount 
            || (login_mount && login_mount > pass_copy +1)) ? pass_copy : "source");
        client->password = strdup(login_pass && login_pass < login_end 
            ? login_pass : pass_copy);

        if (mount == NULL)
        {
            if (login_mount && login_mount < login_end)
            {
                if(*login_mount != '/') *--login_mount = '/';
                httpp_set_query_param (client->parser, "mount", login_mount);
            }
            else if (client->server_conn && client->server_conn->shoutcast_mount)
            {
                httpp_set_query_param (client->parser, "mount",
                    client->server_conn->shoutcast_mount);
            }
            mount = httpp_get_query_param (client->parser, "mount");
        }
        free(pass_copy);
        httpp_setvar (client->parser, HTTPP_VAR_PROTOCOL, "ICY");
        httpp_setvar (client->parser, HTTPP_VAR_ICYPASSWORD, client->password);
    }
    else
        uri += 7;

    if (connection_check_admin_pass (client->parser))
        client->flags |= CLIENT_AUTHENTICATED;
    else
    {
        /* special case for slaves requesting a streamlist for authenticated relaying */
        if (strcmp (uri, "streams") == 0 || strcmp (uri, "streamlist.txt") == 0)
        {
            if (connection_check_relay_pass (client->parser))
                client->flags |= CLIENT_AUTHENTICATED;
        }
    }

    if (mount)
    {
        xmlSetStructuredErrorFunc ((char*)mount, config_xml_parse_failure);
        client->mount = mount;
        client->aux_data = (int64_t)strdup (uri);

        /* no auth/stream required for this */
        if (strcmp (uri, "buildm3u") == 0)
            return command_buildm3u (client, mount);
        if (strcmp (uri, "showimage") == 0)
            return command_show_image (client, mount);

        /* This is a mount request, but admin user is allowed */
        if ((client->flags & CLIENT_AUTHENTICATED) == 0)
        {
            switch (auth_check_source (client, mount))
            {
                case 0:
                    break;
                default:
                    INFO1("Bad or missing password on mount modification "
                            "admin request (%s)", uri);
                    return client_send_401 (client, NULL);
                    /* fall through */
                case 1:
                    return 0;
            }
        }
        if (strcmp (uri, "streams") == 0)
            return auth_add_listener ("/admin/streams", client);
        return admin_mount_request (client);
    }

    return admin_handle_general_request (client, uri);
}


static int admin_handle_general_request (client_t *client, const char *uri)
{
    struct admin_command *cmd;

    if ((client->flags & CLIENT_AUTHENTICATED) == 0)
    {
        INFO1("Bad or missing password on admin command request (%s)", uri);
        return client_send_401 (client, NULL);
    }

    cmd = find_admin_command (admin_general, uri);
    xmlSetStructuredErrorFunc ((char*)uri, config_xml_parse_failure);
    if (cmd == NULL)
    {
        INFO1 ("processing file %s", uri);
        return command_stats (client, uri);
    }
    if (cmd->handle.general == NULL)
        return client_send_400 (client, "unknown request");
    return cmd->handle.general (client, cmd->response);
}


#define COMMAND_REQUIRE(client,name,var) command_require(client,name,&(var))
static int command_require (client_t *client, const char *name, const char **var)
{
    *var = httpp_get_query_param((client)->parser, (name));
    if (*var == NULL)
        return -1;
    return 0;
} 

#define COMMAND_OPTIONAL(client,name,var) \
    (var) = httpp_get_query_param((client)->parser, (name))

int html_success (client_t *client, const char *message)
{
    client->respcode = 200;
    snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
            "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" 
            "<html><head><title>Admin request successful</title></head>"
            "<body><p>%s</p></body></html>", message);
    client->refbuf->len = strlen (client->refbuf->data);
    return fserve_setup_client (client);
}


static int command_move_clients (client_t *client, source_t *source, int response)
{
    const char *dest_source;
    xmlDocPtr doc;
    xmlNodePtr node;
    int parameters_passed = 0;
    char buf[255];

    if((COMMAND_OPTIONAL(client, "destination", dest_source))) {
        parameters_passed = 1;
    }
    if (!parameters_passed) {
        doc = admin_build_sourcelist(source->mount, 0);
        thread_rwlock_unlock (&source->lock);
        return admin_send_response(doc, client, response, "moveclients.xsl");
    }
    INFO2 ("source is \"%s\", destination is \"%s\"", source->mount, dest_source);

    doc = xmlNewDoc(XMLSTR("1.0"));
    node = xmlNewDocNode(doc, NULL, XMLSTR("iceresponse"), NULL);
    xmlDocSetRootElement(doc, node);

    source_set_fallback (source, dest_source);
    source->termination_count = source->listeners;
    source->flags |= SOURCE_LISTENERS_SYNC;

    snprintf (buf, sizeof(buf), "Clients moved from %s to %s",
            source->mount, dest_source);
    thread_rwlock_unlock (&source->lock);
    xmlNewChild(node, NULL, XMLSTR("message"), XMLSTR(buf));
    xmlNewChild(node, NULL, XMLSTR("return"), XMLSTR("1"));

    return admin_send_response (doc, client, response, "response.xsl");
}


static int admin_function (const char *function, char *buf, unsigned int len)
{
    if (strcmp (function, "reopenlog") == 0)
    {
        ice_config_t *config = config_grab_config();

        restart_logging (config);
        config_release_config();
        snprintf (buf, len, "Re-opening log files");
        return 0;
    }
    if (strcmp (function, "updatecfg") == 0)
    {
#ifdef HAVE_SIGNALFD
        connection_running = 0;
        connection_close_sigfd();
#endif
        global . schedule_config_reread = 1;
        snprintf (buf, len, "Requesting reread of configuration file");
        return 0;
    }
    return -1;
}


static int command_admin_function (client_t *client, int response)
{
    xmlDocPtr doc;
    xmlNodePtr node;
    const char *perform;
    char buf[256];

    if (COMMAND_REQUIRE (client, "perform", perform) < 0)
        return client_send_400 (client, "missing arg, perform");
    if (admin_function (perform, buf, sizeof buf) < 0)
        return client_send_400 (client, "No such handler");
    doc = xmlNewDoc(XMLSTR("1.0"));
    node = xmlNewDocNode(doc, NULL, XMLSTR("iceresponse"), NULL);
    xmlDocSetRootElement(doc, node);

    xmlNewChild(node, NULL, XMLSTR("message"), XMLSTR(buf));
    xmlNewChild(node, NULL, XMLSTR("return"), XMLSTR("1"));

    return admin_send_response (doc, client, response, "response.xsl");
}


static void add_relay_xmlnode (xmlNodePtr node, relay_server *relay)
{
    xmlNodePtr relaynode = xmlNewChild (node, NULL, XMLSTR("relay"), NULL);
    relay_server_host *host = relay->hosts;
    char str [50];

    xmlNewChild (relaynode, NULL, XMLSTR("localmount"), XMLSTR(relay->localmount));
    snprintf (str, sizeof (str), "%d", (relay->flags & RELAY_RUNNING) ? 1 : 0);
    xmlNewChild (relaynode, NULL, XMLSTR("enable"), XMLSTR(str));
    snprintf (str, sizeof (str), "%d", (relay->flags & RELAY_ON_DEMAND) ? 1 : 0);
    xmlNewChild (relaynode, NULL, XMLSTR("on_demand"), XMLSTR(str));
    snprintf (str, sizeof (str), "%d", (relay->flags & RELAY_FROM_MASTER ? 1 : 0));
    xmlNewChild (relaynode, NULL, XMLSTR("from_master"), XMLSTR(str));
    while (host)
    {
        xmlNodePtr masternode = xmlNewChild (relaynode, NULL, XMLSTR("master"), NULL);
        xmlNewChild (masternode, NULL, XMLSTR("server"), XMLSTR(host->ip));
        xmlNewChild (masternode, NULL, XMLSTR("mount"), XMLSTR(host->mount));
        snprintf (str, sizeof (str), "%d", host->port);
        xmlNewChild (masternode, NULL, XMLSTR("port"), XMLSTR(str));
        host = host->next;
    }
}


static int command_manage_relay (client_t *client, int response)
{
    const char *relay_mount, *enable;
    const char *msg;
    relay_server *relay;
    xmlDocPtr doc;
    xmlNodePtr node;

    COMMAND_OPTIONAL (client, "relay", relay_mount);
    COMMAND_OPTIONAL (client, "enable", enable);

    if (relay_mount == NULL || enable == NULL)
    {
        avl_node *relaynode;
        doc = xmlNewDoc (XMLSTR("1.0"));
        node = xmlNewDocNode (doc, NULL, XMLSTR("icerelaystats"), NULL);
        xmlDocSetRootElement(doc, node);
        avl_tree_rlock (global.relays);
        relaynode = avl_get_first (global.relays);
        while (relaynode)
        {
            relay_server *relay = (relay_server*)relaynode->key;
            add_relay_xmlnode (node, relay);
            relaynode = avl_get_next (relaynode);
        }

        avl_tree_unlock (global.relays);
        return admin_send_response (doc, client, response, "managerelays.xsl");
    }

    avl_tree_rlock (global.relays);

    relay = slave_find_relay (relay_mount);
    msg = "no such relay";
    if (relay)
    {
        source_t *source = relay->source;
        client_t *client;

        thread_rwlock_wlock (&source->lock);
        client = source->client;
        if (atoi (enable))
            relay->flags |= RELAY_RUNNING;
        else
            relay->flags &= ~RELAY_RUNNING;
        if (client)
        {
            client->schedule_ms = 0;
            worker_wakeup (client->worker);
        }
        thread_rwlock_unlock (&source->lock);
        msg = "relay has been changed";
    }
    avl_tree_unlock (global.relays);

    doc = xmlNewDoc(XMLSTR("1.0"));
    node = xmlNewDocNode(doc, NULL, XMLSTR("iceresponse"), NULL);
    xmlDocSetRootElement(doc, node);
    xmlNewChild(node, NULL, XMLSTR("message"), XMLSTR(msg));
    xmlNewChild(node, NULL, XMLSTR("return"), XMLSTR("1"));
    return admin_send_response(doc, client, response, "response.xsl");
}


/* populate within srcnode, groups of 0 or more listener tags detailing
 * information about each listener connected on the provide source.
 */
void admin_source_listeners (source_t *source, xmlNodePtr srcnode)
{
    avl_node *node;

    if (source == NULL)
        return;
    node = avl_get_first (source->clients);
    while (node)
    {
        client_t *listener = (client_t *)node->key;
        stats_listener_to_xml (listener, srcnode);
        node = avl_get_next (node);
    }
}


static int command_reset_stats (client_t *client, source_t *source, int response)
{
    const char *msg = "Failed to reset values";
    const char *name = httpp_get_query_param (client->parser, "setting");
    int all = 0, ok = 0;
    xmlDocPtr doc;
    xmlNodePtr node;

    if (name == NULL)
        all = 1;
    if (all || strstr (name, "peak"))
    {
        source->peak_listeners = source->listeners;
        source->prev_listeners = source->peak_listeners+1;
        ok = 1;
    }
    if (all || strstr (name, "read"))
        if (source->format)
        {
            source->format->read_bytes = 0;
            ok = 1;
        }
    if (all || strstr (name, "sent"))
        if (source->format)
        {
            source->format->sent_bytes = 0;
            ok = 1;
        }

    if (ok)
        msg = "have reset settings";
    doc = xmlNewDoc(XMLSTR("1.0"));
    node = xmlNewDocNode(doc, NULL, XMLSTR("iceresponse"), NULL);
    xmlDocSetRootElement(doc, node);
    xmlNewChild(node, NULL, XMLSTR("message"), XMLSTR(msg));
    xmlNewChild(node, NULL, XMLSTR("return"), XMLSTR("1"));
    return admin_send_response (doc, client, response, "response.xsl");
}


static int command_show_listeners (client_t *client, source_t *source, int response)
{
    xmlDocPtr doc;
    xmlNodePtr node, srcnode;
    uint64_t id = -1;
    const char *ID_str = NULL;
    char buf[22];

    doc = xmlNewDoc(XMLSTR("1.0"));
    node = xmlNewDocNode(doc, NULL, XMLSTR("icestats"), NULL);
    srcnode = xmlNewChild(node, NULL, XMLSTR("source"), NULL);

    xmlSetProp(srcnode, XMLSTR("mount"), XMLSTR(source->mount));
    xmlDocSetRootElement(doc, node);

    snprintf(buf, sizeof(buf), "%lu", source->listeners);
    xmlNewChild(srcnode, NULL, XMLSTR("listeners"), XMLSTR(buf));

    COMMAND_OPTIONAL(client, "id", ID_str);
    if (ID_str)
        sscanf (ID_str, "%" SCNu64, &id);

    if (id == -1)
        admin_source_listeners (source, srcnode);
    else
    {
        client_t *listener = source_find_client (source, id);

        if (listener)
            stats_listener_to_xml (listener, srcnode);
    }
    thread_rwlock_unlock (&source->lock);

    return admin_send_response (doc, client, response, "listclients.xsl");
}


static int command_show_image (client_t *client, const char *mount)
{
    source_t *source;

    avl_tree_rlock (global.source_tree);
    source = source_find_mount_raw (mount);
    if (source && source->format && source->format->get_image)
    {
        thread_rwlock_rlock (&source->lock);
        avl_tree_unlock (global.source_tree);
        if (source->format->get_image (client, source->format) == 0)
        {
            thread_rwlock_unlock (&source->lock);
            return fserve_setup_client (client);
        }
        thread_rwlock_unlock (&source->lock);
    }
    else
        avl_tree_unlock (global.source_tree);
    return client_send_404 (client, "No image available");
}


static int command_buildm3u (client_t *client, const char *mount)
{
    const char *username = NULL;
    const char *password = NULL;
    ice_config_t *config;
    const char *host = httpp_getvar (client->parser, "host");
    const char *protocol = not_ssl_connection (&client->connection) ? "http" : "https";

    if (COMMAND_REQUIRE(client, "username", username) < 0 ||
            COMMAND_REQUIRE(client, "password", password) < 0)
        return client_send_400 (client, "missing arg, username/password");

    client->respcode = 200;
    config = config_get_config();
    if (host)
    {
        char port[10] = "";
        if (strchr (host, ':') == NULL)
            snprintf (port, sizeof (port), ":%u",  config->port);
        snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
                "HTTP/1.0 200 OK\r\n"
                "Content-Type: audio/x-mpegurl\r\n"
                "Content-Disposition: attachment; filename=\"listen.m3u\"\r\n\r\n"
                "%s://%s:%s@%s%s%s\r\n",
                protocol, username, password,
                host, port, mount);
    }
    else
    {
        snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
                "HTTP/1.0 200 OK\r\n"
                "Content-Type: audio/x-mpegurl\r\n"
                "Content-Disposition: attachment; filename=\"listen.m3u\"\r\n\r\n"
                "%s://%s:%s@%s:%d%s\r\n",
                protocol, username, password,
                config->hostname, config->port, mount);
    }
    config_release_config();

    client->refbuf->len = strlen (client->refbuf->data);
    return fserve_setup_client (client);
}


static int command_manageauth (client_t *client, source_t *source, int response)
{
    xmlDocPtr doc;
    xmlNodePtr node, srcnode, msgnode;
    const char *action = NULL;
    const char *username = NULL;
    const char *message = NULL;
    int ret = AUTH_OK;
    ice_config_t *config = config_get_config ();
    mount_proxy *mountinfo = config_find_mount (config, source->mount);

    do
    { 
        if (mountinfo == NULL || mountinfo->auth == NULL)
        {
            WARN1 ("manage auth request for %s but no facility available", source->mount);
            break;
        }
        COMMAND_OPTIONAL (client, "action", action);
        COMMAND_OPTIONAL (client, "username", username);

        if (action == NULL)
            action = "list";

        if (!strcmp(action, "add"))
        {
            const char *password = NULL;
            COMMAND_OPTIONAL (client, "password", password);

            if (username == NULL || password == NULL)
            {
                WARN1 ("manage auth request add for %s but no user/pass", source->mount);
                break;
            }
            ret = mountinfo->auth->adduser(mountinfo->auth, username, password);
            if (ret == AUTH_FAILED) {
                message = "User add failed - check the icecast error log";
            }
            if (ret == AUTH_USERADDED) {
                message = "User added";
            }
            if (ret == AUTH_USEREXISTS) {
                message = "User already exists - not added";
            }
        }
        if (!strcmp(action, "delete"))
        {
            if (username == NULL)
            {
                WARN1 ("manage auth request delete for %s but no username", source->mount);
                break;
            }
            ret = mountinfo->auth->deleteuser(mountinfo->auth, username);
            if (ret == AUTH_FAILED) {
                message = "User delete failed - check the icecast error log";
            }
            if (ret == AUTH_USERDELETED) {
                message = "User deleted";
            }
        }

        doc = xmlNewDoc(XMLSTR "1.0");
        node = xmlNewDocNode(doc, NULL, XMLSTR("icestats"), NULL);
        srcnode = xmlNewChild(node, NULL, XMLSTR("source"), NULL);
        xmlSetProp(srcnode, XMLSTR "mount", XMLSTR(source->mount));
        thread_rwlock_unlock (&source->lock);

        if (message) {
            msgnode = xmlNewChild(node, NULL, XMLSTR("iceresponse"), NULL);
            xmlNewChild(msgnode, NULL, XMLSTR "message", XMLSTR(message));
        }

        xmlDocSetRootElement(doc, node);

        if (mountinfo && mountinfo->auth && mountinfo->auth->listuser)
            mountinfo->auth->listuser (mountinfo->auth, srcnode);

        config_release_config ();

        return admin_send_response (doc, client, response, "manageauth.xsl");
    } while (0);

    thread_rwlock_unlock (&source->lock);
    config_release_config ();
    return client_send_400 (client, "missing parameter");
}


static int command_kill_source (client_t *client, source_t *source, int response)
{
    xmlDocPtr doc;
    xmlNodePtr node;

    doc = xmlNewDoc(XMLSTR("1.0"));
    node = xmlNewDocNode(doc, NULL, XMLSTR("iceresponse"), NULL);
    xmlNewChild(node, NULL, XMLSTR("message"), XMLSTR("Source Removed"));
    xmlNewChild(node, NULL, XMLSTR("return"), XMLSTR("1"));
    xmlDocSetRootElement(doc, node);

    source->flags &= ~SOURCE_RUNNING;

    thread_rwlock_unlock (&source->lock);
    return admin_send_response (doc, client, response, "response.xsl");
}


static int command_kill_client (client_t *client, source_t *source, int response)
{
    const char *idtext;
    uint64_t id;
    client_t *listener;
    xmlDocPtr doc;
    xmlNodePtr node;
    char buf[50] = "";

    if (COMMAND_REQUIRE(client, "id", idtext) < 0)
    {
        thread_rwlock_unlock (&source->lock);
        return client_send_400 (client, "missing arg, id");
    }

    sscanf (idtext, "%" SCNu64, &id);

    listener = source_find_client(source, id);

    doc = xmlNewDoc(XMLSTR("1.0"));
    node = xmlNewDocNode(doc, NULL, XMLSTR("iceresponse"), NULL);
    xmlDocSetRootElement(doc, node);

    if(listener != NULL) {
        INFO1("Admin request: client %" PRIu64 " removed", id);

        /* This tags it for removal on the next iteration of the main source
         * loop
         */
        listener->connection.error = 1;
        snprintf(buf, sizeof(buf), "Client %" PRIu64 " removed", id);
        xmlNewChild(node, NULL, XMLSTR("message"), XMLSTR(buf));
        xmlNewChild(node, NULL, XMLSTR("return"), XMLSTR("1"));
    }
    else {
        snprintf(buf, sizeof(buf), "Client %" PRIu64 " not found", id);
        xmlNewChild(node, NULL, XMLSTR("message"), XMLSTR(buf));
        xmlNewChild(node, NULL, XMLSTR("return"), XMLSTR("0"));
    }
    thread_rwlock_unlock (&source->lock);
    return admin_send_response (doc, client, response, "response.xsl");
}


static int command_fallback (client_t *client, source_t *source, int response)
{
    char *mount = strdup (source->mount);
    mount_proxy *mountinfo;
    ice_config_t *config;

    thread_rwlock_unlock (&source->lock);
    DEBUG0("Got fallback request");
    config = config_grab_config();
    mountinfo = config_find_mount (config, mount);
    free (mount);
    if (mountinfo)
    {
        const char *fallback;
        char buffer[200];
        if (COMMAND_REQUIRE(client, "fallback", fallback) < 0)
            return client_send_400 (client, "missing arg, fallback");

        xmlFree (mountinfo->fallback_mount);
        mountinfo->fallback_mount = (char *)xmlCharStrdup (fallback);
        snprintf (buffer, sizeof (buffer), "Fallback for \"%s\" configured", mountinfo->mountname);
        config_release_config ();
        return html_success (client, buffer);
    }
    config_release_config ();
    return client_send_400 (client, "no mount details available");
}


static int command_metadata (client_t *client, source_t *source, int response)
{
    const char *song, *title, *artist, *artwork, *charset, *url, *intro;
    format_plugin_t *plugin;
    xmlDocPtr doc;
    xmlNodePtr node;
    int same_ip = 1;

    doc = xmlNewDoc(XMLSTR("1.0"));
    node = xmlNewDocNode(doc, NULL, XMLSTR("iceresponse"), NULL);
    xmlDocSetRootElement(doc, node);

    DEBUG0("Got metadata update request");

    COMMAND_OPTIONAL(client, "song", song);
    COMMAND_OPTIONAL(client, "title", title);
    COMMAND_OPTIONAL(client, "artist", artist);
    COMMAND_OPTIONAL(client, "url", url);
    COMMAND_OPTIONAL(client, "artwork", artwork);
    COMMAND_OPTIONAL(client, "charset", charset);
    COMMAND_OPTIONAL(client, "intro", intro);
    if (intro == NULL)
        COMMAND_OPTIONAL(client, "preroll", intro);

    plugin = source->format;
    if (source_running (source))
        if (strcmp (client->connection.ip, source->client->connection.ip) != 0)
            if (response == RAW && connection_check_admin_pass (client->parser) == 0)
                same_ip = 0;

    do
    {
        if (same_ip == 0 || plugin == NULL)
            break;
        if (artwork)
            stats_event (source->mount, "artwork", artwork);
        if (intro)
        {
            source_set_intro (source, intro);
        }
        if (plugin->set_tag)
        {
            if (url)
            {
                plugin->set_tag (plugin, "url", url, charset);
                INFO2 ("Metadata url on %s set to \"%s\"", source->mount, url);
            }
            if (song)
            {
                plugin->set_tag (plugin, "artist", NULL, NULL);
                plugin->set_tag (plugin, "title", song, charset);
                INFO2("Metadata song on %s set to \"%s\"", source->mount, song);
            }
            if (artist)
            {
                plugin->set_tag (plugin, "artist", artist, charset);
                INFO2 ("Metadata artist on %s changed to \"%s\"", source->mount, artist);
            }
            if (title)
            {
                plugin->set_tag (plugin, "title", title, charset);
                INFO2 ("Metadata title on %s changed to \"%s\"", source->mount, title);
            }
            /* updates are now done, let them be pushed into the stream */
            plugin->set_tag (plugin, NULL, NULL, charset);
        }
        else
        {
            break;
        }
        thread_rwlock_unlock (&source->lock);
        xmlNewChild(node, NULL, XMLSTR("message"), XMLSTR("Metadata update successful"));
        xmlNewChild(node, NULL, XMLSTR("return"), XMLSTR("1"));
        return admin_send_response(doc, client, response, "response.xsl");

    } while (0);
    INFO1 ("Metadata on mountpoint %s prevented", source->mount);
    thread_rwlock_unlock (&source->lock);
    xmlNewChild(node, NULL, XMLSTR("message"), 
            XMLSTR("Mountpoint will not accept this URL update"));
    xmlNewChild(node, NULL, XMLSTR("return"), XMLSTR("1"));
    return admin_send_response(doc, client, response, "response.xsl");
}


static int command_shoutcast_metadata (client_t *client, source_t *source)
{
    const char *action;
    const char *value;
    int same_ip = 1;

    if (COMMAND_REQUIRE(client, "mode", action) < 0)
    {
        thread_rwlock_unlock (&source->lock);
        return client_send_400 (client, "missing arg, mode");
    }

    if ((source->flags & SOURCE_SHOUTCAST_COMPAT) == 0)
    {
        thread_rwlock_unlock (&source->lock);
        ERROR0 ("illegal request on non-shoutcast compatible stream");
        return client_send_400 (client, "Not a shoutcast compatible stream");
    }

    if (strcmp (action, "updinfo") == 0)
    {
        DEBUG0("Got shoutcast metadata update request");
        if (COMMAND_REQUIRE (client, "song", value) < 0)
        {
            thread_rwlock_unlock (&source->lock);
            return client_send_400 (client, "missing arg, song");
        }
        if (source->client && strcmp (client->connection.ip, source->client->connection.ip) != 0)
            if (connection_check_admin_pass (client->parser) == 0)
                same_ip = 0;

        if (same_ip && source->format && source->format->set_tag)
        {
            httpp_set_query_param (client->parser, "mount", client->server_conn->shoutcast_mount);
            source->format->set_tag (source->format, "title", value, NULL);
            source->format->set_tag (source->format, NULL, NULL, NULL);

            DEBUG2("Metadata on mountpoint %s changed to \"%s\"", source->mount, value);
            thread_rwlock_unlock (&source->lock);
            return html_success(client, "Metadata update successful");
        }
        thread_rwlock_unlock (&source->lock);
        return client_send_400 (client, "mountpoint will not accept URL updates");
    }
    if (strcmp (action, "viewxml") == 0)
    {
        xmlDocPtr doc;
        DEBUG0("Got shoutcast viewxml request");
        thread_rwlock_unlock (&source->lock);
        doc = stats_get_xml (STATS_ALL, source->mount);
        return admin_send_response (doc, client, XSLT, "viewxml.xsl");
    }
    thread_rwlock_unlock (&source->lock);
    return client_send_400 (client, "No such action");
}


static int command_stats_mount (client_t *client, source_t *source, int response)
{
    thread_rwlock_unlock (&source->lock);
    return command_stats (client, NULL);
}


/* catch all function for admin requests.  If file has xsl extension then
 * transform it using the available stats, else send the XML tree of the
 * stats
 */
static int command_stats (client_t *client, const char *filename)
{
    admin_response_type response = RAW;
    const char *show_mount = NULL;
    xmlDocPtr doc;

    if (filename)
        if (util_check_valid_extension (filename) == XSLT_CONTENT)
            response = XSLT;

    show_mount = httpp_get_query_param (client->parser, "mount");

    doc = stats_get_xml (STATS_ALL, show_mount);
    return admin_send_response (doc, client, response, filename);
}


static int command_list_log (client_t *client, int response)
{
    refbuf_t *content;
    const char *logname = httpp_get_query_param (client->parser, "log");
    int log = -1;
    unsigned int len = 0;
    ice_config_t *config;

    if (logname == NULL)
        return client_send_400 (client, "No log specified");

    config = config_get_config ();
    if (strcmp (logname, "errorlog") == 0)
        log = config->error_log.logid;
    else if (strcmp (logname, "accesslog") == 0)
        log = config->access_log.logid;
    else if (strcmp (logname, "playlistlog") == 0)
        log = config->playlist_log.logid;

    if (log_contents (log, NULL, &len) < 0)
    {
        config_release_config();
        WARN1 ("request to show unknown log \"%s\"", logname);
        return client_send_400 (client, "unknown");
    }
    content = refbuf_new (len+1);
    log_contents (log, &content->data, &content->len);
    config_release_config();

    if (response == XSLT)
    {
        xmlNodePtr xmlnode;
        xmlDocPtr doc;

        doc = xmlNewDoc(XMLSTR("1.0"));
        xmlnode = xmlNewDocNode(doc, NULL, XMLSTR("icestats"), NULL);
        xmlDocSetRootElement(doc, xmlnode);
        xmlNewTextChild (xmlnode, NULL, XMLSTR("log"), XMLSTR(content->data));
        refbuf_release (content);

        return admin_send_response (doc, client, XSLT, "showlog.xsl");
    }
    else
    {
        refbuf_t *http = refbuf_new (100);
        int len = snprintf (http->data, 100, "%s",
                "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n");
        http->len = len;
        http->next = content; 
        client->respcode = 200;
        client_set_queue (client, NULL);
        client->refbuf = http;
        return fserve_setup_client (client);
    }
}


int command_list_mounts(client_t *client, int response)
{
    DEBUG0("List mounts request");

    client_set_queue (client, NULL);
    client->refbuf = refbuf_new (PER_CLIENT_REFBUF_SIZE);
    if (response == TEXT)
    {
        redirector_update (client);

        snprintf (client->refbuf->data, PER_CLIENT_REFBUF_SIZE,
                "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n");
        client->refbuf->len = strlen (client->refbuf->data);
        client->respcode = 200;

        if (strcmp (httpp_getvar (client->parser, HTTPP_VAR_URI), "/admin/streams") == 0)
            client->refbuf->next = stats_get_streams (1);
        else
            client->refbuf->next = stats_get_streams (0);
        return fserve_setup_client (client);
    }
    else
    {
        xmlDocPtr doc;
        int show_listeners = httpp_get_query_param (client->parser, "with_listeners") ? 1 : 0;
        avl_tree_rlock (global.source_tree);
        doc = admin_build_sourcelist (NULL, show_listeners);
        avl_tree_unlock (global.source_tree);

        return admin_send_response (doc, client, response, "listmounts.xsl");
    }
}


static int command_updatemetadata(client_t *client, source_t *source, int response)
{
    xmlDocPtr doc;
    xmlNodePtr node, srcnode;

    thread_rwlock_unlock (&source->lock);
    doc = xmlNewDoc(XMLSTR("1.0"));
    node = xmlNewDocNode(doc, NULL, XMLSTR("icestats"), NULL);
    srcnode = xmlNewChild(node, NULL, XMLSTR("source"), NULL);
    xmlSetProp(srcnode, XMLSTR("mount"), XMLSTR(source->mount));
    xmlDocSetRootElement(doc, node);

    return admin_send_response (doc, client, response, "updatemetadata.xsl");
}


#ifdef MY_ALLOC
static int command_alloc(client_t *client)
{
    xmlDocPtr doc = xmlNewDoc (XMLSTR("1.0"));
    xmlNodePtr rootnode = xmlNewDocNode(doc, NULL, XMLSTR("icestats"), NULL);
    avl_node *node;
    char value[25];

    xmlDocSetRootElement(doc, rootnode);

    snprintf (value, sizeof value, "%d", xmlMemUsed());
    xmlNewChild (rootnode, NULL, XMLSTR("libxml_mem"), XMLSTR(value));

    avl_tree_rlock (global.alloc_tree);
    node = avl_get_first (global.alloc_tree);
    while (node)
    {
        alloc_node *an = node->key;
        xmlNodePtr bnode = xmlNewChild (rootnode, NULL, XMLSTR("block"), NULL);
        xmlSetProp (bnode, XMLSTR("name"), XMLSTR(an->name));
        snprintf (value, sizeof value, "%d", an->count);
        xmlNewChild (bnode, NULL, XMLSTR("count"), XMLSTR(value));
        snprintf (value, sizeof value, "%d", an->allocated);
        xmlNewChild (bnode, NULL, XMLSTR("allocated"), XMLSTR(value));

        node = avl_get_next (node);
    }
    avl_tree_unlock (global.alloc_tree);

    return admin_send_response (doc, client, RAW, "stats.xsl");
}
#endif

