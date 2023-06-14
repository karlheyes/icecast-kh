/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2010-2023, Karl Heyes <karl@kheyes.plus.net>
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org>,
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#if HAVE_GLOB_H
#include <glob.h>
#endif
#include <errno.h>
#include <fnmatch.h>
#include "thread/thread.h"
#include "timing/timing.h"
#include "cfgfile.h"
#include "refbuf.h"
#include "client.h"
#include "params.h"
#include "logging.h"
#include "global.h"
#include "git_hash.h"

#define CATMODULE "cfgfile"
#define CONFIG_DEFAULT_LOCATION "Earth"
#define CONFIG_DEFAULT_ADMIN "icemaster@localhost"
#define CONFIG_DEFAULT_CLIENT_LIMIT 256
#define CONFIG_DEFAULT_SOURCE_LIMIT 16
#define CONFIG_DEFAULT_QUEUE_SIZE_LIMIT (500*1024)
#define CONFIG_DEFAULT_BURST_SIZE (64*1024)
#define CONFIG_DEFAULT_CLIENT_TIMEOUT 30
#define CONFIG_DEFAULT_HEADER_TIMEOUT 5
#define CONFIG_DEFAULT_SOURCE_TIMEOUT 10
#define CONFIG_DEFAULT_SOURCE_PASSWORD "changeme"
#define CONFIG_DEFAULT_RELAY_PASSWORD "changeme"
#define CONFIG_DEFAULT_MASTER_USERNAME "relay"
#define CONFIG_DEFAULT_SHOUTCAST_MOUNT "/stream"
#define CONFIG_DEFAULT_ICE_LOGIN 0
#define CONFIG_DEFAULT_FILESERVE 1
#define CONFIG_DEFAULT_TOUCH_FREQ 5
#define CONFIG_DEFAULT_HOSTNAME "localhost"
#define CONFIG_DEFAULT_PLAYLIST_LOG NULL
#define CONFIG_DEFAULT_ACCESS_LOG "access.log"
#define CONFIG_DEFAULT_ERROR_LOG "error.log"
#define CONFIG_DEFAULT_LOG_LEVEL 3
#define CONFIG_DEFAULT_CHROOT 0
#define CONFIG_DEFAULT_CHUID 0
#define CONFIG_MASTER_UPDATE_INTERVAL 120
#define CONFIG_YP_URL_TIMEOUT 10
#define CONFIG_DEFAULT_CIPHER_LIST "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA"

#ifndef _WIN32
#define CONFIG_DEFAULT_BASE_DIR "/usr/local/icecast"
#define CONFIG_DEFAULT_LOG_DIR "/usr/local/icecast/logs"
#define CONFIG_DEFAULT_WEBROOT_DIR "/usr/local/icecast/webroot"
#define CONFIG_DEFAULT_ADMINROOT_DIR "/usr/local/icecast/admin"
#define MIMETYPESFILE "/etc/mime.types"
#else
#define CONFIG_DEFAULT_BASE_DIR ".\\"
#define CONFIG_DEFAULT_LOG_DIR ".\\logs"
#define CONFIG_DEFAULT_WEBROOT_DIR ".\\webroot"
#define CONFIG_DEFAULT_ADMINROOT_DIR ".\\admin"
#endif
#ifndef MIMETYPESFILE
#define MIMETYPESFILE ".\\mime.types"
#endif

static ice_config_t _current_configuration;
static ice_config_locks _locks;
uint64_t config_updated = (uint64_t)0;

static void _set_defaults(ice_config_t *c);

static void create_locks(void)
{
    thread_rwlock_create(&_locks.config_lock);
    thread_mutex_create(&_locks.mount_lock);
}

static void release_locks(void)
{
    thread_rwlock_destroy(&_locks.config_lock);
    thread_mutex_destroy(&_locks.mount_lock);
}

typedef struct
{
    xmlNodePtr parent, node;
    xmlChar *val;
    unsigned int flags;
    ice_config_t *config;
} cfg_xml;

#define CFGXML_CHECK_NODE       (1<<0)
#define CFGXML_BYPASS_NAME      (1<<1)


static int  _parse_root (cfg_xml *cfg, void *p);
static aliases* config_clear_alias (aliases *alias);

/*
 */
struct cfg_tag
{
    const char *name;
    int (*retrieve) (cfg_xml *node, void *x);
    void *storage;
    unsigned int flags;
};

#define CFG_TAG_DEF             (1<<0)
#define CFG_TAG_NOTATTR         (1<<1)
#define CFG_TAG_MULTITAG        (1<<2)
#define CFG_TAG_ALLOW_MANY      (1<<3)
#define CFG_TAG_ASSIGNED        (1<<4)


static const char *cfg_get_string (cfg_xml *cfg)
{
    return (char*)(cfg ? cfg->val : NULL);
}


int config_qsizing_conv_a2n (const char *str, uint32_t *p)
{
    unsigned int v = 0;
    char metric = '\0';
    *p = 0;
    errno = 0;
    int r = sscanf ((char*)str, "%u%c", &v, &metric);
    if (r == 2)
    {
        if (metric == 'k')
            v *= 1000;
        else if (metric == 'm')
            v *= 1000000;
        if (metric == 's')
        {
            if (v > 3600)
                v = 3600;   // cap the seconds to something something like sane
            *p = 1<<31; // for later conversion, when bitrate is known.
        }
    } else if (r != 1) // error converting
        return -1;
    if (v > (1<<31))  // enforce cap on largest number
        v = (unsigned int) (1<<31) - 1;
    *p += v;
    return 0;
}


int config_get_qsizing (cfg_xml *cfg, void *x)
{
    int ret = -1;
    const char *str = cfg_get_string (cfg);
    if (str)
    {
        uint32_t *p = (uint32_t *)x;
        ret = (config_qsizing_conv_a2n ((char*)str, p) < 0) ? -1 : 1;
    }
    return ret;
}


/* Process xml node for boolean value, it may be true, yes, or 1
 */
int config_get_bool (cfg_xml *cfg, void *x)
{
    const char *str = cfg_get_string (cfg);
    int ret = 1, val = 0;
    do {

        if (str == NULL) break;
        if (strcasecmp ((char*)str, "no") == 0) break;
        if (strcasecmp ((char*)str, "false") == 0) break;
        val = 1;
        if (strcasecmp ((char*)str, "true") == 0) break;
        if (strcasecmp ((char*)str, "yes") == 0) break;
        if (sscanf ((char*)str, "%d", &val) == 1) break;
        ret = -1;
    } while (0);
    if (ret == 1)
        *(int*)x = val;
    return ret;
}


int config_get_str (cfg_xml *cfg, void *x)
{
    const char *str = cfg_get_string (cfg);
    if (str)
    {
        xmlChar *old = *(xmlChar**)x;
        if (old) xmlFree (old);
        *(xmlChar **)x = (xmlChar*)str;
        cfg->val = NULL;
    }
    return 1;
}


int config_get_int (cfg_xml *cfg, void *x)
{
    const char *str = cfg_get_string (cfg);
    int ret = 1;
    if (str)
    {
        int v = 0;
        errno = 0;
        if (sscanf ((char*)str, "%d", &v) != 1)
            ret = -1;
        else
            *(int *)x = v;
    }
    return ret;
}


int config_get_long (cfg_xml *cfg, void *x)
{
    const char *str = cfg_get_string (cfg);
    int ret = 1;
    if (str)
    {
        unsigned long v = 0;
        errno = 0;
        ret = 1;
        if (sscanf ((char*)str, "%lu", &v) != 1)
            ret = -1;
        else
            *(long *)x = v;
    }
    return ret;
}


int config_get_port (cfg_xml *cfg, void *x)
{
    int val = 0, ret = config_get_int (cfg, &val);

    if (ret == 1)
    {
        if (val > 0 && val < 65536)
            *(int*)x = val;
        else
        {
            WARN1 ("port out of range, %d", val);
            ret = -1;
        }
    }
    return ret;
}


int config_get_bitrate (cfg_xml *cfg, void *x)
{
    const char *str = cfg_get_string (cfg);
    int ret = 1;
    if (str)
    {
        int64_t p = 0;
        char metric = '\0';

        errno = 0;
        int rc = sscanf ((char*)str, "%"SCNd64 "%c", &p, &metric);
        if (rc > 0)
        {
            if (metric == 'k' || metric == 'K')
                p *= 1000;
            if (metric == 'm' || metric == 'M')
                p *= 1000000;
            *(int64_t*)x = p;
        } else
            ret = -1;
    }
    return ret;
}


static int convert_name_to_level (const char *tag)
{
    if (tag)
    {
        if (strcasecmp (tag, "debug") == 0)     return 4;
        if (strcasecmp (tag, "info") == 0)      return 3;
        if (strcasecmp (tag, "warn") == 0)      return 2;
        if (strcasecmp (tag, "error") == 0)     return 1;
    }
    return 0;   // return a default
}

int config_get_loglevel (cfg_xml *cfg, void *x)
{
    log_levels_t *level = (log_levels_t*)x;
    int v = 2, n = 0, l;

    const char *str = cfg_get_string (cfg), *s = str;
    do
    {
        char tag[24], value[32];
        if (str == NULL) break;
        do
        {
            int c = sscanf (s, "%23[0-9a-zA-Z]=%31[a-zA-Z0-9]%n", tag, value, &n);
            if (c == 1)
            {
                n = strlen (tag);
                if ((l = convert_name_to_level (tag)) > 0)
                    v = l;
                else if (strcasecmp (tag, "subsec") == 0)
                   level->flags = LOG_TIME_SS;
                else if (sscanf (tag, "%d", &v) != 1)
                   WARN1 ("unknown level setting %s", tag);
                break;
            }
            if (c == 0)
            {
                n = strcspn (s, ", ");
                WARN2 ("unknown level setting %.*s", (n < 10 ? n : 10), s);
                break;
            }
            l = convert_name_to_level (tag);
            if (l)
            {
               int val = 4;
               if (sscanf (value, "%d", &val) == 1 && val > 0)
               {
                   level->level [l].keep = val;
                   v = l;
                   break;
               }
            }
            WARN2 ("unknown level setting %s=%s", tag, value);
            break;

        } while (0);
        int skip = strspn (s+n, ", ");
        s += (n+skip);
    } while (*s);
    level->mark = v;
    // WARN1 ("log level set to %d", *p);
    return 1;
}


int parse_xml_tag_set (cfg_xml *cfg, struct cfg_tag *tag)
{
    int ret = -1;
    xmlNodePtr node = cfg->node, parent = node->parent;

    if (cfg->flags & CFGXML_CHECK_NODE)  // for node check.
    {
        if ((cfg->flags & CFGXML_BYPASS_NAME) == 0 && strcmp ((char*)node->name, tag->name) != 0)
            return -1;
        xmlNodePtr cnode = node->xmlChildrenNode;
        if (cnode && xmlNodeIsText (cnode) && !xmlIsBlankNode(cnode))
            cfg->val = xmlNodeListGetString (node->doc, cnode, 1);
        ret = tag->retrieve (cfg, tag->storage);
        if (ret < 0)
            xmlParserWarning (NULL, "failed to read element \"%s\" within \"%s\" at line %ld\n", node->name, parent->name, xmlGetLineNo(node));
    }
    else
    {
        xmlChar *v = xmlGetProp (cfg->node, (const xmlChar*)tag->name);
        if (v)
        {
            cfg->val = v;
            ret = tag->retrieve (cfg, tag->storage);
            if (ret < 0)
                xmlParserWarning (NULL, "failed to read attribute \"%s\" within \"%s\" at line %ld\n",
                        tag->name, node->name, xmlGetLineNo(node));
        }
    }
    if (ret > 0)
    {
        if (tag->flags & CFG_TAG_ASSIGNED)
            xmlParserWarning (NULL, "setting for \"%s\" (line %ld) was set previously", node->name, xmlGetLineNo(node));
        if (ret > 0 && (tag->flags & CFG_TAG_ALLOW_MANY) == 0)
            tag->flags |= CFG_TAG_ASSIGNED;
    }
    if (tag->flags & CFG_TAG_MULTITAG) ret = 0;    // check for other tags
    if (ret < 0) ret = 1; // failed or not, we have processed it

    if (cfg->val) xmlFree (cfg->val);
    cfg->val = NULL;
    return ret;
}


int parse_xml_tags (cfg_xml *cfg, struct cfg_tag *args)
{
    int ret = 0;
    xmlNodePtr parent = cfg->node, node = parent->xmlChildrenNode;
    struct cfg_tag *argp;
    cfg_xml ncfg = { .config = cfg->config };

    argp = args;
    ncfg.node = parent;
    for (; argp->name; argp++)
    {
        if ((argp->flags & CFG_TAG_DEF) && xmlNodeIsText (node) && !xmlIsBlankNode (node))
        {
            ncfg.flags = CFGXML_CHECK_NODE|CFGXML_BYPASS_NAME;
            ret = parse_xml_tag_set (&ncfg, argp);
        }
        if (argp->flags & CFG_TAG_NOTATTR)   continue;
        ncfg.flags = 0;
        ret = parse_xml_tag_set (&ncfg, argp);
    }

    ncfg.flags = CFGXML_CHECK_NODE;
    for (; node != NULL; node = node->next)
    {
        if (xmlIsBlankNode (node) || node->type != XML_ELEMENT_NODE)
            continue;
        argp = args;
        ncfg.node = node;
        for (; argp->name; argp++)
        {
            ret = parse_xml_tag_set (&ncfg, argp);
            if (ret > 0) break;
        }
        if (argp->name == NULL)
            xmlParserWarning (NULL, "unknown node \"%s\" parsing \"%s\" at line %ld", node->name,
                    parent->name, xmlGetLineNo(node));
    }
    return 1;
}


void config_initialize(void) {
    create_locks();
}

void config_shutdown(void)
{
    if (config_updated)
    {
        config_get_config();
        config_clear(&_current_configuration);
        config_release_config();
        release_locks();
        config_updated = (uint64_t)0;
    }
}

void config_init_configuration(ice_config_t *configuration)
{
    memset(configuration, 0, sizeof(ice_config_t));
    _set_defaults(configuration);
}


redirect_host *config_clear_redirect (redirect_host *redir)
{
    redirect_host *next = NULL;
    if (redir)
    {
        next = redir->next;
        xmlFree (redir->server);
        free (redir);
    }
    return next;
}


static void _clear_http_header_contents (ice_config_http_header_t *entry)
{
    xmlFree (entry->hdr.name);
    xmlFree (entry->hdr.value);
    xmlFree (entry->hdr.status);
}


ice_config_http_header_t *config_clear_http_header (ice_config_http_header_t *header)
{
    if (header == NULL)
        return header;
    ice_config_http_header_t *ret = header->next;
    _clear_http_header_contents (header);
    free (header);
    return ret;
}


relay_server *config_clear_relay (relay_server *relay)
{
    if (relay == NULL) return NULL;
    relay_server *next = relay->new_details;
    while (relay->hosts)
    {
        relay_server_host *host = relay->hosts;
        relay->hosts = host->next;
        while (host->http_hdrs)
            host->http_hdrs = config_clear_http_header (host->http_hdrs);
        if (host->ip) xmlFree (host->ip);
        if (host->bind) xmlFree (host->bind);
        if (host->mount) xmlFree (host->mount);
        free (host);
    }
    while (relay->http_hdrs)
        relay->http_hdrs = config_clear_http_header (relay->http_hdrs);
    if (relay->localmount)  xmlFree (relay->localmount);
    if (relay->username)    xmlFree (relay->username);
    if (relay->password)    xmlFree (relay->password);
    free (relay);
    return next;
}


int config_mount_template (const char *mount)
{
    int len = strcspn (mount, "*?[+!@$");
    return (mount[len]) ? 1 : 0;
}


void config_clear_mount (mount_proxy *mount, int log)
{
    config_options_t *option;

    if (mount == NULL) return;
    if (config_mount_ref (mount, 0) < 0)
    {
        if (log)
        {
            thread_mutex_lock (&_locks.mount_lock);
            int ref = mount->_refcount;
            thread_mutex_unlock (&_locks.mount_lock);
            WARN2 ("mount block %s has reference %d", mount->mountname, ref);
        }
        return;
    }

    if (mount->username)    xmlFree (mount->username);
    if (mount->password)    xmlFree (mount->password);
    if (mount->dumpfile)    xmlFree (mount->dumpfile);
    if (mount->intro_filename) xmlFree (mount->intro_filename);
    if (mount->on_connect)  xmlFree (mount->on_connect);
    if (mount->on_disconnect) xmlFree (mount->on_disconnect);
    if (mount->fallback.mount) xmlFree (mount->fallback.mount);
    if (mount->fallback.override) xmlFree (mount->fallback.override);
    if (mount->stream_name) xmlFree (mount->stream_name);
    if (mount->stream_description)  xmlFree (mount->stream_description);
    if (mount->stream_url)  xmlFree (mount->stream_url);
    if (mount->stream_genre) xmlFree (mount->stream_genre);
    if (mount->bitrate)     xmlFree (mount->bitrate);
    if (mount->type)        xmlFree (mount->type);
    if (mount->subtype)     xmlFree (mount->subtype);
    if (mount->charset)     xmlFree (mount->charset);
    if (mount->cluster_password) xmlFree (mount->cluster_password);
    if (mount->redirect)            xmlFree (mount->redirect);

    if (mount->auth_type)   xmlFree (mount->auth_type);
    option = mount->auth_options;
    while (option)
    {
        config_options_t *nextopt = option->next;
        if (option->name)   xmlFree (option->name);
        if (option->value)  xmlFree (option->value);
        free (option);
        option = nextopt;
    }
    while (mount->http_headers)
        mount->http_headers = config_clear_http_header (mount->http_headers);

    if (mount->auth)
    {
        thread_mutex_lock (&mount->auth->lock);
        auth_release (mount->auth);
    }
    xmlFree (mount->preroll_log.name);
    if (mount->access_log.logid >= 0)
        log_close (mount->access_log.logid);
    xmlFree (mount->access_log.name);
    xmlFree (mount->access_log.exclude_ext);
    xmlFree (mount->mountname);
    free (mount);
}

// helper routine for avl/cleanup
static int config_clear_mount_from_tree (void *arg)
{
    config_clear_mount ((mount_proxy *)arg, 1);
    return 1;
}

listener_t *config_clear_listener (listener_t *listener)
{
    listener_t *next = NULL;
    if (listener)
    {
        next = listener->next;
        listener->refcount--;
        if (listener->refcount == 0)
        {
            if (listener->bind_address)     xmlFree (listener->bind_address);
            if (listener->shoutcast_mount)  xmlFree (listener->shoutcast_mount);
            free (listener);
        }
    }
    return next;
}


aliases* config_clear_alias (aliases *alias)
{
    aliases *next = NULL;
    if (alias)
    {
        next = alias->next;
        if (alias->source) xmlFree(alias->source);
        if (alias->destination) xmlFree(alias->destination);
        if (alias->bind_address) xmlFree(alias->bind_address);
        free(alias);
    }
    return next;
}

void config_clear(ice_config_t *c)
{
    ice_config_dir_t *dirnode, *nextdirnode;

    free(c->config_filename);

    xmlFree (c->server_id);
    if (c->location) xmlFree(c->location);
    if (c->admin) xmlFree(c->admin);
    if (c->source_password) xmlFree(c->source_password);
    if (c->admin_username) xmlFree(c->admin_username);
    if (c->admin_password) xmlFree(c->admin_password);
    if (c->relay_username) xmlFree(c->relay_username);
    if (c->relay_password) xmlFree(c->relay_password);
    if (c->hostname) xmlFree(c->hostname);
    if (c->base_dir) xmlFree(c->base_dir);
    if (c->log_dir) xmlFree(c->log_dir);
    if (c->webroot_dir) xmlFree(c->webroot_dir);
    if (c->adminroot_dir) xmlFree(c->adminroot_dir);
    if (c->cert_file) xmlFree(c->cert_file);
    if (c->key_file) xmlFree(c->key_file);
    if (c->cipher_list) xmlFree(c->cipher_list);
    if (c->pidfile) xmlFree(c->pidfile);
    if (c->banfile) xmlFree(c->banfile);
    if (c->allowfile) xmlFree (c->allowfile);
    if (c->agentfile) xmlFree (c->agentfile);
    if (c->preroll_log.name) xmlFree(c->preroll_log.name);
    if (c->playlist_log.name) xmlFree(c->playlist_log.name);
    if (c->access_log.name) xmlFree(c->access_log.name);
    if (c->error_log.name) xmlFree(c->error_log.name);
    if (c->access_log.exclude_ext) xmlFree (c->access_log.exclude_ext);
    if (c->shoutcast_mount) xmlFree(c->shoutcast_mount);

    while (c->xforward)
    {
        struct xforward_entry *e = c->xforward;
        c->xforward = e->next;
        xmlFree (e->ip);
        free (e);
    }
    global_lock();
    while ((c->listen_sock = config_clear_listener (c->listen_sock)))
        ;
    global_unlock();

    while (c->http_headers)
        c->http_headers = config_clear_http_header (c->http_headers);

    if (c->master_server) xmlFree(c->master_server);
    if (c->master_username) xmlFree(c->master_username);
    if (c->master_password) xmlFree(c->master_password);
    if (c->master_bind) xmlFree(c->master_bind);
    if (c->user) xmlFree(c->user);
    if (c->group) xmlFree(c->group);
    if (c->mimetypes_fn) xmlFree (c->mimetypes_fn);

    while (c->relays)
        c->relays = config_clear_relay (c->relays);

    while (c->redirect_hosts)
        c->redirect_hosts = config_clear_redirect (c->redirect_hosts);

    avl_tree_free (c->mounts_tree, config_clear_mount_from_tree);
    while (c->mounts)
    {
        mount_proxy *to_go = c->mounts;
        c->mounts = to_go->next;
        config_clear_mount (to_go, 1);
    }
    while (c->aliases)
        c->aliases = config_clear_alias (c->aliases);

    dirnode = c->dir_list;
    while(dirnode) {
        nextdirnode = dirnode->next;
        if (dirnode->host) xmlFree(dirnode->host);
        free(dirnode);
        dirnode = nextdirnode;
    }
#ifdef USE_YP
    int i = 0;
    while (i < c->num_yp_directories)
    {
        if (c->yp_url[i]) xmlFree (c->yp_url[i]);
        i++;
    }
#endif

    memset(c, 0, sizeof(ice_config_t));
}

int config_initial_parse_file(const char *filename)
{
    /* Since we're already pointing at it, we don't need to copy it in place */
    return config_parse_file(filename, &_current_configuration);
}

int config_parse_file(const char *filename, ice_config_t *configuration)
{
    xmlDocPtr doc;
    xmlNodePtr node;

    if (filename == NULL || strcmp(filename, "") == 0) return CONFIG_EINSANE;

    xmlSetGenericErrorFunc ("conf/file", log_parse_failure);
    xmlSetStructuredErrorFunc ("conf/file", config_xml_parse_failure);
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        return CONFIG_EPARSE;
    }

    node = xmlDocGetRootElement(doc);
    if (node == NULL) {
        xmlFreeDoc(doc);
        return CONFIG_ENOROOT;
    }

    if (xmlStrcmp(node->name, XMLSTR("icecast")) != 0) {
        xmlFreeDoc(doc);
        return CONFIG_EBADROOT;
    }

    config_init_configuration(configuration);

    configuration->config_filename = (char *)strdup(filename);

    cfg_xml cfg = { .config = configuration, .node = node };

    if (_parse_root (&cfg, NULL) < 0)
    {
        xmlFreeDoc(doc);
        return CONFIG_EPARSE;
    }
    xmlFreeDoc(doc);
    return 0;
}

int config_parse_cmdline(int arg, char **argv)
{
    return 0;
}

ice_config_locks *config_locks(void)
{
    return &_locks;
}

void config_release_config(void)
{
    thread_rwlock_unlock(&(_locks.config_lock));
}

ice_config_t *config_get_config_c(const char *file, int line)
{
    thread_rwlock_rlock_c(&(_locks.config_lock), line, file);
    return &_current_configuration;
}

ice_config_t *config_grab_config(void)
{
    thread_rwlock_wlock(&(_locks.config_lock));
    return &_current_configuration;
}

/* MUST be called with the lock held! */
void config_set_config (ice_config_t *new_config, ice_config_t *old_config)
{
    if (old_config)
        memcpy (old_config, &_current_configuration, sizeof(ice_config_t));
    memcpy(&_current_configuration, new_config, sizeof(ice_config_t));
    config_updated = timing_get_time();
}

ice_config_t *config_get_config_unlocked(void)
{
    return &_current_configuration;
}


static int compare_mounts (void *arg, void *a, void *b)
{
    mount_proxy *m1 = (mount_proxy *)a;
    mount_proxy *m2 = (mount_proxy *)b;

    return strcmp (m1->mountname, m2->mountname);
}


static void _set_defaults(ice_config_t *configuration)
{
    configuration->gitversion = GIT_VERSION;
    configuration->location = (char *)xmlCharStrdup (CONFIG_DEFAULT_LOCATION);
    configuration->server_id = (char *)xmlCharStrdup (ICECAST_VERSION_STRING);
    configuration->admin = (char *)xmlCharStrdup (CONFIG_DEFAULT_ADMIN);
    configuration->cipher_list = (char *)xmlCharStrdup (CONFIG_DEFAULT_CIPHER_LIST);
    configuration->client_limit = CONFIG_DEFAULT_CLIENT_LIMIT;
    configuration->source_limit = CONFIG_DEFAULT_SOURCE_LIMIT;
    configuration->queue_size_limit = CONFIG_DEFAULT_QUEUE_SIZE_LIMIT;
    configuration->workers_count = 1;
    configuration->client_timeout = CONFIG_DEFAULT_CLIENT_TIMEOUT;
    configuration->header_timeout = CONFIG_DEFAULT_HEADER_TIMEOUT;
    configuration->source_timeout = CONFIG_DEFAULT_SOURCE_TIMEOUT;
    configuration->source_password = (char *)xmlCharStrdup (CONFIG_DEFAULT_SOURCE_PASSWORD);
    configuration->shoutcast_mount = (char *)xmlCharStrdup (CONFIG_DEFAULT_SHOUTCAST_MOUNT);
    configuration->ice_login = CONFIG_DEFAULT_ICE_LOGIN;
    configuration->fileserve = CONFIG_DEFAULT_FILESERVE;
    configuration->touch_interval = CONFIG_DEFAULT_TOUCH_FREQ;
    configuration->on_demand = 0;
    configuration->dir_list = NULL;
    configuration->hostname = (char *)xmlCharStrdup (CONFIG_DEFAULT_HOSTNAME);
    configuration->port = 0;
    configuration->master_server = NULL;
    configuration->master_server_port = 0;
    configuration->master_update_interval = CONFIG_MASTER_UPDATE_INTERVAL;
    configuration->master_username = (char*)xmlCharStrdup (CONFIG_DEFAULT_MASTER_USERNAME);
    configuration->master_password = NULL;
    configuration->master_bind = NULL;
    configuration->master_relay_auth = 0;
    configuration->master_relay_retry = configuration->master_update_interval;
    configuration->master_run_on = 30;
    configuration->base_dir = (char *)xmlCharStrdup (CONFIG_DEFAULT_BASE_DIR);
    configuration->log_dir = (char *)xmlCharStrdup (CONFIG_DEFAULT_LOG_DIR);
    configuration->webroot_dir = (char *)xmlCharStrdup (CONFIG_DEFAULT_WEBROOT_DIR);
    configuration->adminroot_dir = (char *)xmlCharStrdup (CONFIG_DEFAULT_ADMINROOT_DIR);
    configuration->playlist_log.name = (char *)xmlCharStrdup (CONFIG_DEFAULT_PLAYLIST_LOG);
    configuration->access_log.name = (char *)xmlCharStrdup (CONFIG_DEFAULT_ACCESS_LOG);
    configuration->access_log.log_ip = 1;
    configuration->access_log.logid = -1;
    configuration->error_log.name = (char *)xmlCharStrdup (CONFIG_DEFAULT_ERROR_LOG);
    configuration->error_log.level.mark = CONFIG_DEFAULT_LOG_LEVEL;
    configuration->error_log.logid = -1;
    configuration->preroll_log.logid = -1;
    configuration->playlist_log.logid = -1;
    configuration->chroot = CONFIG_DEFAULT_CHROOT;
    configuration->chuid = CONFIG_DEFAULT_CHUID;
    configuration->user = NULL;
    configuration->group = NULL;
    configuration->num_yp_directories = 0;
    configuration->slaves_count = 0;
    configuration->relay_username = (char *)xmlCharStrdup (CONFIG_DEFAULT_MASTER_USERNAME);
    configuration->relay_password = NULL;
    /* default to a typical prebuffer size used by clients */
    configuration->min_queue_size = CONFIG_DEFAULT_BURST_SIZE;
    configuration->burst_size = CONFIG_DEFAULT_BURST_SIZE;
    configuration->mounts_tree = avl_tree_new (compare_mounts, NULL);
}


static int _parse_alias (cfg_xml *cfg, void *arg)
{
    aliases **cur, *alias = calloc (1, sizeof (aliases));
    struct cfg_tag icecast_tags[] =
    {
        { "source",             config_get_str,     &alias->source },
        { "destination",        config_get_str,     &alias->destination },
        { "dest",               config_get_str,     &alias->destination },
        { "bind-address",       config_get_str,     &alias->bind_address },
        { "port",               config_get_port,    &alias->port },
        { NULL, NULL, NULL }
    };
    alias->port = -1;
    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;
    if (alias->source == NULL || alias->destination == NULL)
    {
        WARN1 ("incomplete alias definition at line %ld", xmlGetLineNo (cfg->node));
        config_clear_alias (alias);
        return -1;
    }
    cur = &cfg->config->aliases;
    while (*cur) cur = &((*cur)->next);
    *cur = alias;
    return 1;
}


static int _parse_authentication (cfg_xml *cfg, void *arg)
{
    ice_config_t *config = cfg->config;
    struct cfg_tag icecast_tags[] =
    {
        { "source-password",    config_get_str,     &config->source_password },
        { "admin-user",         config_get_str,     &config->admin_username },
        { "admin-password",     config_get_str,     &config->admin_password },
        { "relay-user",         config_get_str,     &config->relay_username },
        { "relay-password",     config_get_str,     &config->relay_password },
        { NULL, NULL, NULL }
    };

    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;
    return 1;
}


static int _parse_chown (cfg_xml *cfg, void *arg)
{
    ice_config_t *config = cfg->config;
    struct cfg_tag icecast_tags[] =
    {
        { "user",   config_get_str, &config->user },
        { "group",  config_get_str, &config->group },
        { NULL, NULL, NULL }
    };

    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;
    config->chuid = 1;
    return 1;
}


static int _parse_security (cfg_xml *cfg, void *arg)
{
    ice_config_t *config = cfg->config;
    struct cfg_tag icecast_tags[] =
    {
        { "chroot",         config_get_bool,    &config->chroot },
        { "changeowner",    _parse_chown },
        { NULL, NULL, NULL }
    };

    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;
    return 1;
}


static int _parse_accesslog (cfg_xml *cfg, void *arg)
{
    struct access_log *log = arg;
    char *type = NULL;
    struct cfg_tag icecast_tags[] =
    {
        { "name",           config_get_str,     &log->name,     .flags = CFG_TAG_DEF },
        { "ip",             config_get_bool,    &log->log_ip },
        { "type",           config_get_str,     &type },
        { "archive",        config_get_bool,    &log->archive },
        { "exclude_ext",    config_get_str,     &log->exclude_ext },
        { "display",        config_get_int,     &log->display },
        { "history",        config_get_int,     &log->display },
        { "querystr",       config_get_bool,    &log->qstr },
        { "size",           config_get_long,    &log->size },
        { "duration",       config_get_int,     &log->duration },
        { NULL, NULL, NULL }
    };

    log->logid = -1;
    log->type = LOG_ACCESS_CLF;
    log->qstr = 1;
    log->archive = -1;
    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;
    if (type && strcmp (type, "CLF-ESC") == 0)
        log->type = LOG_ACCESS_CLF_ESC;
    xmlFree (type);
    return 1;
}


static int _parse_errorlog (cfg_xml *cfg, void *arg)
{
    error_log *log = arg;
    struct cfg_tag icecast_tags[] =
    {
        { "name",           config_get_str,             &log->name,    .flags = CFG_TAG_DEF },
        { "archive",        config_get_bool,            &log->archive },
        { "display",        config_get_int,             &log->display },
        { "history",        config_get_int,             &log->display },
        { "level",          config_get_loglevel,        &log->level },
        { "size",           config_get_long,            &log->size },
        { "duration",       config_get_int,             &log->duration },
        { NULL, NULL, NULL }
    };

    log->logid = -1;
    logging_init_levels (&log->level, 0);
    return parse_xml_tags (cfg, icecast_tags);
}

static int _parse_playlistlog (cfg_xml *cfg, void *arg)
{
    playlist_log *log = arg;
    struct cfg_tag icecast_tags[] =
    {
        { "name",           config_get_str,     &log->name, .flags = CFG_TAG_DEF },
        { "archive",        config_get_bool,    &log->archive },
        { "display",        config_get_int,     &log->display },
        { "history",        config_get_int,     &log->display },
        { "size",           config_get_long,    &log->size },
        { "duration",       config_get_int,     &log->duration },
        { NULL, NULL, NULL }
    };

    log->logid = -1;
    return parse_xml_tags (cfg, icecast_tags);
}

static int _parse_logging (cfg_xml *cfg, void *arg)
{
    ice_config_t *config = cfg->config;
    long old_trigger_size = -1;
    int old_archive = 1;
    struct cfg_tag icecast_tags[] =
    {
        { "preroll-log",        _parse_errorlog,    &config->preroll_log },
        { "accesslog",          _parse_accesslog,   &config->access_log },
        { "playlistlog",        _parse_playlistlog, &config->playlist_log },
        { "accesslog_ip",       config_get_bool,    &config->access_log.log_ip },
        { "accesslog_exclude_ext",      config_get_str,     &config->access_log.exclude_ext },
        { "accesslog_lines",    config_get_int,     &config->access_log.display },
        { "errorlog",           _parse_errorlog,    &config->error_log },
        { "errorlog_lines",     config_get_int,     &config->error_log.display },
        { "loglevel",           config_get_loglevel,     &config->error_log.level },
        { "playlistlog",        config_get_str,     &config->playlist_log },
        { "playlistlog_lines",  config_get_int,     &config->playlist_log.display },
        { "logsize",            config_get_long,    &old_trigger_size },
        { "logarchive",         config_get_bool,    &old_archive },
        { NULL, NULL, NULL }
    };

    config->preroll_log.logid = -1;
    config->preroll_log.display = 50;
    config->preroll_log.archive = -1;
    config->access_log.type = LOG_ACCESS_CLF;
    config->access_log.logid = -1;
    config->access_log.display = 100;
    config->access_log.archive = -1;
    config->error_log.logid = -1;
    config->error_log.archive = -1;
    config->playlist_log.logid = -1;
    config->playlist_log.display = 10;
    config->playlist_log.archive = -1;

    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;
    if (old_trigger_size < 0)
        old_trigger_size = 20000;   // default
    if (old_trigger_size > 2000000) // have a very large upper value
        old_trigger_size = 2000000;
    old_trigger_size <<= 10; // convert to bytes

    if (config->preroll_log.size == 0)
        config->preroll_log.size = old_trigger_size;
    if (config->error_log.size == 0)
        config->error_log.size = old_trigger_size;
    if (config->access_log.size == 0)
        config->access_log.size = old_trigger_size;
    if (config->playlist_log.size == 0)
        config->playlist_log.size = old_trigger_size;

    if (config->preroll_log.archive == -1)
        config->preroll_log.archive = old_archive;
    if (config->error_log.archive == -1)
        config->error_log.archive = old_archive;
    if (config->access_log.archive == -1)
        config->access_log.archive = old_archive;
    if (config->playlist_log.archive == -1)
        config->playlist_log.archive = old_archive;

    return 1;
}


static int parse_include (cfg_xml *cfg, void *arg)
{
    char *pattern = NULL;
    int ret = 1;
    xmlNodePtr node = cfg->node->xmlChildrenNode;

    if (xmlNodeIsText (node) == 0)
        return -1;
    pattern = (char *)xmlNodeListGetString (node->doc, node, 1);
    do
    {
#if HAVE_GLOB
        glob_t globbuf;
        if (glob (pattern, 0, NULL, &globbuf) == 0)
        {
            int i;
            for (i=0; i<globbuf.gl_pathc; i++)
            {
                xmlDocPtr sub_doc = xmlParseFile (globbuf.gl_pathv[i]);
                if (sub_doc)
                {
                    xmlNodePtr sub_node = xmlDocGetRootElement (sub_doc);
                    if (sub_node)
                        xmlAddNextSibling (cfg->node, sub_node);
                    xmlFreeDoc (sub_doc);
                    continue;
                }
                ret = -1;
                break;
            }
        }
        globfree (&globbuf);
#elif HAVE_DECL_FINDFIRSTFILE
        WIN32_FIND_DATA filedata;
        HANDLE hFind = FindFirstFile (pattern, &filedata);
        do {
            if ((filedata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            {
                xmlDocPtr sub_doc = xmlParseFile (filedata.cFileName);
                if (sub_doc)
                {
                    xmlNodePtr sub_node = xmlDocGetRootElement (sub_doc);
                    if (sub_node)
                        xmlAddNextSibling (cfg->node, sub_node);
                    xmlFreeDoc (sub_doc);
                    continue;
                }
                ret = -1;
                break;
            }
        } while (FindNextFile (hFind, &filedata) != 0);
        FindClose (hFind);
#endif
    } while (0);
    xmlFree (pattern);

    return ret;
}


static int parse_xforward (cfg_xml *cfg, void *arg)
{
    char *str = (char*)cfg_get_string (cfg);
    if (str)
    {
        struct xforward_entry **p = arg, *e = calloc (1, sizeof(struct xforward_entry));

        e->ip = (char*)str;
        if (e->ip)
        {
            cfg->val = NULL;
            e->next = *p;
            *p = e;
        }
    }
    return 1;
}


static int _parse_paths (cfg_xml *cfg, void *arg)
{
    ice_config_t *config = cfg->config;
    struct cfg_tag icecast_tags[] =
    {
        { "basedir",            config_get_str, &config->base_dir },
        { "logdir",             config_get_str, &config->log_dir },
        { "x-forwarded-for",    parse_xforward, &config->xforward,      .flags = CFG_TAG_NOTATTR|CFG_TAG_ALLOW_MANY },
        { "mime-types",         config_get_str, &config->mimetypes_fn },
        { "pidfile",            config_get_str, &config->pidfile },
        { "banfile",            config_get_str, &config->banfile },
        { "ban-file",           config_get_str, &config->banfile },
        { "deny-ip",            config_get_str, &config->banfile },
        { "allow-ip",           config_get_str, &config->allowfile },
        { "deny-agents",        config_get_str, &config->agentfile },
        { "ssl-private-key",        config_get_str,     &config->key_file },
        { "ssl-certificate",        config_get_str,     &config->cert_file },
        { "ssl-cafile",             config_get_str,     &config->ca_file },
        { "ssl_certificate",        config_get_str,     &config->cert_file },
        { "ssl-allowed-ciphers",    config_get_str,     &config->cipher_list },
        { "webroot",            config_get_str,         &config->webroot_dir },
        { "adminroot",          config_get_str,         &config->adminroot_dir },
        { "alias",              _parse_alias,           .flags = CFG_TAG_NOTATTR|CFG_TAG_ALLOW_MANY },
        { NULL, NULL, NULL }
    };

    config->mimetypes_fn = (char *)xmlCharStrdup (MIMETYPESFILE);
    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;
    if (config->cert_file)
    {
        if (config->key_file == NULL)
            config->key_file = strdup (config->cert_file);
    }
    return 1;
}


static int _parse_directory (cfg_xml *cfg, void *arg)
{
    ice_config_t *config = cfg->config;
    struct cfg_tag icecast_tags[] =
    {
        { "yp-url",         config_get_str, &config->yp_url [config->num_yp_directories]},
        { "yp-url-timeout", config_get_int, &config->yp_url_timeout [config->num_yp_directories]},
        { "touch-interval", config_get_int, &config->yp_touch_interval [config->num_yp_directories]},
        { NULL, NULL, NULL }
    };

    if (config->num_yp_directories >= MAX_YP_DIRECTORIES)
    {
        ERROR0("Maximum number of yp directories exceeded!");
        return -1;
    }

    config->yp_url_timeout [config->num_yp_directories] = 10;
    config->yp_touch_interval [config->num_yp_directories] = 600;
    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;
    if (config->yp_url [config->num_yp_directories] == NULL)
        return -1;
    config->num_yp_directories++;
    return 1;
}


static int _add_http_header (ice_config_http_header_t **top, const ice_config_http_header_t *src, int log)
{
    // does it already exist, if so maybe replace
    ice_config_http_header_t **trail = top, *cur = *top;

    while (cur)
    {
        if (strcasecmp (cur->hdr.name, src->hdr.name) == 0)
        {
            if (cur->flags & PARAM_CONST)
                return -1;    // no change allowed.
            if (cur->flags & PARAM_MULTI)
                cur = NULL;
            _clear_http_header_contents (cur);
            cur->hdr = src->hdr;
            break;
        }
        trail = &cur->next;
        cur = *trail;
    }
    if (cur == NULL)    // a new one
    {
        cur = malloc (sizeof (*cur));
        *cur = *src;
        cur->next = *trail;
        *trail = cur;
    }
    if ((src->flags & PARAM_NOCOPY) == 0) // we usually make copies here
    {
        cur->hdr.name =   (char*)xmlCharStrdup (src->hdr.name);
        cur->hdr.value =  (char*)xmlCharStrdup (src->hdr.value);
        cur->hdr.status = (char*)xmlCharStrdup (src->hdr.status);
    }
    if (log)
        DEBUG4 ("Adding %s as %s, status %s (%d)", cur->hdr.name, cur->hdr.value?cur->hdr.value:"set later", cur->hdr.status, (cur->hdr.callback)?1:0);
    return 0;
}


static int config_get_http_header (cfg_xml *cfg, void *arg)
{
    ice_config_http_header_t **top = arg;
    char *name = NULL, *value = NULL, *code = NULL;

    struct cfg_tag icecast_tags[] =
    {
        { "name",       config_get_str,         &name },
        { "value",      config_get_str,         &value },
        { "status",     config_get_str,         &code },
        { NULL, NULL, NULL },
    };

    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;
    do
    {
        if (name == NULL || name[0] == '\0')
            break;
        if (value == NULL)
            value = (char*)xmlCharStrdup("");
        if (code == NULL)
            code = (char*)xmlCharStrdup("*");
        int len = 0;
        // verify provided xml
        if (sscanf (name, "%*[A-Za-z0-9!#$%&'*+.^_'|~-]%n", &len) != 0 || len < 0 || name[len] != '\0')
        {
            WARN1 ("header name invalid \"%.100s\"", name);
            break;
        }

        ice_config_http_header_t hdr = { .flags = PARAM_NOCOPY, .hdr = { .name = name, .value = value, .status = code } };
        if (_add_http_header (top,  &hdr, 1) < 0)
            break;

        return 1;
    } while (0);

    xmlFree (code);
    xmlFree (value);
    xmlFree (name);
    return 1;
}


int config_http_copy (ice_config_http_header_t *src, ice_config_http_header_t **dest)
{
    while (src)
    {
        ice_config_http_header_t hdr = *src;
        hdr.flags &= ~PARAM_NOCOPY;
        _add_http_header (dest, &hdr, 0);
        dest = &(*dest)->next;
        src = src->next;
    }
    return 0;
}


static int _parse_http_headers (cfg_xml *cfg, void *arg)
{
    ice_config_http_header_t **h_p = arg;
    struct cfg_tag icecast_tags[] =
    {
        { "header",               config_get_http_header,    h_p,  .flags = CFG_TAG_NOTATTR|CFG_TAG_ALLOW_MANY },
        { NULL, NULL, NULL },
    };

    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;
    return 1;
}


config_options_t *config_clear_option (config_options_t *opt)
{
    if (opt == NULL) return NULL;
    config_options_t *next = opt->next;
    xmlFree (opt->name);
    xmlFree (opt->value);
    free (opt);
    return next;
}


static int _parse_mount_auth_option (cfg_xml *cfg, void *arg)
{
    config_options_t *opt = calloc (1, sizeof (*opt)), **head = arg;
    struct cfg_tag icecast_tags[] =
    {
        { "name",               config_get_str,    &opt->name },
        { "value",              config_get_str,    &opt->value },
        { NULL, NULL, NULL },
    };
    do {
        if (parse_xml_tags (cfg, icecast_tags) < 0)
            break;
        if (opt->name == NULL) break;
        if (opt->value == NULL) break;
        opt->next = *head;
        *head = opt;
        return 1;
    } while (0);
    config_clear_option (opt);
    return -1;
}


static int _parse_mount_auth (cfg_xml *cfg, void *arg)
{
    config_options_t *opt = NULL;
    int ret = -1;
    auth_t *auth = calloc (1, sizeof (auth_t));
    struct cfg_tag icecast_tags[] =
    {
        { "type",            config_get_str,            &auth->type },
        { "option",         _parse_mount_auth_option,   &opt,   .flags = CFG_TAG_NOTATTR|CFG_TAG_ALLOW_MANY },
        { NULL, NULL, NULL },
    };
    do {
        auth->handlers = 5;
        if (parse_xml_tags (cfg, icecast_tags) < 0)
            break;
        if (auth_get_authenticator (auth, opt) < 0)
        {
            thread_mutex_lock (&auth->lock);
            auth_release (auth);
            break;
        }
        *(auth_t**)arg = auth;
        ret = 1;
    } while (0);

    while (opt) opt = config_clear_option (opt);
    return ret;
}


static int _parse_fallback (cfg_xml *cfg, void *x)
{
    fbinfo *fb = (fbinfo*)x;
    int64_t limit = 0;
    struct cfg_tag icecast_tags[] =
    {
        { "mount",              config_get_str,         &fb->mount,   .flags = CFG_TAG_DEF },
        { "rate",               config_get_bitrate,     &limit },
        { NULL, NULL, NULL },
    };

    parse_xml_tags (cfg, icecast_tags);
    if (fb->mount == NULL)
        WARN1 ("incomplete specification (line %ld)", xmlGetLineNo (cfg->node));
    fb->limit = limit/8;   // the fbinfo sruct expects measure in bytes
    return 1;
}


static int _parse_mount (cfg_xml *cfg, void *arg)
{
    ice_config_t *config = cfg->config;
    mount_proxy *mount = calloc(1, sizeof(mount_proxy));
    char *redirect = NULL;

    struct cfg_tag icecast_tags[] =
    {
        { "mount-name",         config_get_str,     &mount->mountname },
        { "priority",           config_get_int,     &mount->priority },
        { "source-timeout",     config_get_int,     &mount->source_timeout },
        { "queue-size",         config_get_qsizing, &mount->queue_size_limit },
        { "burst-size",         config_get_qsizing, &mount->burst_size},
        { "min-queue-size",     config_get_qsizing, &mount->min_queue_size},
        { "username",           config_get_str,     &mount->username },
        { "password",           config_get_str,     &mount->password },
        { "dump-file",          config_get_str,     &mount->dumpfile },
        { "intro",              config_get_str,     &mount->intro_filename },
        { "file-seekable",      config_get_bool,    &mount->file_seekable },
        { "fallback",           _parse_fallback,    &mount->fallback },
        { "fallback-mount",     _parse_fallback,    &mount->fallback },
        { "fallback-override",  config_get_bool,    &mount->fallback_override },
        { "fallback-when-full", config_get_bool,    &mount->fallback_when_full },
        { "hijack",             config_get_bool,    &mount->hijack },
        { "allow-chunked",      config_get_bool,    &mount->allow_chunked },
        { "max-listeners",      config_get_int,     &mount->max_listeners },
        { "max-bandwidth",      config_get_bitrate, &mount->max_bandwidth },
        { "wait-time",          config_get_int,     &mount->wait_time },
        { "filter-theora",      config_get_bool,    &mount->filter_theora },
        { "limit-rate",         config_get_bitrate, &mount->limit_rate },
        { "skip-accesslog",     config_get_bool,    &mount->skip_accesslog },
        { "charset",            config_get_str,     &mount->charset },
        { "max-send-size",      config_get_int,     &mount->max_send_size },
        { "linger-for",         config_get_int,     &mount->linger_duration },
        { "redirect",           config_get_str,     &redirect },
        { "redirect-to",        config_get_str,     &mount->redirect },
        { "http-headers",       _parse_http_headers,      &mount->http_headers,          .flags = CFG_TAG_NOTATTR },
        { "metadata-interval",  config_get_int,     &mount->mp3_meta_interval },
        { "mp3-metadata-interval",
                                config_get_int,     &mount->mp3_meta_interval },
        { "ogg-passthrough",    config_get_bool,    &mount->ogg_passthrough },
        { "admin_comments_only",config_get_bool,    &mount->admin_comments_only },
        { "allow-url-ogg-metadata",
                                config_get_bool,    &mount->url_ogg_meta },
        { "no-mount",           config_get_bool,    &mount->no_mount },
        { "ban-client",         config_get_int,     &mount->ban_client },
        { "intro-skip-replay",  config_get_int,     &mount->intro_skip_replay },
        { "so-sndbuf",          config_get_int,     &mount->so_sndbuf },
        { "hidden",             config_get_bool,    &mount->hidden },
        { "authentication",     _parse_mount_auth,  &mount->auth,               .flags = CFG_TAG_NOTATTR },
        { "on-connect",         config_get_str,     &mount->on_connect },
        { "on-disconnect",      config_get_str,     &mount->on_disconnect },
        { "max-stream-duration",
                                config_get_int,     &mount->max_stream_duration },
        { "max-listener-duration",
                                config_get_int,     &mount->max_listener_duration },
        { "preroll-log",        _parse_errorlog,    &mount->preroll_log,        .flags = CFG_TAG_NOTATTR },
        { "accesslog",          _parse_accesslog,   &mount->access_log,         .flags = CFG_TAG_NOTATTR },
        /* YP settings */
        { "listenurl",          config_get_str,     &mount->listenurl },
        { "cluster-password",   config_get_str,     &mount->cluster_password },
        { "stream-name",        config_get_str,     &mount->stream_name },
        { "stream-description", config_get_str,     &mount->stream_description },
        { "stream-url",         config_get_str,     &mount->stream_url },
        { "genre",              config_get_str,     &mount->stream_genre },
        { "bitrate",            config_get_str,     &mount->bitrate },
        { "public",             config_get_bool,    &mount->yp_public },
        { "type",               config_get_str,     &mount->type,       .flags = CFG_TAG_NOTATTR }, // clash with type on xiph build
        { "subtype",            config_get_str,     &mount->subtype,    .flags = CFG_TAG_NOTATTR },
        { NULL, NULL, NULL },
    };

    /* default <mount> settings */
    mount->_refcount = 1;
    mount->priority = INT_MAX;
    mount->max_listeners = -1;
    mount->max_bandwidth = -1;
    mount->burst_size = config->burst_size;
    mount->queue_size_limit = config->queue_size_limit;
    mount->min_queue_size = config->min_queue_size;;
    mount->mp3_meta_interval = -1;
    mount->yp_public = -1;
    mount->url_ogg_meta = 1;
    mount->source_timeout = config->source_timeout;
    mount->file_seekable = 1;
    mount->access_log.type = LOG_ACCESS_CLF;
    mount->access_log.logid = -1;
    mount->access_log.log_ip = 1;
    mount->fallback_override = 1;
    mount->max_send_size = 0;
    mount->preroll_log.logid = -1;
    mount->preroll_log.display = 50;
    mount->preroll_log.archive = -1;
    config_http_copy (config->http_headers, &mount->http_headers);

    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;

    if (mount->mountname == NULL)
    {
        xmlFree (redirect);
        config_clear_mount (mount, 0);
        return -1;
    }
    if (mount->priority < 0) mount->priority = INT_MAX;
    if (mount->auth)
        auth_finish_setup (mount->auth, mount->mountname);
    if (redirect)
    {
        char patt[] = "/${mount}";
        int len = strlen (redirect) + strlen (patt) + 1;
        xmlFree (mount->redirect);
        mount->redirect = xmlMalloc (len);
        snprintf (mount->redirect, len, "%s%s", redirect, patt);
        xmlFree (redirect);
    }
    if (mount->admin_comments_only)
        mount->url_ogg_meta = 1;
    if (mount->url_ogg_meta)
        mount->ogg_passthrough = 0;
    if (mount->ban_client < 0)
        mount->no_mount = 0;

    if (mount->fallback.mount && mount->fallback.mount[0] != '/')
    {
        WARN1 ("fallback does not start with / on %s", mount->mountname);
        xmlFree (mount->fallback.mount);
        mount->fallback.mount = NULL;
    }

    if (config_mount_template (mount->mountname))
    {
        mount_proxy *m = config->mounts, **trail = &config->mounts;
        while (m && m->priority < mount->priority)
        {
            trail = &m->next;
            m = *trail;
        }
        mount->next = m;
        *trail = mount;
    }
    else
        avl_insert (config->mounts_tree, mount);

    return 1;
}


static int _relay_host (cfg_xml *cfg, void *arg)
{
    relay_server *relay = arg;
    relay_server_host *host = calloc (1, sizeof (relay_server_host));
    int secure = 0;

    struct cfg_tag icecast_tags[] =
    {
        { "ip",             config_get_str,     &host->ip },
        { "server",         config_get_str,     &host->ip },
        { "port",           config_get_port,    &host->port },
        { "mount",          config_get_str,     &host->mount },
        { "ssl",            config_get_bool,    &secure },
        { "tls",            config_get_bool,    &secure },
        { "bind",           config_get_str,     &host->bind },
        { "timeout",        config_get_int,     &host->timeout },
        { "http-headers",   _parse_http_headers,     &host->http_hdrs, .flags = CFG_TAG_NOTATTR },
        { "priority",       config_get_int,     &host->priority },
        { NULL, NULL, NULL },
    };

    /* default master details taken from the default relay settings */
    host->ip = (char *)xmlCharStrdup (relay->hosts->ip);
    host->mount = (char *)xmlCharStrdup (relay->hosts->mount);
    if (relay->hosts->bind)
        host->bind = (char *)xmlCharStrdup (relay->hosts->bind);
    host->port = relay->hosts->port;
    host->timeout = relay->hosts->timeout;

    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;

    if (host->timeout < 1 || host->timeout > 60)
        host->timeout = 4;

    /* place new details at the end of the list */
    relay_server_host *pre = relay->hosts, *chk;
    while ((chk = pre->next))
    {
        if (host->priority && (chk->priority > host->priority))
            break;
        pre = pre->next;
    }
    pre->next = host;
    host->next = chk;
    if (secure) host->secure = 1;
    if (host->priority == 0)
        host->priority = pre->priority + 1;

    return 1;
}


static int _parse_relay (cfg_xml *cfg, void *arg)
{
    ice_config_t *config = cfg->config;
    relay_server *relay = calloc(1, sizeof(relay_server));
    relay_server_host *host = calloc (1, sizeof (relay_server_host));
    int on_demand = config->on_demand, icy_metadata = 1, running = 1;

    struct cfg_tag icecast_tags[] =
    {
        { "master",                     _relay_host,        relay,      .flags = CFG_TAG_NOTATTR|CFG_TAG_ALLOW_MANY },
        { "host",                       _relay_host,        relay,      .flags = CFG_TAG_NOTATTR|CFG_TAG_ALLOW_MANY },
        { "server",                     config_get_str,     &host->ip },
        { "ip",                         config_get_str,     &host->ip },
        { "bind",                       config_get_str,     &host->bind },
        { "port",                       config_get_port,    &host->port },
        { "mount",                      config_get_str,     &host->mount },
        { "timeout",                    config_get_int,     &host->timeout },
        { "local-mount",                config_get_str,     &relay->localmount },
        { "on-demand",                  config_get_bool,    &on_demand },
        { "run-on",                     config_get_int,     &relay->run_on },
        { "http-headers",               _parse_http_headers,  &relay->http_hdrs,   .flags = CFG_TAG_NOTATTR },
        { "retry-delay",                config_get_int,     &relay->interval },
        { "relay-icy-metadata",         config_get_bool,    &icy_metadata },
        { "relay-shoutcast-metadata",   config_get_bool,    &icy_metadata },
        { "username",                   config_get_str,     &relay->username },
        { "password",                   config_get_str,     &relay->password },
        { "enable",                     config_get_bool,    &running },
        { NULL, NULL, NULL },
    };

    relay->interval = config->master_update_interval;
    relay->run_on = config->master_run_on;
    relay->hosts = host;
    /* default settings */
    host->port = config->port;
    host->ip = (char *)xmlCharStrdup ("127.0.0.1");
    host->mount = (char*)xmlCharStrdup ("/");
    host->timeout = 4;

    do
    {
        if (parse_xml_tags (cfg, icecast_tags) < 0)
            return -1;

        if (on_demand)      relay->flags |= RELAY_ON_DEMAND;
        if (icy_metadata)   relay->flags |= RELAY_ICY_META;
        if (running)        relay->flags |= RELAY_RUNNING;

        /* check for unspecified entries */
        if (relay->localmount == NULL)
            relay->localmount = (char*)xmlCharStrdup (host->mount);
        if (relay->localmount[0] != '/')
        {
            WARN1 ("relay \"%s\" must begin with /, skipping", relay->localmount);
            break;
        }

        /* if master is set then remove the default entry at the head of the list */
        if (relay->hosts->next)
        {
            relay->hosts = relay->hosts->next;
            if (host->mount)  xmlFree (host->mount);
            if (host->ip)     xmlFree (host->ip);
            if (host->bind)   xmlFree (host->bind);
            free (host);
        }

        relay->new_details = config->relays;
        config->relays = relay;

        return 1;
    } while (0);
    config_clear_relay (relay);
    return 1;
}


static int _parse_redirect (cfg_xml *cfg, void *arg)
{
    ice_config_t *config = cfg->config;
    redirect_host *redir = calloc (1, sizeof (*redir));

    struct cfg_tag icecast_tags[] =
    {
        { "host",       config_get_str,         &redir->server },
        { "port",       config_get_port,        &redir->port },
        { NULL, NULL, NULL },
    };

    do
    {
        redir->port = 8000;
        if (parse_xml_tags (cfg, icecast_tags) < 0)
            break;

        if (redir->server == NULL)
            break;
        redir->next = config->redirect_hosts;
        config->redirect_hosts = redir;
        return 1;
    } while (0);
    free (redir);
    return 1;
}


static int _parse_limits (cfg_xml *cfg, void *arg)
{
    ice_config_t *config = cfg->config;
    struct cfg_tag icecast_tags[] =
    {
        { "max-bandwidth",      config_get_bitrate,     &config->max_bandwidth },
        { "max-listeners",      config_get_int,         &config->max_listeners },
        { "clients",            config_get_int,         &config->client_limit },
        { "sources",            config_get_int,         &config->source_limit },
        { "queue-size",         config_get_qsizing,     &config->queue_size_limit },
        { "min-queue-size",     config_get_qsizing,     &config->min_queue_size },
        { "burst-size",         config_get_qsizing,     &config->burst_size },
        { "workers",            config_get_int,         &config->workers_count },
        { "client-timeout",     config_get_int,         &config->client_timeout },
        { "header-timeout",     config_get_int,         &config->header_timeout },
        { "source-timeout",     config_get_int,         &config->source_timeout },
        { "inactivity-timeout", config_get_int,         &config->inactivity_timeout },
        { NULL, NULL, NULL },
    };
    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;
    if (config->workers_count < 1)   config->workers_count = 1;
    if (config->workers_count > 400) config->workers_count = 400;
    return 1;
}


static int _parse_master (cfg_xml *cfg, void *arg)
{
    ice_config_t *config = cfg->config;

    struct cfg_tag icecast_tags[] =
    {
        { "server",             config_get_str,     &config->master_server },
        { "port",               config_get_port,    &config->master_server_port },
        { "ssl-port",           config_get_int,     &config->master_ssl_port },
        { "username",           config_get_str,     &config->master_username },
        { "password",           config_get_str,     &config->master_password },
        { "bind",               config_get_str,     &config->master_bind },
        { "interval",           config_get_int,     &config->master_update_interval },
        { "relay-auth",         config_get_bool,    &config->master_relay_auth },
        { "retry-delay",        config_get_int,     &config->master_relay_retry },
        { "redirect",           config_get_bool,    &config->master_redirect },
        { "run-on",             config_get_int,     &config->master_run_on },
        { "on-demand",          config_get_bool,    &config->on_demand },
        { NULL, NULL, NULL },
    };

    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;
    if (config->master_update_interval < 2)
        config->master_update_interval = 60;
    if (config->master_relay_retry < 1)
        config->master_relay_retry = 60;

    return 1;
}


static int _parse_listen_sock (cfg_xml *cfg, void *arg)
{
    ice_config_t *config = cfg->config;
    listener_t *listener = calloc (1, sizeof(listener_t));

    struct cfg_tag icecast_tags[] =
    {
        { "port",               config_get_port,    &listener->port },
        { "shoutcast-compat",   config_get_bool,    &listener->shoutcast_compat },
        { "bind-address",       config_get_str,     &listener->bind_address },
        { "queue-len",          config_get_int,     &listener->qlen },
        { "so-sndbuf",          config_get_int,     &listener->so_sndbuf },
#ifndef _WIN32
        { "so-mss",             config_get_int,     &listener->so_mss },
#endif
        { "shoutcast-mount",    config_get_str,     &listener->shoutcast_mount },
        { NULL, NULL, NULL },
    };

    listener->refcount = 1;
    listener->qlen = ICE_LISTEN_QUEUE;
    do {
        if (parse_xml_tags (cfg, icecast_tags) < 0)
            break;
        if (listener->port == 0) break;

        if (listener->qlen < 1)
            listener->qlen = ICE_LISTEN_QUEUE;

        if (listener->shoutcast_mount)
        {
            if (listener->shoutcast_compat)
            {
                WARN1 ("shoutcast-compat and shoutcast-mount set on port %d, ignoring", listener->port);
                break;
            }
            if (config->shoutcast_mount == NULL)
                config->shoutcast_mount = (char*)xmlStrdup (XMLSTR(listener->shoutcast_mount));

            listener_t *sc_port = calloc (1, sizeof (listener_t));
            sc_port->refcount = 1;
            sc_port->port = listener->port+1;
            sc_port->qlen = listener->qlen;
            sc_port->shoutcast_compat = 1;
            sc_port->shoutcast_mount = (char*)xmlStrdup (XMLSTR(listener->shoutcast_mount));
            if (listener->bind_address)
                sc_port->bind_address = (char*)xmlStrdup (XMLSTR(listener->bind_address));

            sc_port->next = config->listen_sock;
            config->listen_sock = sc_port;
            config->listen_sock_count++;
        }
        listener->next = config->listen_sock;
        config->listen_sock = listener;
        config->listen_sock_count++;

        if (config->port == 0)
            config->port = listener->port;
        // leave unset shoutcast mount at this point, let the connection setup routine fill them
        return 1;
    } while (0);
    config_clear_listener (listener);
    return 1;
}


static int _parse_root (cfg_xml *cfg, void *p)
{
    ice_config_t *config = cfg->config;
    char *bindaddress = NULL;
    struct cfg_tag icecast_tags[] =
    {
        { "location",           config_get_str,     &config->location },
        { "admin",              config_get_str,     &config->admin },
        { "server_id",          config_get_str,     &config->server_id },
        { "server-id",          config_get_str,     &config->server_id },
        { "source-password",    config_get_str,     &config->source_password },
        { "hostname",           config_get_str,     &config->hostname },
        { "port",               config_get_port,    &config->port },
        { "bind-address",       config_get_str,     &bindaddress },
        { "fileserve",          config_get_bool,    &config->fileserve },
        { "relays-on-demand",   config_get_bool,    &config->on_demand },
        { "master-server",      config_get_str,     &config->master_server },
        { "master-username",    config_get_str,     &config->master_username },
        { "master-password",    config_get_str,     &config->master_password },
        { "master-bind",        config_get_str,     &config->master_bind },
        { "master-server-port", config_get_int,     &config->master_server_port },
        { "master-update-interval",
                                config_get_int,     &config->master_update_interval },
        { "master-relay-auth",  config_get_bool,    &config->master_relay_auth },
        { "master-ssl-port",    config_get_int,     &config->master_ssl_port },
        { "master-redirect",    config_get_bool,    &config->master_redirect },
        { "max-redirect-slaves",config_get_int,     &config->max_redirects },
        { "redirect",           _parse_redirect },
        { "shoutcast-mount",    config_get_str,     &config->shoutcast_mount },
        { "listen-socket",      _parse_listen_sock,             .flags = CFG_TAG_NOTATTR|CFG_TAG_ALLOW_MANY },
        { "limits",             _parse_limits,                  .flags = CFG_TAG_NOTATTR },
        { "http-headers",       _parse_http_headers,    &config->http_headers,  .flags = CFG_TAG_NOTATTR },
        { "relay",              _parse_relay,                   .flags = CFG_TAG_NOTATTR|CFG_TAG_ALLOW_MANY },
        { "mount",              _parse_mount,                   .flags = CFG_TAG_NOTATTR|CFG_TAG_ALLOW_MANY },
        { "master",             _parse_master,                  .flags = CFG_TAG_NOTATTR|CFG_TAG_ALLOW_MANY },
        { "directory",          _parse_directory,               .flags = CFG_TAG_NOTATTR|CFG_TAG_ALLOW_MANY },
        { "paths",              _parse_paths,                   .flags = CFG_TAG_NOTATTR },
        { "logging",            _parse_logging,                 .flags = CFG_TAG_NOTATTR },
        { "security",           _parse_security,                .flags = CFG_TAG_NOTATTR },
        { "authentication",     _parse_authentication,          .flags = CFG_TAG_NOTATTR },
        { "include",            parse_include,                  .flags = CFG_TAG_NOTATTR|CFG_TAG_ALLOW_MANY },
        { NULL, NULL, NULL }
    };

    extern ice_config_http_header_t default_headers[];

    for (int i = 0; default_headers[i].hdr.name; i++)
        if (_add_http_header (&config->http_headers, &default_headers[i], 1) < 0)
            WARN1 ("Problem with default header %s", default_headers[i].hdr.name);

    config->master_relay_auth = 1;
    if (parse_xml_tags (cfg, icecast_tags) < 0)
        return -1;

    if (config->max_redirects == 0 && config->master_redirect)
        config->max_redirects = 1;
    if (config->listen_sock_count == 0)
    {
        if (config->port)
        {
            listener_t *listener = calloc (1, sizeof(listener_t));
            listener->refcount = 1;
            listener->port = config->port;
            listener->qlen = ICE_LISTEN_QUEUE;
            listener->bind_address = (char*)xmlStrdup (XMLSTR(bindaddress));
            listener->next = config->listen_sock;
            config->listen_sock = listener;
            config->listen_sock_count++;
        }
        else
        {
            WARN0 ("No listen-socket defintions");
            return -1;
        }
    }
    if (config->master_update_interval < 2)
        config->master_update_interval = 60;
    return 1;
}


/* return the mount details that match the supplied mountpoint */
mount_proxy *config_find_mount (ice_config_t *_c, const char *mount)
{
    ice_config_t *config = _c;
    if (mount == NULL)
    {
        WARN0 ("no mount name provided");
        return NULL;
    }
    if (_c == NULL)
        config = config_get_config();
    void *result;
    mount_proxy findit, *mountinfo = NULL;
    findit.mountname = (char *)mount;

    int missing = avl_get_by_key (config->mounts_tree, &findit, &result);
    if (missing)
    {
        mount_proxy *to_return = NULL;
        mountinfo = config->mounts;
        while (mountinfo)
        {
            if (to_return && to_return->priority < mountinfo->priority)
                break;
            if (fnmatch (mountinfo->mountname, mount, 0) == 0)
                to_return = mountinfo;
            mountinfo = mountinfo->next;
        }
        mountinfo = to_return;
    }
    else
        mountinfo = result;
    return mountinfo;
}


// return 0 for operation done, -1 for failure (ie refcount is out of whack)
//
int config_mount_ref (mount_proxy *mountinfo, int inc)
{
    int odd = 0, val = -1;

    if (mountinfo)
    {
         thread_mutex_lock (&_locks.mount_lock);
         if (inc > 0)
             mountinfo->_refcount++;
         else if (mountinfo->_refcount > 0)
             mountinfo->_refcount--;
         else
             odd = 1;
         val = mountinfo->_refcount;
         thread_mutex_unlock (&_locks.mount_lock);
         if (odd)
             WARN2 ("request to decrease ref on %s, count %d", mountinfo->mountname, val);
    }
    return val ? -1 : 0;
}


mount_proxy *config_lock_mount (ice_config_t *_c, const char *mount)
{
    ice_config_t *config = _c;
    if (_c == NULL)
        config = config_get_config();
    mount_proxy *mountinfo = config_find_mount (config, mount);
    config_mount_ref (mountinfo, 1);
    if (_c == NULL)
        config_release_config();
    return mountinfo;
}


void config_xml_parse_failure (void *user, xmlErrorPtr error)
{
   if (error->file)
       log_parse_failure (user, "%s %s", error->file, error->message);
   else
       log_parse_failure (user, "%s", error->message);
}
