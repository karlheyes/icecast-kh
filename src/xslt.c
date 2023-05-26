/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org>,
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 * Copyright 2010-2023, Karl Heyes <karl@kheyes.plus.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/debugXML.h>
#include <libxml/HTMLtree.h>
#include <libxml/xmlIO.h>
#include <libxml/xinclude.h>
#include <libxml/catalog.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "timing/timing.h"
#include "thread/thread.h"
#include "avl/avl.h"
#include "httpp/httpp.h"
#include "net/sock.h"

#include "connection.h"

#include "global.h"
#include "refbuf.h"
#include "client.h"
#include "stats.h"
#include "fserve.h"
#include "util.h"

#define CATMODULE "xslt"

#include "logging.h"


typedef struct {
    char                *filename;
    char                *disposition;
    xsltStylesheetPtr   stylesheet;
    uint32_t            flags;
    uint32_t            refc;
    time_t              last_modified;
    uint64_t            cache_age;
    uint64_t            next_check;
} stylesheet_cache_t;

#define XSLCACHE_PENDING        (1<<0)
#define XSLCACHE_FAILED         (1<<1)
#define XSLCACHE_ADMIN          (1<<2)


typedef struct
{
    int32_t index;
    int32_t flags;
    client_t *client;
    xmlDocPtr doc;
    char *filename;
    stylesheet_cache_t *cache;
} xsl_req;

#define XSLREQ_DELAY            (1<<0)
#define XSLREQ_ADM              (1<<1)


static int xslt_client (client_t *client);


struct _client_functions xslt_ops =
{
    xslt_client,
    client_destroy
};


struct bufs
{
    refbuf_t *head, **tail;
    int len;
};


#define CACHESIZE      20

static stylesheet_cache_t cache[CACHESIZE];
static rwlock_t sheet_lock;     // for the library sheet access
static mutex_t  cache_lock;     // for cache access (not-sheet), control details
static mutex_t  update_lock;    // for thread/queue access.
static int xsl_threads = 0;

static client_t *xsl_clients = NULL;
static int xsl_count = 0;



#ifndef HAVE_XSLTSAVERESULTTOSTRING
int xsltSaveResultToString(xmlChar **doc_txt_ptr, int * doc_txt_len, xmlDocPtr result, xsltStylesheetPtr style)
{
    xmlOutputBufferPtr buf;

    *doc_txt_ptr = NULL;
    *doc_txt_len = 0;
    if (result->children == NULL)
        return 0;

    buf = xmlAllocOutputBuffer(NULL);

    if (buf == NULL)
        return -1 ;
    xsltSaveResultTo(buf, result, style);
    if (buf->conv != NULL)
    {
        *doc_txt_len = xmlBufUse (buf->conv);
        *doc_txt_ptr = xmlStrndup (xmlBufContent (buf->conv), *doc_txt_len);
    } else {
        *doc_txt_len = xmlBufUse (buf->buffer);
        *doc_txt_ptr = xmlStrndup (xmlBufContent (buf->buffer), *doc_txt_len);
    }
    (void)xmlOutputBufferClose(buf);
    return 0;
}
#endif


static int xslt_write_callback (void *ctxt, const char *data, int len)
{
    struct bufs *x = ctxt;
    refbuf_t *r;
    int loop = 10;

    if (len == 0)
        return 0;
    if (len < 0 || len > 2000000)
    {
        ERROR1 ("%d length requested", len);
        return -1;
    }
    while (loop)
    {
        r = *x->tail;
        if (r)
        {
            x->tail = &r->next;
            loop--;
            continue;
        }
        *x->tail = r = refbuf_new (len);
        memcpy (r->data, data, len);
        x->len += len;
        break;
    }
    return len;
}


int xslt_SaveResultToBuf (refbuf_t **bptr, int *len, xmlDocPtr result, xsltStylesheetPtr style)
{
    xmlOutputBufferPtr buf;
    struct bufs x;

    if (result->children == NULL)
    {
        *bptr = NULL;
        *len = 0;
        return 0;
    }

    memset (&x, 0, sizeof (x));
    x.tail = &x.head;
    buf = xmlOutputBufferCreateIO (xslt_write_callback, NULL, &x, NULL);

    if (buf == NULL)
        return  -1;
    xsltSaveResultTo (buf, result, style);
    *bptr = x.head;
    *len = x.len;
    xmlOutputBufferClose(buf);
    return 0;
}



void xslt_initialize(void)
{
    memset (&cache[0], 0, sizeof cache);
    thread_rwlock_create (&sheet_lock);
    thread_mutex_create (&cache_lock);
    thread_mutex_create (&update_lock);
    xsl_threads = 0;
#ifdef MY_ALLOC
    xmlMemSetup(xmlMemFree, xmlMemMalloc, xmlMemRealloc, xmlMemoryStrdup);
#endif
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlSubstituteEntitiesDefault(1);
    xmlLoadExtDtdDefaultValue = 1;
}


static void clear_cached_stylesheet (stylesheet_cache_t *entry, int zerod)
{
    if (entry == NULL) return;
    free (entry->filename);
    free (entry->disposition);
    if (entry->stylesheet)
        xsltFreeStylesheet (entry->stylesheet);
    if (zerod) memset (entry, 0, sizeof (*entry));
}

void xslt_shutdown(void) {
    int i;

    for(i=0; i < CACHESIZE; i++) {
        clear_cached_stylesheet (&cache[i], 0);
    }

    thread_rwlock_destroy (&sheet_lock);
    thread_mutex_destroy (&cache_lock);
    thread_mutex_destroy (&update_lock);
    xmlCleanupParser();
    xsltCleanupGlobals();
}


//
static void xsl_req_clear (xsl_req *x)
{
    xmlFreeDoc (x->doc);
    if (x->cache)
    {
        thread_mutex_lock (&cache_lock);
        x->cache->flags &= ~XSLCACHE_PENDING;
        x->cache->refc--;
        thread_mutex_unlock (&cache_lock);
    }
    free (x->filename);
    free (x);
}

// requires write lock on xslt_lock on entry
//
static int xslt_cached (xsl_req *x, uint64_t now)
{
    uint64_t early_p = now+1, early_f = early_p, early_na = early_p;
    int i, present = CACHESIZE, failed = CACHESIZE, nonadmin = CACHESIZE;

    if (x && x->cache)
    {
        thread_mutex_lock (&cache_lock);
        if ((x->cache->flags & XSLCACHE_PENDING) == 0)
        {
            x->flags &= ~XSLREQ_DELAY;          // toggle off
            x->cache->cache_age = now;           // update to keep around
        }
        thread_mutex_unlock (&cache_lock);
        return 1; // already set
    }
    thread_mutex_lock (&cache_lock);
    for (i=0; i < CACHESIZE; i++)
    {
        if (cache[i].filename == NULL)
            break;
        if (filename_cmp (x->filename, cache[i].filename) == 0)
            break;
        if (cache[i].cache_age > 0 && cache[i].refc == 0)
        {
            if (cache[i].flags & XSLCACHE_FAILED)
            {
                if (early_f > cache[i].cache_age)
                {
                    early_f = cache[i].cache_age;
                    failed = i;
                }
            }
            else if ((cache[i].flags & XSLCACHE_ADMIN) == 0)
            {
                if (early_na > cache[i].cache_age)
                {
                    early_na = cache[i].cache_age;
                    nonadmin = i;
                }
            }
            else if (early_p > cache[i].cache_age)
            {
                early_p = cache[i].cache_age;
                present = i;
            }
        }
    }
    int rc = 0;
    do
    {
        if (i == CACHESIZE)
        {   // no matching filename, maybe something to replace
            if (failed < CACHESIZE)       // evict failed slots over success
                i = failed;
            else if (nonadmin < CACHESIZE) // evict non-admin slots over admin
                i = nonadmin;
            else if (present < CACHESIZE)  // oldest of all
                i = present;
            if (i == CACHESIZE)
                break;  // nothing selected, drop out for retry
            clear_cached_stylesheet (&cache[i], 1);
            DEBUG1 ("cleared slot %d", i);
        }
        if (cache[i].filename == NULL)
        {
            cache[i].filename = strdup (x->filename);
            cache[i].cache_age = 0;
            cache[i].flags = XSLCACHE_PENDING;  // init
            if (x->flags & XSLREQ_ADM)
                cache[i].flags |= XSLCACHE_ADMIN;
        }
        else if (cache[i].flags & XSLCACHE_PENDING)
            x->flags |= XSLREQ_DELAY;       // slot is in pending state
        rc = -1;
        if ((cache[i].flags & XSLCACHE_FAILED) && cache[i].next_check > now)
            break;
        if ((cache[i].flags & XSLCACHE_PENDING) == 0)
        {
            x->flags &= ~XSLREQ_DELAY;          // toggle off
            cache[i].cache_age = now;           // update to keep around
            cache[i].flags &= ~XSLCACHE_FAILED; // drop for recheck
        }
        cache[i].refc++;        // tag it to keep unchanged.
        thread_mutex_unlock (&cache_lock);
        x->cache = &cache[i];
        DEBUG2 ("using cache slot %d for %s", i, x->filename);
        return 1;
    } while (0);
    thread_mutex_unlock (&cache_lock);
    return rc;
}


static int _apply_sheet (xsl_req *x)
{
    client_t *client = x->client;
    xmlDocPtr res;
    xsltStylesheetPtr sheet = x->cache->stylesheet;
    char    **params = NULL;

    if (sheet == NULL)
        return -1;
    if (client->parser->queryvars)
    {
        // annoying but we need to surround the args with ' when passing them in
        int j, arg_count = client->parser->queryvars->length * 2;
        avl_node *node = avl_get_first (client->parser->queryvars);

        params = calloc (arg_count+1, sizeof (char *));
        for (j = 0; node && j < arg_count; node = avl_get_next (node))
        {
            http_var_t *param = (http_var_t *)node->key;
            char *tmp = util_url_escape (param->value);
            params[j++] = param->name;
            // use alloca for now, should really url esc into a supplied buffer
            params[j] = (char*)alloca (strlen (tmp) + 3);
            sprintf (params[j++], "\'%s\'", tmp);
            free (tmp);
        }
        params[j] = NULL;
    }
    client->aux_data = 0;

    res = xsltApplyStylesheet (sheet, x->doc, (const char **)params);
    free (params);

    if (res == NULL)
    {
        thread_rwlock_unlock (&sheet_lock);
        return -1;
    }
    xmlFreeDoc (x->doc);
    x->doc = res;

    return 0;
}


// This is to keep the cached sheets and metadata intact/up to date
//
// enter with cache_lock, return drops cache lock, return 0 with sheet_lock (read)
//
static int xslt_apply_sheet (xsl_req *x, uint64_t now)
{
    int rc = 0;
    char *fn = NULL;
    stylesheet_cache_t *cached = x->cache;
    do
    {
        xsltStylesheetPtr sheet;
        rc = -1;
        cached->cache_age = now;
        if (cached->next_check > now)
            thread_mutex_unlock (&cache_lock);
        else
        {
            struct stat file;
            fn = strdup (cached->filename);
            time_t mtime = cached->last_modified;
            cached->next_check = now + 60000;
            thread_mutex_unlock (&cache_lock);

            int failed = stat (fn, &file);
            if (failed)
            {
                WARN2 ("Error checking for stylesheet file \"%s\": %s", fn, strerror(errno));
                break;
            }

            if (file.st_mtime != mtime)
            {
                sheet = xsltParseStylesheetFile (XMLSTR(fn));
                if (sheet == NULL)
                {
                    WARN1 ("problem reading stylesheet \"%s\"", fn);
                    break;
                }
                char *dispos = NULL;
                int lookup_dispos = 0;
                INFO1 ("loaded stylesheet %s", fn);
                if (sheet->mediaType && strcmp ((char*)(sheet->mediaType), "text/html") != 0)
                    lookup_dispos = 1;      // avoid lookup for html pages
                if (lookup_dispos)
                {
                    char filename[100] = "file.";
                    fserve_write_mime_ext ((char*)sheet->mediaType, filename + 5, sizeof(filename)-5);
                    dispos = strdup (filename);
                }
                thread_rwlock_wlock (&sheet_lock);
                xsltStylesheetPtr old_sheet = cached->stylesheet;
                cached->stylesheet = sheet;
                thread_rwlock_unlock (&sheet_lock);
                xsltFreeStylesheet (old_sheet);

                thread_mutex_lock (&cache_lock);
                cached->last_modified = file.st_mtime;
                cached->disposition = dispos;
                cached->flags &= ~(XSLCACHE_FAILED|XSLCACHE_PENDING);
                // drop refc after response done.
                thread_mutex_unlock (&cache_lock);
            }
            else
            {
                DEBUG1 ("file %s has same mtime, not modified", fn);
            }
        }
        thread_rwlock_rlock (&sheet_lock);
        if (_apply_sheet (x) < 0)
        {
            WARN1 ("problem applying stylesheet \"%s\"", x->filename);
            break;
        }
        rc = 0;

    } while (0);

    if (rc < 0)
    {   // error condition, so drop any last ties
        thread_mutex_lock (&cache_lock);
        cached->flags |= XSLCACHE_FAILED;
        if (cached->refc > 0) cached->refc--;
        cached->flags &= ~XSLCACHE_PENDING;
        thread_mutex_unlock (&cache_lock);
        x->cache = NULL;
    }
    free (fn);
    return rc;
}



// requires sheet_lock before being called, released on return
//
static int xslt_prepare_response (xsl_req *x)
{
    stylesheet_cache_t  *cached = x->cache;
    xsltStylesheetPtr   sheet = cached->stylesheet;
    refbuf_t            *content = NULL;
    int len, rc = -1;

    ice_http_t http = ICE_HTTP_INIT;
    do
    {
        if (xslt_SaveResultToBuf (&content, &len, x->doc, sheet) < 0)
        {   // unlikely, memory starvation
            thread_rwlock_unlock (&sheet_lock);
            WARN1 ("body for stylesheet \"%s\" failed", x->filename);
            thread_mutex_lock (&cache_lock);
            break;
        }
        x->cache = NULL;
        rc = 0;
        ice_http_setup_flags (&http, x->client, 200, 0, NULL);

        x->client = NULL;
        const char *mediatype = NULL;

        /* lets find out the content type to use */
        if (sheet->mediaType)
            mediatype = (char *)sheet->mediaType;
        else
        {
            /* check method for the default, a missing method assumes xml */
            if (sheet->method && xmlStrcmp (sheet->method, XMLSTR("html")) == 0)
                mediatype = "text/html";
            else
                if (sheet->method && xmlStrcmp (sheet->method, XMLSTR("text")) == 0)
                    mediatype = "text/plain";
                else
                    mediatype = "text/xml";
        }
        if (sheet->encoding)
            ice_http_printf (&http, "Content-Type", 0, "%s; charset=%s", mediatype, (char *)sheet->encoding);
        else
            ice_http_printf (&http, "Content-Type", 0, "%s", mediatype);
        thread_rwlock_unlock (&sheet_lock);

        ice_http_apply_block (&http, content);
        http.in_length = len;

        thread_mutex_lock (&cache_lock);
        if (cached->disposition)
            ice_http_printf (&http, "Content-Disposition", 0, "attachment; filename=\"%s\"", cached->disposition);
    } while (0);

    if (cached->refc > 0) cached->refc--;
    cached->flags &= ~XSLCACHE_PENDING;
    // DEBUG3 ("Tmp: %s, cache %s, ref %d", (rc?"failed":"content"), cached->filename, cached->refc);
    thread_mutex_unlock (&cache_lock);

    ice_http_complete (&http);
    return rc;
}


/* thread to read xsl file and add to the cache */
void *xslt_update (void *arg)
{
    xmlSetStructuredErrorFunc ("xsl/file", config_xml_parse_failure);
    xsltSetGenericErrorFunc ("", log_parse_failure);

    thread_mutex_lock (&update_lock);
    for (client_t *client = xsl_clients; client; client = xsl_clients)
    {
        xsl_clients = client->next_on_worker;
        xsl_count--;
        thread_mutex_unlock (&update_lock);
        int running = global_state() == ICE_RUNNING;

        xsl_req *x = (xsl_req *)client->aux_data;
        client->next_on_worker = NULL;

        uint64_t now = timing_get_time();

        if (running && client->connection.discon.time > (now/1000))
        {
            thread_mutex_lock (&cache_lock);
            if (xslt_apply_sheet (x, now) == 0 && xslt_prepare_response (x) == 0)
                fserve_setup_client (client);
        }

        if (x->client)
            client_send_404 (client, "Could not provide XSLT file");
        xsl_req_clear (x);
        thread_mutex_lock (&update_lock);
    }
    xsl_threads--;
    thread_mutex_unlock (&update_lock);
    return NULL;
}


int xslt_client (client_t *client)
{
    xsl_req *x = (xsl_req*)client->aux_data;
    uint64_t now = client->worker->time_ms;
    int rc = xslt_cached (x, now);
    do
    {
        if (rc < 0) break;
        if (client->connection.discon.time <= (now/1000))
        {
            WARN1 ("Taking too long to get %s from cache", x->filename);
            break;
        }
        if (rc > 0)
        {       // process only if cached and none already pending
            if (x->flags & XSLREQ_DELAY)
            {
                client->schedule_ms += 15;
                return 0;
            }
            thread_mutex_lock (&update_lock);
            int q = xsl_count;
            if (q < 40)
            {       // cache slot marked and queue not too bad
                client->next_on_worker = xsl_clients;
                client->worker = NULL;
                xsl_clients = client;
                xsl_count++;
                if (xsl_threads < 5)
                {
                    xsl_threads++;
                    thread_mutex_unlock (&update_lock);
                    // DEBUG1 ("Starting update thread for %s", x->filename);
                    thread_create ("update xslt", xslt_update, NULL, THREAD_DETACHED);
                    return 1;
                }
                int v = xsl_threads;
                thread_mutex_unlock (&update_lock);
                DEBUG2 ("reschedule update, %d queued, %d running", q, v);
                return 1;
            }
            thread_mutex_unlock (&update_lock);
            break;
        }
        INFO1 ("dropping request for %s as cache full and in use", x->filename);
        // if cache busy then drop further requests
    } while (0);
    xsl_req_clear (x);
    return client_send_404 (client, NULL);
}


static int _xslt_transform (xmlDocPtr doc, const char *xslfilename, client_t *client, int admin)
{
    xsl_req *x = calloc (1, sizeof (xsl_req));
    x->client = client;
    x->doc = doc;
    x->filename = strdup (xslfilename);
    client->aux_data = (uintptr_t)x;
    client->schedule_ms = client->worker->time_ms;
    client->ops = &xslt_ops;
    client->connection.discon.time = client->worker->current_time.tv_sec + 3;
    return client->worker ? client->ops->process (client) : 0;
}

// entry point for xslt requests
//
int xslt_transform (xmlDocPtr doc, const char *xslfilename, client_t *client)
{
    return _xslt_transform (doc, xslfilename, client, 0);
}

int xslt_transform_admin (xmlDocPtr doc, const char *xslfilename, client_t *client)
{
    return _xslt_transform (doc, xslfilename, client, 1);
}
