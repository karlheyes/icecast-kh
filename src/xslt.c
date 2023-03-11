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
 * Copyright 2010-2022, Karl Heyes <karl@kheyes.plus.com>
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
    char               *filename;
    char               *disposition;
    uint32_t            flags;
    time_t             last_modified;
    time_t             cache_age;
    time_t             next_check;
    xsltStylesheetPtr  stylesheet;
} stylesheet_cache_t;

#define XSLCACHE_PENDING        (1<<0)
#define XSLCACHE_FAILED         (1<<1)


typedef struct
{
    int index;
    client_t *client;
    xmlDocPtr doc;
    char *filename;
    stylesheet_cache_t *cache;
} xsl_req;


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
static rwlock_t xslt_lock;
static spin_t update_lock;
static int xsl_threads = 0;

static client_t *xsl_clients = NULL;
static int xsl_count = 0;



#ifndef HAVE_XSLTSAVERESULTTOSTRING
int xsltSaveResultToString(xmlChar **doc_txt_ptr, int * doc_txt_len, xmlDocPtr result, xsltStylesheetPtr style) {
    xmlOutputBufferPtr buf;

    *doc_txt_ptr = NULL;
    *doc_txt_len = 0;
    if (result->children == NULL)
	return(0);

	buf = xmlAllocOutputBuffer(NULL);

    if (buf == NULL)
		return(-1);
    xsltSaveResultTo(buf, result, style);
    if (buf->conv != NULL) {
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
    thread_rwlock_create (&xslt_lock);
    thread_spin_create (&update_lock);
    xsl_threads = 0;
#ifdef MY_ALLOC
    xmlMemSetup(xmlMemFree, xmlMemMalloc, xmlMemRealloc, xmlMemoryStrdup);
#endif
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlSubstituteEntitiesDefault(1);
    xmlLoadExtDtdDefaultValue = 1;
}

void xslt_shutdown(void) {
    int i;

    for(i=0; i < CACHESIZE; i++) {
        free(cache[i].filename);
        free(cache[i].disposition);
        if(cache[i].stylesheet)
            xsltFreeStylesheet(cache[i].stylesheet);
    }

    thread_rwlock_destroy (&xslt_lock);
    thread_spin_destroy (&update_lock);
    xmlCleanupParser();
    xsltCleanupGlobals();
}


//
static void xsl_req_clear (xsl_req *x)
{
    xmlFreeDoc (x->doc);
    if (x->cache)
    {
        thread_rwlock_wlock (&xslt_lock);
        x->cache->flags &= ~XSLCACHE_PENDING;
        thread_rwlock_unlock (&xslt_lock);
    }
    free (x->filename);
    free (x);
}


static int xslt_sheet_check (stylesheet_cache_t *cached, time_t now)
{
    int rc = 0;
    do
    {
        if (cached->next_check > cached->cache_age)
            break;
        rc = -1;
        struct stat file;
        if (stat (cached->filename, &file))
        {
            WARN2 ("Error checking for stylesheet file \"%s\": %s", cached->filename, strerror(errno));
            break;
        }
        if (file.st_mtime == cached->last_modified)
        {
            //thread_spin_unlock (&update_lock);
            DEBUG1 ("file %s has same mtime, not modified", cached->filename);
            break;
        }
        xsltStylesheetPtr sheet = xsltParseStylesheetFile (XMLSTR(cached->filename));
        if (sheet)
        {
            INFO1 ("loaded stylesheet %s", cached->filename);
            if (sheet->mediaType && strcmp ((char*)(sheet->mediaType), "text/html") != 0)
            {
                // avoid this lookup for html pages
                char filename[100] = "file.";
                fserve_write_mime_ext ((char*)sheet->mediaType, filename + 5, sizeof(filename)-5);
                cache->disposition = strdup (cached->filename);
            }
            rc = 0;
            cached->stylesheet = sheet;
            cached->flags &= ~XSLCACHE_FAILED;
        }
    } while (0);
    cached->flags &= ~XSLCACHE_PENDING;
    cached->cache_age = now;
    cached->next_check = now + 60;
    return rc;

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


// requires write lock on xslt_lock on entry
//
static int xslt_cached (xsl_req *x, time_t now)
{
    time_t earliest = now;
    int i, evict = CACHESIZE;

    for (i=0; i < CACHESIZE; i++)
    {
        if (cache[i].filename == NULL)
            break;
        if (filename_cmp (x->filename, cache[i].filename) == 0)
            break;
        if (cache[i].cache_age > 0 && earliest > cache[i].cache_age && (cache[i].flags & XSLCACHE_PENDING) == 0)
        {
            earliest = cache[i].cache_age;
            evict = i;
            // DEBUG2 ("early is %ld, idx %d", earliest, evict);
        }
    }
    if (i == CACHESIZE && evict < CACHESIZE)
    {   // no matching filename, but something to replace
        i = evict;
        clear_cached_stylesheet (&cache[i], 1);
        // DEBUG1 ("dropped idx %d", i);
    }
    if (i < CACHESIZE)
    {
        if (cache[i].filename == NULL)
        {
            cache[i].filename = strdup (x->filename);
            cache[i].cache_age = 0;
            cache[i].flags |= XSLCACHE_PENDING;
        }
        if ((cache[i].flags & XSLCACHE_FAILED) && cache[i].next_check > now)
            return -1;
        if (cache[i].cache_age)
            cache[i].cache_age = now;   // update to keep around
        cache[i].flags &= ~XSLCACHE_FAILED;
        x->cache = &cache[i];
        DEBUG1 ("using cache slot %d", i);
        return 1;
    }
    return 0;
}


// requires xslt_lock before being called, released on return
//
static int xslt_send_response (xsl_req *x)
{
    xmlDocPtr           res;
    stylesheet_cache_t  *cached = x->cache;
    xsltStylesheetPtr   sheet = cached->stylesheet;
    char                **params = NULL;
    refbuf_t            *content = NULL;
    int len;

    client_t *client = x->client;
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

    res = xsltApplyStylesheet (sheet, x->doc, (const char **)params);
    free (params);
    client->aux_data = 0;

    ice_http_t http;

    if (res == NULL || xslt_SaveResultToBuf (&content, &len, res, sheet) < 0)
    {
        WARN1 ("problem applying stylesheet \"%s\"", x->filename);

        ice_http_setup_flags (&http, client, 404, 0, NULL);
        thread_rwlock_unlock (&xslt_lock);
    }
    else
    {
        ice_http_setup_flags (&http, client, 200, 0, NULL);

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

        http.in_length = len;
        if (cached->disposition)
            ice_http_printf (&http, "Content-Disposition", 0, "attachment; filename=\"%s\"", cached->disposition);

        thread_rwlock_unlock (&xslt_lock);
        ice_http_apply_block (&http, content);
    }
    xmlFreeDoc (res);
    return client_http_send (&http);   // adds to worker for sending
}


/* thread to read xsl file and add to the cache */
void *xslt_update (void *arg)
{
    xmlSetStructuredErrorFunc ("xsl/file", config_xml_parse_failure);
    xsltSetGenericErrorFunc ("", log_parse_failure);

    thread_spin_lock (&update_lock);
    for (client_t *client = xsl_clients; client; client = xsl_clients)
    {
        xsl_clients = client->next_on_worker;
        xsl_count--;
        thread_spin_unlock (&update_lock);

        xsl_req *x = (xsl_req *)client->aux_data;
        // DEBUG2 ("Processing client %ld, req for %s", client->connection.id, x->filename);
        client->next_on_worker = NULL;

        time_t now = time(NULL);
        if (client->connection.discon.time > now)
        {
            stylesheet_cache_t *cached = x->cache;
            thread_rwlock_wlock (&xslt_lock);
            if (xslt_sheet_check (cached, now) < 0)
            {
                cached->flags |= XSLCACHE_FAILED;
                thread_rwlock_unlock (&xslt_lock);
                WARN1 ("problem reading stylesheet \"%s\"", x->filename);
                //client->shared_data = NULL;
                client_send_404 (client, "Could not parse XSLT file");
            }
            else
            {
                //cached->flags &= ~XSLCACHE_PENDING;
                xslt_send_response (x);
            }
            x->cache = NULL;
        }
        xsl_req_clear (x);
        thread_spin_lock (&update_lock);
    }
    xsl_threads--;
    thread_spin_unlock (&update_lock);
    return NULL;
}


int xslt_client (client_t *client)
{
    xsl_req *x = (xsl_req*)client->aux_data;
    time_t now = client->worker->current_time.tv_sec;
    int rc = xslt_cached (x, now);
    do
    {
        if (rc < 0) break;
        if (client->connection.discon.time <= now)
            break;
        thread_spin_lock (&update_lock);
        if (rc && xsl_count < 50)
        {       // cache slot marked and queue not too bad
            client->next_on_worker = xsl_clients;
            xsl_clients = client;
            xsl_count++;
            if (xsl_threads < 5)
            {
                xsl_threads++;
                thread_spin_unlock (&update_lock);
                DEBUG1 ("Starting update thread for %s", x->filename);
                thread_create ("update xslt", xslt_update, NULL, THREAD_DETACHED);
                return 1;
            }
            int v = xsl_threads, q = xsl_count;
            thread_spin_unlock (&update_lock);
            DEBUG2 ("reschedule update, %d queued, %d running", q, v);
            return 1;
        }
        thread_spin_unlock (&update_lock);
        // DEBUG1 ("cache full, reschedule client %ld", client->connection.id);

        client->schedule_ms += 20;
        return 0;   // retry
    } while (0);
    xsl_req_clear (x);
    return client_send_404 (client, "failed on cache");
}


// entry point for xslt requests
//
int xslt_transform (xmlDocPtr doc, const char *xslfilename, client_t *client)
{
    xsl_req *x = calloc (1, sizeof (xsl_req));
    x->client = client;
    x->doc = doc;
    x->filename = strdup (xslfilename);
    client->aux_data = (uintptr_t)x;
    client->schedule_ms = client->worker->time_ms;
    client->ops = &xslt_ops;
    client->connection.discon.time = client->worker->current_time.tv_sec + 3;
    return client->ops->process (client);
}

