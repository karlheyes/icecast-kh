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

static int xslt_client (client_t *client);

typedef struct {
    char               *filename;
    char               *disposition;
    time_t             last_modified;
    time_t             cache_age;
    time_t             last_checked;
    xsltStylesheetPtr  stylesheet;
} stylesheet_cache_t;


typedef struct
{
    int index;
    client_t *client;
    xmlDocPtr doc;
    stylesheet_cache_t cache;
} xsl_req;


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


/* Keep it small... */
#define CACHESIZE       10

static stylesheet_cache_t cache[CACHESIZE];
static rwlock_t xslt_lock;
static spin_t update_lock;
int    xsl_updating;



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
    memset(cache, 0, sizeof(stylesheet_cache_t)*CACHESIZE);
    thread_rwlock_create (&xslt_lock);
    thread_spin_create (&update_lock);
    xsl_updating = 0;
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



/* thread to read xsl file and add to the cache */
void *xslt_update (void *arg)
{
    xsl_req *x = arg;
    client_t *client = x->client;
    worker_t *worker = client ? client->worker : NULL;
    char *fn = x->cache.filename;
    xsltStylesheetPtr sheet;

    xmlSetGenericErrorFunc ("", log_parse_failure);
    xsltSetGenericErrorFunc ("", log_parse_failure);

    sheet = x->cache.stylesheet = xsltParseStylesheetFile (XMLSTR(fn));
    if (sheet)
    {
        int i = x->index;
        stylesheet_cache_t old;

        if (client) fn = strdup (fn); // need to copy the filename if another lookup is to be done
        INFO1 ("loaded stylesheet %s", x->cache.filename);
        if (sheet->mediaType && strcmp ((char*)sheet->mediaType, "text/html") != 0)
        {
            // avoid this lookup for html pages
            const char _hdr[] = "Content-Disposition: attachment; filename=file.";
            const size_t _hdrlen = sizeof (_hdr);
            size_t len = _hdrlen + 12;
            char *filename = malloc (len); // enough for name and extension
            strcpy (filename, _hdr);
            fserve_write_mime_ext ((char*)sheet->mediaType, filename + _hdrlen - 1, len - _hdrlen - 3);
            strcat (filename, "\r\n");
            x->cache.disposition = filename;
        }
        thread_rwlock_wlock (&xslt_lock);
        memcpy (&old, &cache[i], sizeof (old));
        memcpy (&cache[i], &x->cache, sizeof (stylesheet_cache_t));
        thread_rwlock_unlock (&xslt_lock);
        memset (&x->cache, 0, sizeof (stylesheet_cache_t));
        free (old.filename);
        free (old.disposition);
        xsltFreeStylesheet (old.stylesheet);

        if (client)
        {
            x->cache.filename = fn;
            client->flags |= CLIENT_ACTIVE;
        }
    }
    else
    {
        WARN1 ("problem reading stylesheet \"%s\"", x->cache.filename);
        free (fn);
        xmlFreeDoc (x->doc);
        if (client)
        {
            client->shared_data = NULL;
            client_send_404 (client, "Could not parse XSLT file");
        }
        client = NULL;
        worker = NULL;
    }
    thread_spin_lock (&update_lock);
    xsl_updating--;
    thread_spin_unlock (&update_lock);
    if (worker) worker_wakeup (worker); // wakeup after the decrease or it may delay
    if (client == NULL) free (x);
    return NULL;
}


static int xslt_cached (const char *fn, client_t *client)
{
    worker_t *worker = client->worker;
    time_t now = worker->current_time.tv_sec, oldest = now;
    int evict = 0, i;
    xsl_req *x;
    struct stat file;

    for(i=0; i < CACHESIZE; i++)
    {
        if(cache[i].filename)
        {
#ifdef _WIN32
            if (stricmp(fn, cache[i].filename) == 0)
#else
            if (strcmp(fn, cache[i].filename) == 0)
#endif
            {
                if (now - cache[i].last_checked > 10)
                {
                    cache[i].last_checked = now;
                    if (stat (fn, &file))
                    {
                        WARN2("Error checking for stylesheet file \"%s\": %s", fn, strerror(errno));
                        return i;
                    }
                    DEBUG1 ("rechecked file time on %s", fn);

                    thread_spin_lock (&update_lock);
                    if (file.st_mtime > cache[i].last_modified)
                    {
                        cache[i].last_modified = file.st_mtime;
                        thread_spin_unlock (&update_lock);
                        break;
                    }
                    thread_spin_unlock (&update_lock);
                }
                cache[i].cache_age = now;
                return i;
            }
            if (oldest < cache[i].cache_age)
            {
                oldest = cache[i].cache_age;
                evict = i;
            }
            continue;
        }
        evict = i;
        break;
    }
    if (i == CACHESIZE)
    {
        if (stat (fn, &file))
        {
            WARN2("Error checking for stylesheet file \"%s\": %s", fn, strerror(errno));
            return -2;
        }
        i = evict;
    }
    x = calloc (1, sizeof (xsl_req));
    x->index = i;
    x->client = client;
    x->doc = client->shared_data;
    x->cache.filename = strdup (fn);
    x->cache.last_modified = file.st_mtime;
    x->cache.cache_age = now;
    x->cache.last_checked = now;
    client->shared_data = x;
    client->schedule_ms = worker->time_ms;
    client->ops = &xslt_ops;

    thread_spin_lock (&update_lock);
    if (xsl_updating < 3)
    {
        xsl_updating++;
        thread_spin_unlock (&update_lock);
        client->flags &= ~CLIENT_ACTIVE;
        thread_create ("update xslt", xslt_update, x, THREAD_DETACHED);
        return -1;
    }
    thread_spin_unlock (&update_lock);
    client->schedule_ms += 10;
    if ((client->flags & CLIENT_ACTIVE) == 0)
    {
        client->flags |= CLIENT_ACTIVE;
        worker_wakeup (worker);
    }
    return -1;
}



int xslt_transform (xmlDocPtr doc, const char *xslfilename, client_t *client)
{
    xmlDocPtr    res;
    xsltStylesheetPtr cur;
    int len, i;
    char **params = NULL;
    refbuf_t *content = NULL;

    client->shared_data = doc;
    thread_rwlock_rlock (&xslt_lock);
    i = xslt_cached (xslfilename, client);
    if (i < 0)
    {
        thread_rwlock_unlock (&xslt_lock);
        if (i == -2)
        {
            xmlFreeDoc (doc);
            client->shared_data = NULL;
            return client_send_404 (client, "Could not parse XSLT file");
        }
        return 0;
    }
    cur = cache[i].stylesheet;
    client->shared_data = NULL;
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

    res = xsltApplyStylesheet (cur, doc, (const char **)params);
    free (params);

    if (res == NULL || xslt_SaveResultToBuf (&content, &len, res, cur) < 0)
    {
        thread_rwlock_unlock (&xslt_lock);
        xmlFreeDoc (res);
        xmlFreeDoc (doc);
        WARN1 ("problem applying stylesheet \"%s\"", xslfilename);
        return client_send_404 (client, "XSLT problem");
    }
    else
    {
        /* the 100 is to allow for the hardcoded headers */
        refbuf_t *refbuf = refbuf_new (500);
        const char *mediatype = NULL;

        /* lets find out the content type to use */
        if (cur->mediaType)
            mediatype = (char *)cur->mediaType;
        else
        {
            /* check method for the default, a missing method assumes xml */
            if (cur->method && xmlStrcmp (cur->method, XMLSTR("html")) == 0)
                mediatype = "text/html";
            else
                if (cur->method && xmlStrcmp (cur->method, XMLSTR("text")) == 0)
                    mediatype = "text/plain";
                else
                    mediatype = "text/xml";
        }
        snprintf (refbuf->data, 500,
                "HTTP/1.0 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n%s"
                "Expires: Thu, 19 Nov 1981 08:52:00 GMT\r\n"
                "Cache-Control: no-store, no-cache, must-revalidate\r\n"
                "Pragma: no-cache\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Headers: Origin, Accept, X-Requested-With, Content-Type\r\n"
                "Access-Control-Allow-Methods: GET, OPTIONS, HEAD\r\n"
                "\r\n",
                mediatype, len,
                cache[i].disposition ? cache[i].disposition : "");

        thread_rwlock_unlock (&xslt_lock);
        client->respcode = 200;
        client_set_queue (client, NULL);
        client->refbuf = refbuf;
        refbuf->len = strlen (refbuf->data);
        refbuf->next = content;
    }
    xmlFreeDoc(res);
    xmlFreeDoc(doc);
    return fserve_setup_client (client);
}


int xslt_client (client_t *client)
{
    xsl_req *x = client->shared_data;
    int ret = xslt_transform (x->doc, x->cache.filename, client);
    free (x->cache.filename);
    free (x);
    return ret;
}

