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
    time_t             last_modified;
    time_t             cache_age;
    time_t             next_check;
    xsltStylesheetPtr  stylesheet;
} stylesheet_cache_t;


typedef struct
{
    int index;
    client_t *client;
    xmlDocPtr doc;
    stylesheet_cache_t cache;
} xsl_req;


static int xslt_client (client_t *client);
static int xslt_cached (const char *fn, stylesheet_cache_t *new_sheet, time_t now);
static int xslt_send_sheet (client_t *client, xmlDocPtr doc, int idx);


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
    memset (&cache[0], 0, sizeof cache);
    thread_rwlock_create (&xslt_lock);
    thread_spin_create (&update_lock);
    xsl_updating = 0;
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



/* thread to read xsl file and add to the cache */
void *xslt_update (void *arg)
{
    xsl_req *x = arg;
    client_t *client = x->client;
    char *fn = x->cache.filename;
    xsltStylesheetPtr sheet;

    xmlSetStructuredErrorFunc ("xsl/file", config_xml_parse_failure);
    xsltSetGenericErrorFunc ("", log_parse_failure);

    sheet = x->cache.stylesheet = xsltParseStylesheetFile (XMLSTR(fn));
    if (sheet)
    {
        int i;

        INFO1 ("loaded stylesheet %s", x->cache.filename);
        if (sheet->mediaType && strcmp ((char*)sheet->mediaType, "text/html") != 0)
        {
            // avoid this lookup for html pages
            const char _hdr[] = "Content-Disposition: attachment; filename=\"file.";
            const size_t _hdrlen = sizeof (_hdr);
            size_t len = _hdrlen + 12;
            char *filename = malloc (len); // enough for name and extension
            strcpy (filename, _hdr);
            fserve_write_mime_ext ((char*)sheet->mediaType, filename + _hdrlen - 1, len - _hdrlen - 4);
            strcat (filename, "\"\r\n");
            x->cache.disposition = filename;
        }
        // we now have a sheet, find and update.
        thread_rwlock_wlock (&xslt_lock);
        i = xslt_cached (fn, &x->cache, time(NULL));
        xslt_send_sheet (client, x->doc, i);
    }
    else
    {
        WARN1 ("problem reading stylesheet \"%s\"", x->cache.filename);
        free (fn);
        xmlFreeDoc (x->doc);
        free (x->cache.disposition);
        client->shared_data = NULL;
        client_send_404 (client, "Could not parse XSLT file");
    }
    thread_spin_lock (&update_lock);
    xsl_updating--;
    thread_spin_unlock (&update_lock);
    free (x);
    return NULL;
}


static int xslt_cached (const char *fn, stylesheet_cache_t *new_sheet, time_t now)
{
    time_t oldest = now + 100000;
    int evict = CACHESIZE, i;

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
                evict = i;
                if (new_sheet)
                    break;
                return i;
            }
            if (oldest > cache[i].cache_age)
            {
                oldest = cache[i].cache_age;
                evict = i;
            }
            continue;
        }
        evict = i;
        break;
    }
    if (new_sheet) // callback from xslt reader thread, should be writelocked
    {
        stylesheet_cache_t old;
        //DEBUG2 ("replace %d with %s", evict, new_sheet->filename);
        memcpy (&old, &cache[evict], sizeof (old));
        memcpy (&cache[evict], new_sheet, sizeof (stylesheet_cache_t));
        memset (new_sheet, 0, sizeof (stylesheet_cache_t));
        free (old.filename);
        free (old.disposition);
        if (old.stylesheet) xsltFreeStylesheet (old.stylesheet);
        return evict;
    }
    return -1;
}



static int xslt_req_sheet (client_t *client, xmlDocPtr doc, const char *fn, int i)
{
    xsl_req     *x = client->shared_data;
    worker_t    *worker = client->worker;
    time_t      now = worker->current_time.tv_sec;
    struct stat file;

    // DEBUG4 ("idx %d, fn %s, check %ld/%ld", i, i==CACHESIZE?"XXX":cache[i].filename, (long)cache[i].next_check, now);
    while (i < CACHESIZE && i >= 0 && cache[i].filename && cache[i].next_check >= now)
    {
        thread_spin_lock (&update_lock);
        if (now == cache[i].next_check)
        {
            cache[i].next_check = now + 20;
            thread_spin_unlock (&update_lock);
            break; // jump out of loop to do xsl load
        }
        thread_spin_unlock (&update_lock);
        return i;
    }
    if (stat (fn, &file))
    {
        WARN2("Error checking for stylesheet file \"%s\": %s", fn, strerror(errno));
        return -1;
    }
    if (i < CACHESIZE && i >= 0)
    {
        thread_spin_lock (&update_lock);
        cache[i].next_check = now + 20;
        if (file.st_mtime == cache[i].last_modified)
        {
            thread_spin_unlock (&update_lock);
            DEBUG1 ("file %s has same mtime, not modified", cache[i].filename);
            return i;
        }
        thread_spin_unlock (&update_lock);
        // DEBUG3 ("idx %d, time is %ld, %ld", i, (long)(cache[i].last_modified), (long)file.st_mtime);
    }
    if (x == NULL)
    {
        x = calloc (1, sizeof (xsl_req));
        x->index = i;
        x->client = client;
        x->doc = doc;
        x->cache.filename = strdup (fn);
        x->cache.last_modified = file.st_mtime;
        x->cache.cache_age = now;
        x->cache.next_check = now + 20;
        client->shared_data = x;
        client->schedule_ms = worker->time_ms;
        client->ops = &xslt_ops;
    }

    thread_spin_lock (&update_lock);
    if (xsl_updating < 3)
    {
        xsl_updating++;
        thread_spin_unlock (&update_lock);
        client->flags &= ~CLIENT_ACTIVE;
        // DEBUG1 ("Starting update thread for %s", x->cache.filename);
        thread_create ("update xslt", xslt_update, x, THREAD_DETACHED);
        return CACHESIZE;
    }
    thread_spin_unlock (&update_lock);
    // DEBUG1 ("Delaying update thread for %s", x->cache.filename);
    client->schedule_ms += 10;
    if ((client->flags & CLIENT_ACTIVE) == 0)
    {
        client->flags |= CLIENT_ACTIVE;
        worker_wakeup (worker);
    }
    return CACHESIZE;
}


int xslt_transform (xmlDocPtr doc, const char *xslfilename, client_t *client)
{
    int     i, ret;
    xsl_req *x;

    thread_rwlock_rlock (&xslt_lock);
    i = xslt_cached (xslfilename, NULL, client->worker->current_time.tv_sec);
    i = xslt_req_sheet (client, doc, xslfilename, i);
    x = client->shared_data;
    switch (i)
    {
        case -1:
            thread_rwlock_unlock (&xslt_lock);
            xmlFreeDoc (doc);
            client->shared_data = NULL;
            ret = client_send_404 (client, "Could not parse XSLT file");
            break;
        case CACHESIZE:   // delayed
            thread_rwlock_unlock (&xslt_lock);
            return 0;
        default:  // found it and ok to use
            ret = xslt_send_sheet (client, doc, i);
            break;
    }
    if (x)
    {
        free (x->cache.filename);
        free (x->cache.disposition);
        free (x);
    }
    return ret;
}


// requires xslt_lock before being called, released on return
static int xslt_send_sheet (client_t *client, xmlDocPtr doc, int idx)
{
    xmlDocPtr           res;
    xsltStylesheetPtr   cur = cache [idx].stylesheet;
    char                **params = NULL;
    refbuf_t            *content = NULL;
    int len;

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
    client->shared_data = NULL;

    if (res == NULL || xslt_SaveResultToBuf (&content, &len, res, cur) < 0)
    {
        thread_rwlock_unlock (&xslt_lock);
        xmlFreeDoc (res);
        xmlFreeDoc (doc);
        WARN1 ("problem applying stylesheet \"%s\"", cache [idx].filename);
        return client_send_404 (client, "XSLT problem");
    }
    else
    {
        /* the 100 is to allow for the hardcoded headers */
        refbuf_t *refbuf = refbuf_new (1000);
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
        int bytes = snprintf (refbuf->data, 1000,
                "HTTP/1.0 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n%s"
                "Expires: Thu, 19 Nov 1981 08:52:00 GMT\r\n"
                "Cache-Control: no-store, no-cache, must-revalidate\r\n"
                "Pragma: no-cache\r\n%s\r\n",
                mediatype, len,
                cache[idx].disposition ? cache[idx].disposition : "", client_keepalive_header (client));

        thread_rwlock_unlock (&xslt_lock);
        if (bytes < 1000)
            client_add_cors (client, refbuf->data+bytes, 1000-bytes);
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
    // DEBUG1 ("delayed update for %s, trying to update now", x->cache.filename);
    return xslt_transform (x->doc, x->cache.filename, client);
}

