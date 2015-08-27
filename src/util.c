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
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef HAVE_POLL
#include <sys/poll.h>
#endif
#else
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <unistd.h>
#endif

#include "net/sock.h"
#include "thread/thread.h"

#include "cfgfile.h"
#include "util.h"
#include "refbuf.h"
#include "connection.h"
#include "client.h"
#include "global.h"

#define CATMODULE "util"

#include "logging.h"

struct rate_calc_node
{
    int64_t index;
    uint64_t value;
    struct rate_calc_node *next;
};

struct rate_calc
{
    int64_t total;
    struct rate_calc_node *current;
    spin_t lock;
    unsigned int samples;
    unsigned int ssec;
    unsigned int blocks;
};


/* Abstract out an interface to use either poll or select depending on which
 * is available (poll is preferred) to watch a single fd.
 *
 * timeout is in milliseconds.
 *
 * returns > 0 if activity on the fd occurs before the timeout.
 *           0 if no activity occurs
 *         < 0 for error.
 */
int util_timed_wait_for_fd(sock_t fd, int timeout)
{
#ifdef HAVE_POLL
    struct pollfd ufds;

    ufds.fd = fd;
    ufds.events = POLLIN;
    ufds.revents = 0;

    return poll(&ufds, 1, timeout);
#else
    fd_set rfds;
    struct timeval tv, *p=NULL;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    if(timeout >= 0) {
        tv.tv_sec = timeout/1000;
        tv.tv_usec = (timeout % 1000)*1000;
        p = &tv;
    }
    return select(fd+1, &rfds, NULL, NULL, p);
#endif
}

int util_read_header(sock_t sock, char *buff, unsigned long len, int entire)
{
    int read_bytes, ret;
    unsigned long pos;
    char c;
    ice_config_t *config;
    int header_timeout;

    config = config_get_config();
    header_timeout = config->header_timeout;
    config_release_config();

    read_bytes = 1;
    pos = 0;
    ret = 0;

    while ((read_bytes == 1) && (pos < (len - 1))) {
        read_bytes = 0;

        if (util_timed_wait_for_fd(sock, header_timeout*1000) > 0) {

            if ((read_bytes = recv(sock, &c, 1, 0))) {
                if (c != '\r') buff[pos++] = c;
                if (entire) {
                    if ((pos > 1) && (buff[pos - 1] == '\n' && 
                                      buff[pos - 2] == '\n')) {
                        ret = 1;
                        break;
                    }
                }
                else {
                    if ((pos > 1) && (buff[pos - 1] == '\n')) {
                        ret = 1;
                        break;
                    }
                }
            }
        } else {
            break;
        }
    }

    if (ret) buff[pos] = '\0';
    
    return ret;
}

char *util_get_extension(const char *path) {
    char *ext = strrchr(path, '.');

    if(ext == NULL)
        return "";
    else
        return ext+1;
}

int util_check_valid_extension(const char *uri) {
    int    ret = 0;
    char    *p2;

    if (uri) {
        p2 = strrchr(uri, '.');
        if (p2) {
            p2++;
            if (strncmp(p2, "xsl", strlen("xsl")) == 0) {
                /* Build the full path for the request, concatenating the webroot from the config.
                ** Here would be also a good time to prevent accesses like '../../../../etc/passwd' or somesuch.
                */
                ret = XSLT_CONTENT;
            }
            if (strncmp(p2, "htm", strlen("htm")) == 0) {
                /* Build the full path for the request, concatenating the webroot from the config.
                ** Here would be also a good time to prevent accesses like '../../../../etc/passwd' or somesuch.
                */
                ret = HTML_CONTENT;
            }
            if (strncmp(p2, "html", strlen("html")) == 0) {
                /* Build the full path for the request, concatenating the webroot from the config.
                ** Here would be also a good time to prevent accesses like '../../../../etc/passwd' or somesuch.
                */
                ret = HTML_CONTENT;
            }

        }
    }
    return ret;
}

static int hex(char c)
{
    if(c >= '0' && c <= '9')
        return c - '0';
    else if(c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else if(c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else
        return -1;
}

static int verify_path(char *path) {
    int dir = 0, indotseq = 0;

    while(*path) {
        if(*path == '/' || *path == '\\') {
            if(indotseq)
                return 0;
            if(dir)
                return 0;
            dir = 1;
            path++;
            continue;
        }

        if(dir || indotseq) {
            if(*path == '.')
                indotseq = 1;
            else
                indotseq = 0;
        }
        
        dir = 0;
        path++;
    }

    return 1;
}

char *util_get_path_from_uri(char *uri) {
    char *path = util_normalise_uri(uri);
    char *fullpath;

    if(!path)
        return NULL;
    else {
        fullpath = util_get_path_from_normalised_uri(path, 0);
        free(path);
        return fullpath;
    }
}

char *util_get_path_from_normalised_uri(const char *uri, int use_admin)
{
    char *fullpath;
    char *root;
    ice_config_t *config = config_get_config();

    if (use_admin)
        root = config->adminroot_dir;
    else
        root = config->webroot_dir;

    fullpath = malloc(strlen(uri) + strlen(root) + 1);
    if (fullpath)
        sprintf (fullpath, "%s%s", root, uri);
    config_release_config();

    return fullpath;
}

static char hexchars[16] = {
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
};

static char safechars[256] = {
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  0,  0,  0,
      0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
      1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  0,  0,
      0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
      1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
};

char *util_url_escape (const char *src)
{
    int len, i, j=0;
    char *dst;
    unsigned char *source;

    if (src == NULL)
        return strdup ("");
    len = strlen(src);
    /* Efficiency not a big concern here, keep the code simple/conservative */
    dst = calloc(1, len*3 + 1); 
    source = (unsigned char *)src;

    for(i=0; i < len; i++) {
        if(safechars[source[i]]) {
            dst[j++] = source[i];
        }
        else {
            dst[j] = '%';
            dst[j+1] = hexchars[ (source[i] >> 4) & 0xf ];
            dst[j+2] = hexchars[ source[i] & 0xf ];
            j+= 3;
        }
    }

    dst[j] = 0;
    return dst;
}


static int unescape_code (const char *src)
{
    if (hex (src[0]) == -1 || hex (src[1]) == -1)
        return -1;
    return (hex (src[0]) << 4)  + hex (src[1]);
}


char *util_url_unescape (const char *src)
{
    int len = strlen(src);
    char *decoded;
    int i, v;
    char *dst;

    decoded = calloc(1, len + 1);

    dst = decoded;

    for(i=0; i < len; i++)
    {
        if (src[i] == '%' && i+2 < len)
        {
            v = unescape_code (src + i +1);
            if (v >= 0 && isprint(v))
            {
                *dst++ = (char)v;
                i += 2;
                continue;
            }
        }
        *dst++ = src[i];
    }

    *dst = 0; /* null terminator */

    return decoded;
}


/* Get an absolute path (from the webroot dir) from a URI. Return NULL if the
 * path contains 'disallowed' sequences like foo/../ (which could be used to
 * escape from the webroot) or if it cannot be URI-decoded.
 * Caller should free the path.
 */
char *util_normalise_uri(const char *uri) {
    char *path;

    if(uri[0] != '/')
        return NULL;

    path = util_url_unescape(uri);

    if(path == NULL) {
        WARN1("Error decoding URI: %s\n", uri);
        return NULL;
    }

    while (1)
    {
        char *s = strstr (path, "//");
        if (s == NULL) break;
        memmove (path+1, path+2, strlen (path+2)+1);
    }
    /* We now have a full URI-decoded path. Check it for allowability */
    if(verify_path(path))
        return path;
    else {
        WARN1("Rejecting invalid path \"%s\"", path);
        free(path);
        return NULL;
    }
}

static char base64table[64] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
};

static signed char base64decode[256] = {
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
     52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -1, -2, -2,
     -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
     -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
     41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
};

char *util_bin_to_hex(unsigned char *data, int len)
{
    char *hex = malloc(len*2 + 1);
    int i;

    for(i = 0; i < len; i++) {
        hex[i*2] = hexchars[(data[i]&0xf0) >> 4];
        hex[i*2+1] = hexchars[data[i]&0x0f];
    }

    hex[len*2] = 0;

    return hex;
}

/* This isn't efficient, but it doesn't need to be */
char *util_base64_encode(const char *data)
{
    int len = strlen(data);
    char *out = malloc(len*4/3 + 4);
    char *result = out;
    int chunk;

    while(len > 0) {
        chunk = (len >3)?3:len;
        *out++ = base64table[(*data & 0xFC)>>2];
        *out++ = base64table[((*data & 0x03)<<4) | ((*(data+1) & 0xF0) >> 4)];
        switch(chunk) {
            case 3:
                *out++ = base64table[((*(data+1) & 0x0F)<<2) | ((*(data+2) & 0xC0)>>6)];
                *out++ = base64table[(*(data+2)) & 0x3F];
                break;
            case 2:
                *out++ = base64table[((*(data+1) & 0x0F)<<2)];
                *out++ = '=';
                break;
            case 1:
                *out++ = '=';
                *out++ = '=';
                break;
        }
        data += chunk;
        len -= chunk;
    }
    *out = 0;

    return result;
}

char *util_base64_decode(const char *data)
{
    const unsigned char *input = (const unsigned char *)data;
    int len = strlen (data);
    char *out = malloc(len*3/4 + 5);
    char *result = out;
    signed char vals[4];

    while(len > 0) {
        if(len < 4)
        {
            free(result);
            return NULL; /* Invalid Base64 data */
        }

        vals[0] = base64decode[*input++];
        vals[1] = base64decode[*input++];
        vals[2] = base64decode[*input++];
        vals[3] = base64decode[*input++];

        if(vals[0] < 0 || vals[1] < 0 || vals[2] < -1 || vals[3] < -1) {
            len -= 4;
            continue;
        }

        *out++ = vals[0]<<2 | vals[1]>>4;
        /* vals[3] and (if that is) vals[2] can be '=' as padding, which is
           looked up in the base64decode table as '-1'. Check for this case,
           and output zero-terminators instead of characters if we've got
           padding. */
        if(vals[2] >= 0)
            *out++ = ((vals[1]&0x0F)<<4) | (vals[2]>>2);
        else
            *out++ = 0;

        if(vals[3] >= 0)
            *out++ = ((vals[2]&0x03)<<6) | (vals[3]);
        else
            *out++ = 0;

        len -= 4;
    }
    *out = 0;

    return result;
}

util_dict *util_dict_new(void)
{
    return (util_dict *)calloc(1, sizeof(util_dict));
}

void util_dict_free(util_dict *dict)
{
    util_dict *next;

    while (dict) {
        next = dict->next;

        if (dict->key)
            free (dict->key);
        if (dict->val)
            free (dict->val);
        free (dict);

        dict = next;
    }
}

const char *util_dict_get(util_dict *dict, const char *key)
{
    while (dict) {
        if (!strcmp(key, dict->key))
            return dict->val;
        dict = dict->next;
    }
    return NULL;
}

int util_dict_set(util_dict *dict, const char *key, const char *val)
{
    util_dict *prev;

    if (!dict || !key) {
        ERROR0("NULL values passed to util_dict_set()");
        return 0;
    }

    prev = NULL;
    while (dict) {
        if (!dict->key || !strcmp(dict->key, key))
            break;
        prev = dict;
        dict = dict->next;
    }

    if (!dict) {
        dict = util_dict_new();
        if (!dict) {
            ERROR0("unable to allocate new dictionary");
            return 0;
        }
        if (prev)
            prev->next = dict;
    }

    if (dict->key)
        free (dict->val);
    else if (!(dict->key = strdup(key))) {
        if (prev)
            prev->next = NULL;
        util_dict_free (dict);

        ERROR0("unable to allocate new dictionary key");
        return 0;
    }

    dict->val = strdup(val);
    if (!dict->val) {
        ERROR0("unable to allocate new dictionary value");
        return 0;
    }

    return 1;
}

/* given a dictionary, URL-encode each val and 
   stringify it in order as key=val&key=val... if val 
   is set, or just key&key if val is NULL.
  TODO: Memory management needs overhaul. */
char *util_dict_urlencode(util_dict *dict, char delim)
{
    char *res, *tmp;
    char *enc;
    int start = 1;

    for (res = NULL; dict; dict = dict->next) {
        /* encode key */
        if (!dict->key)
            continue;
        if (start) {
            if (!(res = malloc(strlen(dict->key) + 1))) {
                return NULL;
            }
            sprintf(res, "%s", dict->key);
            start = 0;
        } else {
            if (!(tmp = realloc(res, strlen(res) + strlen(dict->key) + 2))) {
                free(res);
                return NULL;
            } else
                res = tmp;
            sprintf(res + strlen(res), "%c%s", delim, dict->key);
        }

        /* encode value */
        if (!dict->val)
            continue;
        if (!(enc = util_url_escape(dict->val))) {
            free(res);
            return NULL;
        }

        if (!(tmp = realloc(res, strlen(res) + strlen(enc) + 2))) {
            free(enc);
            free(res);
            return NULL;
        } else
            res = tmp;
        sprintf(res + strlen(res), "=%s", enc);
        free(enc);
    }

    return res;
}

#ifndef HAVE_LOCALTIME_R
struct tm *localtime_r (const time_t *timep, struct tm *result)
{
#ifdef _WIN32
     struct tm *tm = localtime (timep); // win32 uses TLS for this, so we can copy without a lock
     memcpy (result, tm, sizeof (*result));
#else
     struct tm *tm;
     static mutex_t localtime_lock;
     static int initialised = 0;

     if (initialised == 0)
     {
         thread_mutex_create (&localtime_lock);
         initialised = 1;
     }
     thread_mutex_lock (&localtime_lock);
     tm = localtime (timep);
     memcpy (result, tm, sizeof (*result));
     thread_mutex_unlock (&localtime_lock);
#endif
     return result;
}
#endif


#ifndef HAVE_GMTIME_R
struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
#ifdef _WIN32
    if (gmtime_s (result, timep) == 0)
        return result;
    return NULL;
#else
    struct tm *tm;
    static mutex_t gmtime_lock;
    static int initialised = 0;

    if (initialised == 0)
    {
        thread_mutex_create (&gmtime_lock);
        initialised = 1;
    }
    thread_mutex_lock (&gmtime_lock);
    tm = gmtime (timep);
    memcpy (result, tm, sizeof (*result));
    thread_mutex_unlock (&gmtime_lock);
    return result;
#endif
}
#endif


/* helper function for converting a passed string in one character set to another
 * we use libxml2 for this
 */
char *util_conv_string (const char *string, const char *in_charset, const char *out_charset)
{
    xmlCharEncodingHandlerPtr in, out;
    char *ret = NULL;

    if (string == NULL || in_charset == NULL || out_charset == NULL)
        return NULL;

    in  = xmlFindCharEncodingHandler (in_charset);
    out = xmlFindCharEncodingHandler (out_charset);

    if (in && out)
    {
        xmlBufferPtr orig = xmlBufferCreate ();
        xmlBufferPtr utf8 = xmlBufferCreate ();
        xmlBufferPtr conv = xmlBufferCreate ();

        INFO2 ("converting metadata from %s to %s", in_charset, out_charset);
        xmlBufferCCat (orig, string);
        if (xmlCharEncInFunc (in, utf8, orig) > 0)
        {
            xmlCharEncOutFunc (out, conv, NULL);
            if (xmlCharEncOutFunc (out, conv, utf8) >= 0)
                ret = strdup ((const char *)xmlBufferContent (conv));
        }
        xmlBufferFree (orig);
        xmlBufferFree (utf8);
        xmlBufferFree (conv);
    }
    xmlCharEncCloseFunc (in);
    xmlCharEncCloseFunc (out);

    return ret;
}


/* setup a rate block of so many seconds, so that an average can be
 * determined of that range
 */
struct rate_calc *rate_setup (unsigned int samples, unsigned int ssec)
{
    struct rate_calc *calc = calloc (1, sizeof (struct rate_calc));

    if (calc == NULL || samples < 2 || ssec == 0)
    {
        free (calc);
        return NULL;
    }
    thread_spin_create (&calc->lock);
    calc->samples = samples;
    calc->ssec = ssec;
    return calc;
}

static void rate_purge_entries (struct rate_calc *calc, uint64_t cutoff)
{
    struct rate_calc_node *node = calc->current->next, *to_free = NULL;
    int count = calc->blocks;

    while (count && node->index <= cutoff)
    {
        struct rate_calc_node *to_go = node;
        if (node == NULL || node->next == NULL)
            abort();
        count--;
        if (count)
        {
            node = node->next;
            calc->current->next = node;
            calc->total -= to_go->value;
        }
        else
        {
             calc->current = NULL;
             calc->total = 0;
        }
        to_go->next = to_free;
        to_free = to_go;
    }
    calc->blocks = count;
    thread_spin_unlock (&calc->lock);
    while (to_free)
    {
        struct rate_calc_node *to_go = to_free;
        to_free = to_go->next;
        free (to_go);
    }
}

/* add a value to sampled data, t is used to determine which sample
 * block the sample goes into.
 */
void rate_add (struct rate_calc *calc, long value, uint64_t sid) 
{
    uint64_t cutoff;

    thread_spin_lock (&calc->lock);
    cutoff = sid - calc->samples;
    if (value == 0 && calc->current && calc->current->value == 0)
    {
        calc->current->index = sid; /* update the timestamp if 0 already present */
        rate_purge_entries (calc, cutoff);
        return;
    }
    while (1)
    {
        struct rate_calc_node *next = NULL, *node;
        int to_insert = 1;
        if (calc->current)
        {
            if (sid == calc->current->index)
            {
                if (value)
                {
                    calc->current->value += value;
                    calc->total += value;
                }
                thread_spin_unlock (&calc->lock);
                return;
            }
            next = calc->current->next;
            if (cutoff > next->index)
                to_insert = 0;
        }
        if (to_insert)
        {
            thread_spin_unlock (&calc->lock);
            node = calloc (1, sizeof (*node));

            node->index = sid;
            thread_spin_lock (&calc->lock);
            if ((calc->current && calc->current->next != next) ||
                    (calc->current == NULL && next != NULL))
            {
                thread_spin_unlock (&calc->lock);
                free (node);
                thread_spin_lock (&calc->lock);
                continue;
            }
            node->next = next ? next : node;
            if (calc->current)  calc->current->next = node;
            calc->current = node;
            calc->blocks++;
        }
        calc->current->value += value;
        break;
    }
    calc->total += value;
    rate_purge_entries (calc, cutoff);
}


/* return the average sample value over all the blocks except the 
 * current one, as that may be incomplete
 */
long rate_avg (struct rate_calc *calc)
{
    long total = 0, ssec = 1;
    float range = 1.0;

    if (calc == NULL)
        return total;
    thread_spin_lock (&calc->lock);
    if (calc && calc->blocks > 1)
    {
        range = (float)(calc->current->index - calc->current->next->index) + 1;
        if (range < 1)
            range = 1;
        total = calc->total;
        ssec = calc->ssec;
    }
    thread_spin_unlock (&calc->lock);
    return (long)(total / range * ssec);
}


/* reduce the samples used to calculate average */
void rate_reduce (struct rate_calc *calc, unsigned int range)
{
    if (calc == NULL)
        return;
    thread_spin_lock (&calc->lock);
    if (range && calc->blocks > 1)
        rate_purge_entries (calc, calc->current->index - range);
    else
        thread_spin_unlock (&calc->lock);
}


void rate_free (struct rate_calc *calc)
{
    if (calc == NULL)
        return;
    if (calc->current)
    {
        struct rate_calc_node *node = calc->current->next;
        calc->current->next = NULL;
        while (node)
        {
            struct rate_calc_node *to_go = node;
            node = node->next;
            free (to_go);
        }
    }
    thread_spin_destroy (&calc->lock);
    free (calc);
}


int get_line(FILE *file, char *buf, size_t siz)
{
    if(fgets(buf, (int)siz, file)) {
        size_t len = strlen(buf);
        if(len > 0 && buf[len-1] == '\n') {
            buf[--len] = 0;
            if(len > 0 && buf[len-1] == '\r')
                buf[--len] = 0;
        }
        return 1;
    }
    return 0;
}

#ifdef _MSC_VER
int msvc_snprintf (char *buf, int len, const char *fmt, ...)
{
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = _vsnprintf (buf, len, fmt, ap);
    if (ret < 0)
        buf[len-1] = 0;
    va_end(ap);
    return ret;
}
int msvc_vsnprintf (char *buf, int len, const char *fmt, va_list ap)
{
    int ret = _vsnprintf (buf, len, fmt, ap);
    if (ret < 0)
        buf[len-1] = 0;
    return ret;
}
#endif

#ifdef WIN32
/* Since strftime's %z option on win32 is different, we need
   to go through a few loops to get the same info as %z */
int util_get_clf_time (char *buffer, unsigned len, time_t now)
{
    char        sign = '+';
    int time_days, time_hours, time_tz;
    int tempnum1, tempnum2;
    struct tm thetime;
    struct tm gmt;
    char        timezone_string [30];

    gmtime_r (&now, &gmt);
    localtime_r (&now, &thetime);

    time_days = thetime.tm_yday - gmt.tm_yday;

    if (time_days < -1) {
        tempnum1 = 24;
    }
    else {
        tempnum1 = 1;
    }
    if (tempnum1 < time_days) {
       tempnum2 = -24;
    }
    else {
        tempnum2 = time_days*24;
    }

    time_hours = (tempnum2 + thetime.tm_hour - gmt.tm_hour);
    time_tz = time_hours * 60 + thetime.tm_min - gmt.tm_min;

    if (time_tz < 0) {
        sign = '-';
        time_tz = -time_tz;
    }

    snprintf (timezone_string, sizeof (timezone_string),
            "%%d/%%b/%%Y:%%H:%%M:%%S %c%.2d%.2d", sign, time_tz / 60, time_tz % 60);

    return strftime (buffer, len, timezone_string, &thetime);
}
#else

int util_get_clf_time (char *buffer, unsigned len, time_t now)
{
    struct tm thetime;
    localtime_r (&now, &thetime);
    return strftime (buffer, len, "%d/%b/%Y:%H:%M:%S %z", &thetime);
}

#endif


/* this routine tales the pattern and expands it with mount and fills the result in buffer.
 * the len_p initially indicates the max buffer size and is returned as the amount written,
 * the mount is initially copied allowing to a loop where the buffer is later provided to
 * mount on a subsequent invocation.
 */
int util_expand_pattern (const char *mount, const char *pattern, char *buf, unsigned int *len_p)
{
   unsigned int max = (*len_p)-1, i = 0, j = 0;
   int len = mount ? strlen (mount) : 0;
   char *mnt;

   if (pattern == NULL || mount == NULL)
   {
       int r = snprintf (buf, *len_p, "%s", mount ? mount : pattern);
       if (r < 1) return -1;
       *len_p = (unsigned int)r;
       return 0;
   }
   if (len && mount[0] == '/')
   {
      mount++;  // lets skip over the first slash if there is one
      len--;
   }
   if (len < 1 || len > max) return -1;

   mnt = strdup (mount);
   while (i < max)
   {
      if (pattern[j] == 0) break;
      if (pattern[j] == '$')
      {
          if (strncmp (pattern+j, "${mount}", 8) == 0)
          {
              strncpy (buf+i, mnt, len);
              j += 8;
              i += len;
              continue;
          }
          // other tags to expand?
      }
      buf [i++] = pattern [j++];
   }
   buf [i] = '\0';
   *len_p = i;
   free (mnt);
   return 0;
}

