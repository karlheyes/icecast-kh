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

#ifndef __UTIL_H__
#define __UTIL_H__

#include "compat.h"

#define XSLT_CONTENT 1
#define HTML_CONTENT 2

#define READ_ENTIRE_HEADER 1
#define READ_LINE 0

#define MAX_LINE_LEN 512

int util_timed_wait_for_fd(sock_t fd, int timeout);
int util_read_header(sock_t sock, char *buff, unsigned long len, int entire);
int util_check_valid_extension(const char *uri);
char *util_get_extension(const char *path);
char *util_get_path_from_uri(char *uri);
char *util_get_path_from_normalised_uri(const char *uri, int use_admin);
char *util_normalise_uri(const char *uri);
char *util_base64_encode(const char *data);
char *util_base64_decode(const char *input);
char *util_bin_to_hex(unsigned char *data, int len);

char *util_url_unescape(const char *src);
char *util_url_escape(const char *src);

int util_get_clf_time (char *buffer, unsigned len, time_t now);

/* String dictionary type, without support for NULL keys, or multiple
 * instances of the same key */
typedef struct _util_dict {
  char *key;
  char *val;
  struct _util_dict *next;
} util_dict;


struct node_IP_time
{
    char ip[24];
    union
    {
        time_t timeout;
        struct node_IP_time *next;
    } a;
};

struct cache_list_node
{
    char *content;
    struct cache_list_node *next;
};

struct _cache_contents;
typedef void (*cachefile_add_func)(struct _cache_contents *, const void *ip, time_t now);
typedef int  (*cachefile_compare_func)(void *, void *, void *);

typedef struct _cache_contents
{
    time_t                  file_recheck;
    time_t                  file_mtime;
    void                    *extra;
    avl_tree                *contents;
    // callback routines key insert and comparison
    cachefile_compare_func  compare;
    cachefile_add_func      add;

    void *deletions[9];
    int  deletions_count;
    char                    *filename;
} cache_file_contents;


util_dict *util_dict_new(void);
void util_dict_free(util_dict *dict);
/* dict, key must not be NULL. */
int util_dict_set(util_dict *dict, const char *key, const char *val);
const char *util_dict_get(util_dict *dict, const char *key);
char *util_dict_urlencode(util_dict *dict, char delim);

#ifndef HAVE_LOCALTIME_R
struct tm *localtime_r (const time_t *timep, struct tm *result);
#endif
#ifndef HAVE_GMTIME_R
struct tm *gmtime_r(const time_t *timep, struct tm *result);
#endif
char *util_conv_string (const char *string, const char *in_charset, const char *out_charset);

struct rate_calc *rate_setup (unsigned int samples, unsigned int ssec);
void rate_add_sum (struct rate_calc *calc, long value, uint64_t t, uint64_t *sum);
#define rate_add(A,B,C)   rate_add_sum((A),(B),(C), NULL);
long rate_avg (struct rate_calc *calc);
long rate_avg_shorten (struct rate_calc *calc, unsigned int t);
void rate_free (struct rate_calc *calc);
void rate_reduce (struct rate_calc *calc, unsigned int range);

int get_line(FILE *file, char *buf, size_t siz);
int util_expand_pattern (const char *mount, const char *pattern, char *buf, unsigned int *len_p);

void cached_file_init (cache_file_contents *cache, const char *filename, cachefile_add_func add, cachefile_compare_func compare);

int cached_treenode_free (void*x);
int cached_pattern_compare (const char *value, const char *pattern);

void cached_file_clear (cache_file_contents *cache);
int cached_pattern_search (cache_file_contents *cache, const char *line, time_t now);
void cached_file_recheck (cache_file_contents *cache, time_t now);
void cached_prune (cache_file_contents *cache);


#endif  /* __UTIL_H__ */
