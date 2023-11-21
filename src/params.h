/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2023-2023,  Karl Heyes <karl@kheyes.plus.com>
 */

/*
 * External API for using the parameter building routines. Initially for HTTP
 * and POST data.
 */

#ifndef __PARAMS_H__
#define __PARAMS_H__


typedef struct _ice_http_t              ice_http_t;
typedef struct _ice_param_t             ice_param_t;

typedef struct _ice_param_t
{
    struct _ice_param_t *next;
    uint32_t    flags;
    uint16_t    name_len;
    uint16_t    value_len;
    char        *name;
    char        *value;
    int         (*callback)(void *arg, ice_param_t *curr);
    void        *callback_arg;         // sent in arg for callback
} ice_param_t;


typedef struct  _ice_params_t
{
    ice_param_t *head;          // linked list
    uint32_t    len;
    uint32_t    flags;

    uint32_t    extra_len;       // extra space to allocate

    // info for the param separation
    uint8_t     entry_end_len;
    uint8_t     entry_div_len;

    char        entry_end[4];  // may need to increase in future but fine for now
    char        entry_div[4];
} ice_params_t;


typedef struct
{
    int         status;
    const char  *msg;
} ice_http_status_t;


typedef struct  _ice_http_t
{
    ice_params_t headers;

    char        respcode[4];

    // placeholders quicker lookup
    uint8_t     in_major;
    uint8_t     in_minor;
    off_t       in_length; // informational for reporting in headers

    char        *msg;
    const char  *in_connection;
    const char  *in_origin;
    char        *in_realm;
    char        *in_server_id;

    client_t    *client;

    ice_http_status_t  conn;
} ice_http_t;

// for ice_param_t
#define PARAM_PASS                              0
#define PARAM_NOCOPY                            (1<<0)
#define PARAM_AS                                (1<<1)          // ignore any default encodings
#define PARAM_ESC                               (1<<2)          // escape encode this param

#define PARAM_CONST                             (1<<8)          // fixed
#define PARAM_MULTI                             (1<<9)          // allow duplicate param

// for ice_params_t
#define PARAMS_ESC                              (1<<10)         // use escape encoding for all tags by default

// for ice_http_t
#define ICE_HTTP_REQUEST                        (1<<0)
#define ICE_HTTP_WILDCARD_ORIGIN                (1<<1)
#define ICE_HTTP_USE_ICY                        (1<<2)
#define ICE_HTTP_CONN_CLOSE                     (1<<3)


#define ICE_HTTP_INIT   ((ice_http_t){ .client = NULL })

int  ice_http_setup_flags (ice_http_t *http, client_t *client, int status, unsigned int flags, const char *statusmsg);

int  ice_http_apply_cfg (ice_http_t *http, struct _config_http_header_tag *h);
int  ice_http_apply (ice_http_t *http, const ice_param_t *header);
int  ice_http_apply_block (ice_http_t *http, refbuf_t *ref);
void ice_http_clear (ice_http_t *http);
int  ice_http_complete (ice_http_t *http);
int  ice_http_send (ice_http_t *http);
int  ice_http_printf (ice_http_t *http, const char *name, int flags, const char *fmt, ...) __attribute__ ((format (printf, 4, 5)));

int  ice_params_setup (ice_params_t *p, const char *divider, const char *separator, unsigned int flags);
int  ice_params_printf (ice_params_t *p, const char *name, int flags, const char *fmt, ...) __attribute__ ((format (printf, 4, 5)));
int  ice_params_apply (ice_params_t *pm, const ice_param_t *header);
void ice_params_clear (ice_params_t *params);
refbuf_t *ice_params_complete (ice_params_t *pm);

#endif
