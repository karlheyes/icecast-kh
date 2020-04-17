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

#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#include <sys/types.h>
#include <time.h>
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

struct source_tag;
struct ice_config_tag;
typedef struct connection_tag connection_t;

#include "compat.h"
#include "httpp/httpp.h"
#include "net/sock.h"

extern struct _client_functions http_request_ops;

struct connection_tag
{
    uint64_t id;

    time_t con_time;
    struct {
        time_t      time;
        uint64_t    offset;
    } discon;
    uint64_t sent_bytes;

    sock_t sock;
    unsigned int chunk_pos; // for short writes on chunk size line
    char error;
    unsigned char readchk;

#ifdef HAVE_OPENSSL
    unsigned char sslflags;
    SSL *ssl;   /* SSL handler */
#endif

    char *ip;
};


struct connection_bufs
{
    short count, max;
    int total;
    IOVEC *block;
};

#ifdef WIN32
#define IO_VECTOR_LEN(x) ((x)->len)
#define IO_VECTOR_BASE(x) ((x)->buf)
#else
#define IO_VECTOR_LEN(x) ((x)->iov_len)
#define IO_VECTOR_BASE(x) ((x)->iov_base)
#endif

#ifdef HAVE_OPENSSL
#define not_ssl_connection(x)    ((x)->ssl==NULL)
#else
#define not_ssl_connection(x)    (1)
#endif
void connection_initialize(void);
void connection_shutdown(void);
void connection_thread_startup();
void connection_thread_shutdown();
int  connection_setup_sockets (struct ice_config_tag *config);
void connection_reset (connection_t *con, uint64_t time_ms);
void connection_close(connection_t *con);
int  connection_init (connection_t *con, sock_t sock, const char *addr);
void connection_uses_ssl (connection_t *con);
void connection_add_banned_ip (const char *ip, int duration);
void connection_release_banned_ip (const char *ip);
void connection_stats (void);

void connection_bufs_init (struct connection_bufs *vectors, short start);
void connection_bufs_release (struct connection_bufs *v);
void connection_bufs_flush (struct connection_bufs *v);
int  connection_bufs_append (struct connection_bufs *vectors, void *buf, unsigned int len);
int  connection_bufs_read (connection_t *con, struct connection_bufs *vecs, int skip);
int  connection_bufs_send (connection_t *con, struct connection_bufs *vecs, int skip);
int  connection_unreadable (connection_t *con);


#define CHUNK_HDR_SZ            16

int  connection_chunk_start (connection_t *con, struct connection_bufs *vecs, char *chunk_hdr, unsigned chunk_sz);
int  connection_chunk_end (connection_t *con, struct connection_bufs *bufs, char *chunk_hdr, unsigned chunk_sz);


#ifdef HAVE_OPENSSL
int  connection_read_ssl (connection_t *con, void *buf, size_t len);
int  connection_send_ssl (connection_t *con, const void *buf, size_t len);
#endif
int  connection_read (connection_t *con, void *buf, size_t len);
int  connection_send (connection_t *con, const void *buf, size_t len);
void connection_thread_shutdown_req (void);

int connection_check_pass (http_parser_t *parser, const char *user, const char *pass);
int connection_check_relay_pass(http_parser_t *parser);
int connection_check_admin_pass(http_parser_t *parser);

void connection_close_sigfd (void);
void connection_listen_sockets_close (struct ice_config_tag *config, int all_sockets);

extern int connection_running;

#endif  /* __CONNECTION_H__ */
