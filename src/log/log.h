/* 
** Logging framework.
**
** This program is distributed under the GNU General Public License, version 2.
** A copy of this license is included with this source.
*/

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#define LOG_EINSANE -1
#define LOG_ENOMORELOGS -2
#define LOG_ECANTOPEN -3
#define LOG_ENOTOPEN -4
#define LOG_ENOTIMPL -5

#ifdef _WIN32
#define IO_BUFFER_TYPE _IONBF
#else
#define IO_BUFFER_TYPE _IOLBF
#endif

typedef int (*mx_create_func)(void**m, int create);
typedef int (*mx_lock_func)(void**m, int create);
typedef void (*log_commit_callback)(int id);

void log_initialize_lib (mx_create_func mxc, mx_lock_func mxl);
void log_initialize(void);
int log_open_file(FILE *file);
int log_open(const char *filename);
int log_open_with_buffer(const char *filename, int size);
void log_set_level(int log_id, unsigned level);
void log_set_trigger(int id, unsigned long trigger);
void log_set_reopen_after (int id, unsigned int trigger);
int  log_set_filename(int id, const char *filename);
void log_set_lines_kept (int log_id, unsigned int count);
int  log_contents (int log_id, char **_contents, unsigned int *_len);
int log_set_archive_timestamp(int id, int value);
void log_flush(int log_id);
void log_reopen(int log_id);
void log_close(int log_id);
void log_shutdown(void);

void log_write(int log_id, unsigned priority, const char *cat, const char *func, 
        const char *fmt, ...)  __attribute__ ((format (gnu_printf, 5, 6)));
void log_write_direct(int log_id, const char *fmt, ...) __attribute__ ((format (gnu_printf, 2, 3)));
void log_set_commit_callback (log_commit_callback f);
void log_commit_entries ();

#endif  /* __LOG_H__ */
