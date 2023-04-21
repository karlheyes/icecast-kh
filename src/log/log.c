/*
** Logging framework.
**
** This program is distributed under the GNU General Public License, version 2.
** A copy of this license is included with this source.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE     200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif


#include "log.h"

#define LOG_MAXLOGS logs_allocated
#define LOG_MAXLINELEN 1000


static void *_logger_mutex;
static int _initialized = 0;

static mx_create_func       log_mutex_alloc;
static mx_lock_func         log_mutex_lock;
static log_commit_callback  log_callback;


typedef struct _log_entry_t
{
    struct _log_entry_t *next;
    char *line;
    unsigned int len;
    int flags;
    int priority;
    struct timeval tstamp;
} log_entry_t;


typedef struct log_tag
{
    uint8_t in_use;
    uint8_t archive_timestamp;
    uint8_t level;
    uint16_t flags;

    char *filename;
    FILE *logfile;
    off_t size;
    off_t trigger_level;
    time_t reopen_at;
    unsigned int duration;
    time_t recheck_time;

    unsigned long buffer_bytes;
    unsigned int entries;
    unsigned int keep_entries;
    log_entry_t *written_entry;
    log_entry_t *log_head;
    log_entry_t *log_tail;

    char *buffer;
} log_t;

typedef struct
{
   int flags;
   int id;
   int line_len;
   int priority;
   uint8_t level;
   char *line;
} log_lineinfo_t;

#define LOG_TIME_MS             (1<<0)
// set internally
#define LOG_TIME                (1<<8)

int logs_allocated;
static log_t *loglist;

static int _get_log_id(void);
static void _lock_logger_c(const char *file, size_t line);
static void _unlock_logger_c(const char *file, size_t line);
static int do_log_run (int log_id);

#define _lock_logger() _lock_logger_c(__FILE__,__LINE__)
#define _unlock_logger() _unlock_logger_c(__FILE__,__LINE__)

static int _log_open (int id, time_t now)
{
    if (loglist [id] . in_use == 0)
        return 0;

    /* check for cases where an open of the logfile is wanted */
    if (loglist [id] . logfile == NULL ||
       (loglist [id] . duration && loglist [id] . reopen_at <= now) ||
       (loglist [id] . trigger_level && loglist [id] . size > loglist [id] . trigger_level))
    {
        if (loglist [id] . filename)  /* only re-open files where we have a name */
        {
            FILE *f = NULL;
            struct stat st;
            int exists = 0, archive = 1;
            off_t trigger = loglist [id] . trigger_level;

            _unlock_logger();
            if (stat (loglist [id] . filename, &st) == 0)
            {
                exists = 1;
                if ((trigger && loglist [id].size > trigger) && st.st_size < trigger)
                {  // log changed from under us, but less than trigger size, better reopen this and not archive for now.
                   archive = 0;
                }
            }
            char new_name [4096];
            _lock_logger();
            if (loglist [id].logfile && loglist [id].logfile != stderr)
            {
                fclose (loglist [id] . logfile);
                loglist [id] . logfile = NULL;
                if (archive)
                {
                    if (loglist[id].archive_timestamp)
                    {
                        char timestamp [128];

                        strftime (timestamp, sizeof (timestamp), "%Y%m%d_%H%M%S", localtime (&now));
                        snprintf (new_name,  sizeof(new_name), "%s.%s", loglist[id].filename, timestamp);
                    }
                    else {
                        snprintf (new_name,  sizeof(new_name), "%s.old", loglist [id] . filename);
                    }
                    if (exists)
                    {
#ifdef _WIN32
                        remove (new_name);
#endif
                        rename (loglist [id] . filename, new_name);
                    }
                }
            }
            snprintf (new_name, sizeof new_name, "%s", loglist [id].filename);
            _unlock_logger();

            f = fopen (new_name, "a");

            _lock_logger();
            if (f == NULL)
            {
                if (loglist [id] . logfile != stderr)
                {
                    loglist [id] . logfile = stderr;
                }
                return 1;
            }
            loglist [id].logfile = f;
            setvbuf (loglist [id] . logfile, NULL, IO_BUFFER_TYPE, 0);
            if (stat (loglist [id] . filename, &st) < 0)
                loglist [id] . size = 0;
            else
                loglist [id] . size = st.st_size;
            if (loglist [id] . duration)
                loglist [id] . reopen_at = now + loglist [id] . duration;
            loglist [id].recheck_time = now + 10;
        }
        else
            loglist [id] . size = 0;
    }
    return 1;
}

static void log_init (log_t *log)
{
    memset (log, 0, sizeof (*log));
    log->level = 2;
    log->trigger_level = 50*1024*1024;
    log->filename = NULL;
    log->logfile = NULL;
    log->buffer = NULL;
    log->keep_entries = 20;
}

void log_initialize_lib (mx_create_func mxc, mx_lock_func mxl)
{
    if (_initialized) return;
    logs_allocated = 0;
    loglist = NULL;
    log_mutex_alloc = mxc ? mxc : NULL;
    log_mutex_lock = mxl ? mxl : NULL;

    if (log_mutex_alloc)
        log_mutex_alloc (&_logger_mutex, __FILE__, __LINE__, 3);
    log_callback = NULL;
    _initialized = 1;
}


void log_initialize(void)
{
    if (_initialized) return;

    logs_allocated = 0;
    loglist = NULL;
    /* initialize mutexes */

    _initialized = 1;
    log_callback = NULL;
}

int log_open_file(FILE *file)
{
    int log_id;

    if(file == NULL) return LOG_EINSANE;

    log_id = _get_log_id();
    if (log_id < 0) return LOG_ENOMORELOGS;

    loglist[log_id].logfile = file;
    loglist[log_id].filename = NULL;
    loglist[log_id].size = 0;
    loglist[log_id].reopen_at = 0;
    loglist[log_id].archive_timestamp = 0;

    return log_id;
}


int log_open(const char *filename)
{
    int id;

    if (filename == NULL) return LOG_EINSANE;
    if (strcmp(filename, "") == 0) return LOG_EINSANE;

    id = _get_log_id();

    if (id >= 0)
    {
        _lock_logger();
        free (loglist [id] . filename);
        loglist [id] . filename = strdup (filename);
        loglist [id].entries = 0;
        loglist [id].log_head = NULL;
        loglist [id].log_tail = NULL;
        loglist [id].logfile = NULL;
        loglist [id].size = 0;
        loglist [id].reopen_at = 0;
        loglist [id].archive_timestamp = 0;
        _unlock_logger();
    }

    return id;
}


/* set the trigger level to trigger, represented in bytes */
void log_set_trigger(int id, unsigned long trigger)
{
    _lock_logger();
    if (id >= 0 && id < LOG_MAXLOGS && loglist [id] . in_use)
    {
        if (trigger < 100000)
            trigger = 100000;
        loglist [id] . trigger_level = trigger;
    }
    _unlock_logger();
}


void log_set_reopen_after (int id, unsigned int trigger)
{
    _lock_logger();
    if (id >= 0 && id < LOG_MAXLOGS && loglist [id] . in_use)
    {
         loglist [id] . duration = trigger;
         loglist [id] . reopen_at = trigger ? time (NULL) + trigger : 0;
    }
    _unlock_logger();
}


int log_set_filename(int id, const char *filename)
{
    if (id < 0 || id >= LOG_MAXLOGS)
        return LOG_EINSANE;
    /* NULL filename is ok, empty filename is not. */
    if (filename && !strcmp(filename, ""))
        return LOG_EINSANE;
    _lock_logger();
    if (loglist [id] . in_use)
    {
        if (loglist [id] . filename)
            free (loglist [id] . filename);
        if (filename)
            loglist [id] . filename = strdup (filename);
        else
            loglist [id] . filename = NULL;
    }
    _unlock_logger();
    return id;
}

int log_set_archive_timestamp(int id, int value)
{
    if (id < 0 || id >= LOG_MAXLOGS)
        return LOG_EINSANE;
     _lock_logger();
     if (loglist [id] . in_use)
         loglist[id].archive_timestamp = value;
     _unlock_logger();
    return id;
}


int log_open_with_buffer(const char *filename, int size)
{
    /* not implemented */
    return LOG_ENOTIMPL;
}


void log_set_lines_kept (int log_id, unsigned int count)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
    if (count > 1000000) return;

    _lock_logger ();
    if (loglist[log_id].in_use)
        loglist[log_id].keep_entries = count;
    _unlock_logger ();
}


void log_set_level(int log_id, unsigned level)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;

    uint16_t flags = level >> 8;
    loglist[log_id].flags = flags;
    level &= 15;
    _lock_logger();
    if (loglist[log_id].in_use)
        loglist[log_id].level = level;
    _unlock_logger();
}

void log_flush(int log_id)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
    if (loglist[log_id].in_use == 0) return;

    _lock_logger();
    if (loglist[log_id].logfile)
        fflush(loglist[log_id].logfile);
    _unlock_logger();
}

void log_reopen(int log_id)
{
    if (log_id < 0 && log_id >= LOG_MAXLOGS)
        return;
    _lock_logger();
    do
    {
        if (loglist [log_id] . filename == NULL || loglist [log_id] . logfile == NULL)
            break;
        if (loglist [log_id]. archive_timestamp < 0)
        {
            struct stat st;
            fflush (loglist [log_id] . logfile);
            if (stat (loglist [log_id] . filename, &st) == 0 && st.st_size == loglist [log_id].size)
                break;
            // a missing or different sized log indicates an external move so trigger a reopen
        }
        if (loglist [log_id] . logfile)
        {
            fclose (loglist [log_id] . logfile);
            loglist [log_id] . logfile = NULL;
        }
    } while (0);
    _unlock_logger();
}



static void _log_close_internal (int log_id)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;

    int loop = 0;
    do {} while (++loop < 10 && do_log_run (log_id) > 0);

    loglist[log_id].level = 2;
    free (loglist[log_id].filename);
    loglist[log_id].filename = NULL;
    if (loglist[log_id].buffer) free(loglist[log_id].buffer);

    if (loglist [log_id] . logfile)
    {
        fclose (loglist [log_id] . logfile);
        loglist [log_id] . logfile = NULL;
    }
    while (loglist [log_id].log_head)
    {
        log_entry_t *to_go = loglist [log_id].log_head;
        loglist [log_id].log_head = to_go->next;
        loglist [log_id].buffer_bytes -= to_go->len;
        free (to_go->line);
        free (to_go);
        loglist [log_id].entries--;
    }
    loglist [log_id].written_entry = NULL;
    loglist [log_id].entries = 0;
    loglist [log_id].in_use = 0;
}


void log_close(int log_id)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;

    _lock_logger();

    if (loglist[log_id].in_use != 1)
    {
        if (loglist[log_id].in_use == 3)
            loglist[log_id].in_use = 1;
        _unlock_logger();
        return;
    }
    _log_close_internal (log_id);
    _unlock_logger();
}


void log_shutdown(void)
{
    if (_initialized == 0)
        return;
    int log_id;
    log_commit_entries ();
    for (log_id = 0; log_id < logs_allocated ; log_id++)
        log_close (log_id);
    logs_allocated = 0;
    free (loglist);
    loglist = NULL;
    /* destroy mutexes */
    if (log_mutex_alloc)
        log_mutex_alloc (&_logger_mutex, __FILE__, __LINE__, 0);

    _initialized = 0;
}

static log_entry_t *log_entry_pop (int log_id)
{
    log_entry_t *to_go = loglist [log_id].log_head;

    if (to_go == NULL || loglist [log_id].written_entry == NULL || loglist [log_id].written_entry == to_go)
        return NULL;
    loglist [log_id].log_head = to_go->next;
    loglist [log_id].buffer_bytes -= to_go->len;
    loglist [log_id].entries--;

    if (to_go == loglist [log_id].log_tail)
        loglist [log_id].log_tail = NULL;

    if (to_go == loglist [log_id].written_entry)
        loglist [log_id].written_entry = NULL;

    return to_go;
}


static int _log_expand_preline (log_entry_t *next, char *preline, size_t prelen)
{
    int r = 0;
    if (next->flags & LOG_TIME)
    {
        struct tm thetime;
        time_t secs = next->tstamp.tv_sec;
        if (next->flags & LOG_TIME_MS)
        {
            r =  strftime (preline, prelen, "[%Y-%m-%d  %H:%M:%S", localtime_r(&secs, &thetime));
            r += snprintf (preline+r, prelen-r, ".%06ld] ", (long)next->tstamp.tv_usec);
        }
        else
        {
            r = strftime (preline, prelen, "[%Y-%m-%d  %H:%M:%S] ", localtime_r(&secs, &thetime));
        }
    }
    return r;
}


// flush out any waiting log entries
//
static int do_log_run (int log_id)
{
    log_entry_t *next;
    int loop = 0;
    time_t now;

    loglist [log_id].in_use = 3;
    time (&now);
    if (loglist [log_id].written_entry == NULL)
        next = loglist [log_id].log_head;
    else
        next = loglist [log_id].written_entry->next;

    // recheck size every so often in case contents are modified outside of this use.
    if (next &&
            loglist[log_id].logfile &&
            loglist [log_id] .filename &&
            loglist [log_id].recheck_time <= now)
    {
        struct stat st;
        loglist [log_id].recheck_time = now + 6;
        if (fstat (fileno(loglist[log_id].logfile), &st) < 0)
        {
            loglist [log_id].size = loglist [log_id].trigger_level+1;
            // fprintf (stderr, "recheck size of %s, failed\n", loglist [log_id] .filename);
        }
        else
        {
            // fprintf (stderr, "recheck size of %s, %s\n", loglist [log_id] .filename, (loglist [log_id].size == st.st_size) ? "ok" :"different");
            loglist [log_id] . size = st.st_size;
        }
    }
    // fprintf (stderr, "in log run, id %d\n", log_id);
    while (loglist [log_id].in_use == 3 && next && ++loop < 300)
    {
        if (_log_open (log_id, now) == 0)
            break;

        loglist [log_id].written_entry = next;
        if (loglist [log_id].level >= next->priority)
        {
            _unlock_logger ();

            char preline [64] = "";
            _log_expand_preline (next, preline, sizeof preline);

            // fprintf (stderr, "in log run, line is %s\n", next->line);
            int len = fprintf (loglist [log_id].logfile, "%s%s\n", preline, next->line);

            _lock_logger ();
            if (len >= 0)
                loglist [log_id].size += (len + 1);
        }
        next = next->next;
    }
    // fprintf (stderr, "log.c, end of run %d, in_use %d\n", log_id, loglist [log_id].in_use);
    if (loglist [log_id].in_use == 3)
        loglist [log_id].in_use = 1;    // normal route
    else
        _log_close_internal (log_id);   // log_close could of triggered
    return loop;
}

void log_commit_entries ()
{
    int count = 0, c = 0, log_id;

    //fprintf (stderr, "in log commit\n");
    _lock_logger ();
    for (log_id = 0; log_id < logs_allocated ; log_id++)
    {
        do
        {
            if (loglist [log_id].in_use)
                c = do_log_run (log_id);
            if (c == 0) break;      // skip to next log
        } while ((count += c) < 1000);
    }
    _unlock_logger ();
}


// set callback routine for whenever a log message is performed
//
void log_set_commit_callback (log_commit_callback f)
{
    log_callback = f;
}


// purge log entries back to least 1 on the specified log, assumes lock in use
//
static void do_purge (int log_id)
{
    int last = loglist [log_id].keep_entries;

    //fprintf (stderr, "in log purge, id %d, last %d, entries %d\n", log_id, last, loglist [log_id].entries);
    while (loglist [log_id].entries > last)
    {
        log_entry_t *to_go = log_entry_pop (log_id);

        if (to_go)
        {
            //fprintf (stderr, "  log purge (%d), %s\n", loglist [log_id].entries, to_go->line);
            free (to_go->line);
            free (to_go);
            continue;
        }
        break;
    }
}


static int create_log_entry (log_lineinfo_t *info)
{
    log_entry_t *entry;
    int len = info->line_len + 1,       // add for nul/NL
        prelen = 0;

    entry = calloc (1, sizeof (log_entry_t));
    if (info->flags & LOG_TIME)
    {
        prelen += 23;   // "[YYYY-MM-DD  HH:MM:SS] "
#ifdef HAVE_GETTIMEOFDAY
        gettimeofday (&entry->tstamp, NULL);
#else
        entry->tstamp.tv_sec = (uint64_t)time (NULL);
#endif
        if (loglist [info->id].flags & LOG_TIME_MS)
        {
            entry->flags |= LOG_TIME_MS;
            prelen += 7;        // "[YYYY-MM-DD  HH:MM:SS.UUUUUU] "
        }
        entry->flags |= LOG_TIME;
    }

    entry->line = strdup (info->line);
    entry->len = len + prelen;
    entry->priority = info->priority;
    loglist [info->id].buffer_bytes += entry->len;

    if (loglist [info->id].log_tail)
        loglist [info->id].log_tail->next = entry;
    else
        loglist [info->id].log_head = entry;

    loglist [info->id].log_tail = entry;
    loglist [info->id].entries++;
    if (log_callback)
        log_callback (info->id);
    else
        do_log_run (info->id);
    do_purge (info->id);
    return len;
}


int log_contents (int log_id, int level, char **_contents, unsigned int *_len)
{
    int remain;
    log_entry_t *entry;
    char *ptr;

    if (log_id < 0) return -1;
    if (log_id >= LOG_MAXLOGS) return -1; /* Bad log number */

    if (_contents == NULL)
    {
        _lock_logger ();  // normal initial route
        if (loglist [log_id].in_use == 0)
        {
            _unlock_logger ();
            return -1;
        }
        *_len = loglist [log_id].buffer_bytes; // max amount really
        return 1;
    }
    remain = *_len;

    if (level == 0)
        level = loglist[log_id].level;
    entry = loglist [log_id].log_head;
    ptr = *_contents;
    *ptr = '\0';
    while (entry && remain)
    {
        if (entry->priority <= level)
        {
            if (entry->len >= remain) break;
            char preline [64] = "";
            _log_expand_preline (entry, preline, sizeof preline);
            int len = snprintf (ptr, remain, "%s%s\n", preline, entry->line);
            if (len > 0 && len <= remain)
            {
                ptr += len;
                remain -= len;
            }
        }
        entry = entry->next;
    }
    _unlock_logger ();
    if (remain)
        *_len -= remain;
    return 0;
}


void log_write(int log_id, unsigned priority, const char *cat, const char *func,
        const char *fmt, ...)
{
    static char *prior[] = { "EROR", "WARN", "INFO", "DBUG" };
    char line[LOG_MAXLINELEN];
    va_list ap;

    if (log_id < 0 || log_id >= LOG_MAXLOGS) return; /* Bad log number */
    if (priority > sizeof(prior)/sizeof(prior[0])) return; /* Bad priority */

    log_lineinfo_t info = { .id = log_id, .line = line, .priority = priority, .flags = LOG_TIME };

    va_start(ap, fmt);

    int len = 0;
    len += snprintf (line, sizeof line, "%s %s%s ", prior [priority-1], cat, func);
    len += vsnprintf (line+len, sizeof line-len, fmt, ap);
    info.line_len = (len < LOG_MAXLINELEN) ? len : LOG_MAXLINELEN-1;

    _lock_logger();
    create_log_entry (&info);
    _unlock_logger();

    va_end(ap);
}

void log_write_direct(int log_id, const char *fmt, ...)
{
    va_list ap;
    char line[LOG_MAXLINELEN];

    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;

    log_lineinfo_t info = { .id = log_id, .line = line };

    va_start(ap, fmt);

    _lock_logger();
    int len = vsnprintf(line, LOG_MAXLINELEN, fmt, ap);
    info.line_len = (len < LOG_MAXLINELEN) ? len : LOG_MAXLINELEN-1;
    create_log_entry (&info);
    _unlock_logger();

    va_end(ap);
}

static int _get_log_id(void)
{
    int i;
    int id = -1;

    /* lock mutex */
    _lock_logger();

    for (i = 0; i < logs_allocated; i++)
        if (loglist[i].in_use == 0) {
            loglist[i].in_use = 1;
            id = i;
            break;
        }
    if (id == -1)
    {
        int new_count = logs_allocated + 20;
        log_t *new_list = realloc (loglist, new_count * sizeof (log_t));
        if (new_list)
        {
            for (i = logs_allocated; i < new_count; i++)
                log_init (&new_list[i]);
            loglist = new_list;
            id = logs_allocated;
            loglist[id].in_use = 1;
            logs_allocated = new_count;
        }
    }

    /* unlock mutex */
    _unlock_logger();

    return id;
}


static void _lock_logger_c(const char *file, size_t line)
{
    if (log_mutex_lock)
        log_mutex_lock (&_logger_mutex, file, line, 1);
}

static void _unlock_logger_c(const char *file, size_t line)
{
    if (log_mutex_lock)
        log_mutex_lock (&_logger_mutex, file, line, 0);
}




