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
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif


#include "log.h"

#define LOG_MAXLOGS logs_allocated
#define LOG_MAXLINELEN 1024


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
} log_entry_t;


typedef struct log_tag
{
    int in_use;

    unsigned level;

    char *filename;
    FILE *logfile;
    off_t size;
    off_t trigger_level;
    time_t reopen_at;
    unsigned int duration;
    short archive_timestamp;
    time_t recheck_time;

    unsigned long buffer_bytes;
    unsigned int entries;
    unsigned int keep_entries;
    log_entry_t *written_entry;
    log_entry_t *log_head;
    log_entry_t *log_tail;
    
    char *buffer;
} log_t;

int logs_allocated;
static log_t *loglist;

static int _get_log_id(void);
static void _release_log_id(int log_id);
static void _lock_logger(void);
static void _unlock_logger(void);
static int do_log_run (int log_id);


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

            if (stat (loglist [id] . filename, &st) == 0)
            {
                exists = 1;
                if ((loglist [id] . trigger_level && loglist [id] . size > loglist [id] . trigger_level) &&
                        st.st_size < loglist [id] . trigger_level)
                {  // log changed from under us, but less than trigger size, better reopen this and not archive for now.
                   archive = 0;
                }
            }
            if (loglist [id].logfile && loglist [id].logfile != stderr)
            {
                char new_name [4096];
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
            f = fopen (loglist [id] . filename, "a");
            if (f == NULL)
            {
                if (loglist [id] . logfile != stderr)
                {
                    loglist [id] . logfile = stderr;
                    do_log_run (id);
                }
                return 0;
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
    log->in_use = 0;
    log->level = 2;
    log->size = 0;
    log->trigger_level = 50*1024*1024;
    log->duration = 0;
    log->filename = NULL;
    log->logfile = NULL;
    log->buffer = NULL;
    log->buffer_bytes = 0;
    log->entries = 0;
    log->keep_entries = 5;
    log->written_entry = NULL;
    log->log_head = NULL;
    log->log_tail = NULL;
}

void log_initialize_lib (mx_create_func mxc, mx_lock_func mxl)
{
    if (_initialized) return;
    logs_allocated = 0;
    loglist = NULL;
    log_mutex_alloc = mxc ? mxc : NULL;
    log_mutex_lock = mxl ? mxl : NULL;

    if (log_mutex_alloc)
        log_mutex_alloc (&_logger_mutex, 1);
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
    if (loglist[log_id].in_use == 0) return;
    if (count > 1000000) return;

    _lock_logger ();
    loglist[log_id].keep_entries = count;
    _unlock_logger ();
}


void log_set_level(int log_id, unsigned level)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
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
    while (++loop < 10 && do_log_run (log_id) > 0)
        ;
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
    int log_id;
    log_commit_entries ();
    for (log_id = 0; log_id < logs_allocated ; log_id++)
        log_close (log_id);
    logs_allocated = 0;
    free (loglist);
    /* destroy mutexes */
    if (log_mutex_alloc)
        log_mutex_alloc (&_logger_mutex, 0);

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

    if (next && loglist[log_id].logfile && loglist [log_id] .filename && loglist [log_id].recheck_time <= now)
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
    while (next && ++loop < 300)
    {
        if (_log_open (log_id, now) == 0)
            break;

        loglist [log_id].written_entry = next;
        _unlock_logger ();

        // fprintf (stderr, "in log run, line is %s\n", next->line);
        if (fprintf (loglist [log_id].logfile, "%s\n", next->line) >= 0)
            loglist [log_id].size += (next->len + 1);

        _lock_logger ();
        next = next->next;
    }
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


static int create_log_entry (int log_id, const char *line)
{
    log_entry_t *entry;
    int len;

    entry = calloc (1, sizeof (log_entry_t));
    len = entry->len = strlen (line);
    entry->line = malloc (entry->len+1);
    snprintf (entry->line, entry->len+1, "%s", line);
    loglist [log_id].buffer_bytes += entry->len;

    if (loglist [log_id].log_tail)
        loglist [log_id].log_tail->next = entry;
    else
        loglist [log_id].log_head = entry;

    loglist [log_id].log_tail = entry;
    loglist [log_id].entries++;
    if (log_callback)
        log_callback (log_id);
    else
        do_log_run (log_id);
    do_purge (log_id);
    return len;
}


int log_contents (int log_id, char **_contents, unsigned int *_len)
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
        *_len = loglist [log_id].buffer_bytes + loglist [log_id].entries; // add space for newlines
        return 1;
    }
    remain = *_len;

    entry = loglist [log_id].log_head;
    ptr = *_contents;
    *ptr = '\0';
    while (entry && remain)
    {
        int len = snprintf (ptr, remain, "%s\n", entry->line);
        if (len > 0)
        {
            ptr += len;
            remain -= len;
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
    int datelen;
    time_t now;
    struct tm thetime;
    char line[LOG_MAXLINELEN];
    va_list ap;

    if (log_id < 0 || log_id >= LOG_MAXLOGS) return; /* Bad log number */
    if (loglist[log_id].level < priority) return;
    if (priority > sizeof(prior)/sizeof(prior[0])) return; /* Bad priority */

    va_start(ap, fmt);

    now = time(NULL);

    datelen = strftime (line, sizeof (line), "[%Y-%m-%d  %H:%M:%S]", localtime_r(&now, &thetime));

    datelen += snprintf (line+datelen, sizeof line-datelen, " %s %s%s ", prior [priority-1], cat, func);
    vsnprintf (line+datelen, sizeof line-datelen, fmt, ap);

    _lock_logger();
    create_log_entry (log_id, line);
    _unlock_logger();

    va_end(ap);
}

void log_write_direct(int log_id, const char *fmt, ...)
{
    va_list ap;
    char line[LOG_MAXLINELEN];

    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
    
    va_start(ap, fmt);

    _lock_logger();
    vsnprintf(line, LOG_MAXLINELEN, fmt, ap);
    create_log_entry (log_id, line);
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

static void _release_log_id(int log_id)
{
    /* lock mutex */
    _lock_logger();

    loglist[log_id].in_use = 0;

    /* unlock mutex */
    _unlock_logger();
}

static void _lock_logger(void)
{
    if (log_mutex_lock)
        log_mutex_lock (&_logger_mutex, 1);
}

static void _unlock_logger(void)
{
    if (log_mutex_lock)
        log_mutex_lock (&_logger_mutex, 0);
}




