/* 
** Logging framework.
**
** This program is distributed under the GNU General Public License, version 2.
** A copy of this license is included with this source.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
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


#ifndef _WIN32
#include <pthread.h>
#else
#include <windows.h>
#endif

#include "log.h"

#define LOG_MAXLOGS logs_allocated
#define LOG_MAXLINELEN 1024

#ifdef _WIN32
#define mutex_t CRITICAL_SECTION
// #define snprintf _snprintf
// #define vsnprintf vsnprintf_s
#else
#define mutex_t pthread_mutex_t
#endif

static mutex_t _logger_mutex;
static int _initialized = 0;

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
    int archive_timestamp;

    unsigned long total;
    unsigned int entries;
    unsigned int keep_entries;
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
            struct stat st;

            if (loglist [id] . logfile)
            {
                char new_name [4096];
                fclose (loglist [id] . logfile);
                loglist [id] . logfile = NULL;
                /* simple rename, but could use time providing locking were used */
                if (loglist[id].archive_timestamp)
                {
                    char timestamp [128];

                    strftime (timestamp, sizeof (timestamp), "%Y%m%d_%H%M%S", localtime (&now));
                    snprintf (new_name,  sizeof(new_name), "%s.%s", loglist[id].filename, timestamp);
                }
                else {
                    snprintf (new_name,  sizeof(new_name), "%s.old", loglist [id] . filename);
                }
#ifdef _WIN32
                if (stat (new_name, &st) == 0)
                    remove (new_name);
#endif
                rename (loglist [id] . filename, new_name);
            }
            loglist [id] . logfile = fopen (loglist [id] . filename, "a");
            if (loglist [id] . logfile == NULL)
                return 0;
            setvbuf (loglist [id] . logfile, NULL, IO_BUFFER_TYPE, 0);
            if (stat (loglist [id] . filename, &st) < 0)
                loglist [id] . size = 0;
            else
                loglist [id] . size = st.st_size;
            if (loglist [id] . duration)
                loglist [id] . reopen_at = now + loglist [id] . duration;
        }
        else
            loglist [id] . size = 0;
    }
    return 1;
}

static log_init (log_t *log)
{
    log->in_use = 0;
    log->level = 2;
    log->size = 0;
    log->trigger_level = 50*1024*1024;
    log->duration = 0;
    log->filename = NULL;
    log->logfile = NULL;
    log->buffer = NULL;
    log->total = 0;
    log->entries = 0;
    log->keep_entries = 0;
    log->log_head = NULL;
    log->log_tail = NULL;
}

void log_initialize(void)
{
    if (_initialized) return;

    logs_allocated = 0;
    loglist = NULL;
    /* initialize mutexes */
#ifndef _WIN32
    pthread_mutex_init(&_logger_mutex, NULL);
#else
    InitializeCriticalSection(&_logger_mutex);
#endif

    _initialized = 1;
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

    return log_id;
}


int log_open(const char *filename)
{
    int id;
    FILE *file;

    if (filename == NULL) return LOG_EINSANE;
    if (strcmp(filename, "") == 0) return LOG_EINSANE;
    
    file = fopen(filename, "a");

    id = log_open_file(file);

    if (id >= 0)
    {
        struct stat st;

        setvbuf (loglist [id] . logfile, NULL, IO_BUFFER_TYPE, 0);
        free (loglist [id] . filename);
        loglist [id] . filename = strdup (filename);
        if (stat (loglist [id] . filename, &st) == 0)
            loglist [id] . size = st.st_size;
        loglist [id] . entries = 0;
        loglist [id] . log_head = NULL;
        loglist [id] . log_tail = NULL;
    }

    return id;
}


/* set the trigger level to trigger, represented in kilobytes */
void log_set_trigger(int id, unsigned trigger)
{
    if (id >= 0 && id < LOG_MAXLOGS && loglist [id] . in_use)
    {
         loglist [id] . trigger_level = trigger*1024;
    }
}


void log_set_reopen_after (int id, unsigned int trigger)
{
    if (id >= 0 && id < LOG_MAXLOGS && loglist [id] . in_use)
    {
         loglist [id] . duration = trigger;
         loglist [id] . reopen_at = time (NULL) + trigger;
    }
}


int log_set_filename(int id, const char *filename)
{
    if (id < 0 || id >= LOG_MAXLOGS)
        return LOG_EINSANE;
    /* NULL filename is ok, empty filename is not. */
    if ((filename && !strcmp(filename, "")) || loglist [id] . in_use == 0)
        return LOG_EINSANE;
     _lock_logger();
    if (loglist [id] . filename)
        free (loglist [id] . filename);
    if (filename)
        loglist [id] . filename = strdup (filename);
    else
        loglist [id] . filename = NULL;
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

    _lock_logger ();
    loglist[log_id].keep_entries = count;
    while (loglist[log_id].entries > count)
    {
        log_entry_t *to_go = loglist [log_id].log_head;
        loglist [log_id].log_head = to_go->next;
        loglist [log_id].total -= to_go->len;
        free (to_go->line);
        free (to_go);
        loglist [log_id].entries--;
    }
    _unlock_logger ();
}


void log_set_level(int log_id, unsigned level)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
    if (loglist[log_id].in_use == 0) return;

    loglist[log_id].level = level;
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
    if (loglist [log_id] . filename && loglist [log_id] . logfile)
    {
        fclose (loglist [log_id] . logfile);
        loglist [log_id] . logfile = NULL;
    }
    _unlock_logger();
}

void log_close(int log_id)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;

    _lock_logger();

    if (loglist[log_id].in_use == 0)
    {
        _unlock_logger();
        return;
    }

    loglist[log_id].in_use = 0;
    loglist[log_id].level = 2;
    if (loglist[log_id].filename) free(loglist[log_id].filename);
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
        loglist [log_id].total -= to_go->len;
        free (to_go->line);
        free (to_go);
        loglist [log_id].entries--;
    }
    loglist [log_id].entries = 0;
    _unlock_logger();
}

void log_shutdown(void)
{
    free (loglist);
    /* destroy mutexes */
#ifndef _WIN32
    pthread_mutex_destroy(&_logger_mutex);
#else
    DeleteCriticalSection(&_logger_mutex);
#endif 

    _initialized = 0;
}


static int create_log_entry (int log_id, const char *pre, const char *line)
{
    log_entry_t *entry;

    if (loglist[log_id].keep_entries == 0)
        return fprintf (loglist[log_id].logfile, "%s%s\n", pre, line); 
    
    entry = calloc (1, sizeof (log_entry_t));
    entry->len = strlen (pre) + strlen (line);
    entry->line = malloc (entry->len+1);
    snprintf (entry->line, entry->len+1, "%s%s", pre, line);
    loglist [log_id].total += entry->len;

    if (loglist [log_id].log_tail)
        loglist [log_id].log_tail->next = entry;
    else
        loglist [log_id].log_head = entry;

    loglist [log_id].log_tail = entry;

    if (loglist [log_id].entries >= loglist [log_id].keep_entries)
    {
        log_entry_t *to_go = loglist [log_id].log_head;
        loglist [log_id].log_head = to_go->next;
        loglist [log_id].total -= to_go->len;
        free (to_go->line);
        free (to_go);
    }
    else
        loglist [log_id].entries++;
    return fprintf (loglist [log_id].logfile, "%s\n", entry->line);
}


void log_contents (int log_id, char **_contents, unsigned int *_len)
{
    int remain;
    log_entry_t *entry;
    char *ptr;

    if (log_id < 0) return;
    if (log_id >= LOG_MAXLOGS) return; /* Bad log number */

    _lock_logger ();
    remain = loglist [log_id].total + loglist [log_id].entries + 1;
    *_contents = malloc (remain);
    **_contents= '\0';
    *_len = loglist [log_id].total;

    entry = loglist [log_id].log_head;
    ptr = *_contents;
    while (entry)
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
}


void log_write(int log_id, unsigned priority, const char *cat, const char *func, 
        const char *fmt, ...)
{
    static char *prior[] = { "EROR", "WARN", "INFO", "DBUG" };
    int datelen;
    time_t now;
    char pre[256];
    char line[LOG_MAXLINELEN];
    va_list ap;

    if (log_id < 0 || log_id >= LOG_MAXLOGS) return; /* Bad log number */
    if (loglist[log_id].level < priority) return;
    if (priority > sizeof(prior)/sizeof(prior[0])) return; /* Bad priority */

    va_start(ap, fmt);
    vsnprintf(line, LOG_MAXLINELEN, fmt, ap);

    now = time(NULL);

    _lock_logger();
    datelen = strftime (pre, sizeof (pre), "[%Y-%m-%d  %H:%M:%S]", localtime(&now)); 

    snprintf (pre+datelen, sizeof (pre)-datelen, " %s %s%s ", prior [priority-1], cat, func);

    if (_log_open (log_id, now))
    {
        int len = create_log_entry (log_id, pre, line);
        if (len > 0)
            loglist[log_id].size += len;
    }
    _unlock_logger();

    va_end(ap);
}

void log_write_direct(int log_id, const char *fmt, ...)
{
    va_list ap;
    time_t now;
    char line[LOG_MAXLINELEN];

    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
    
    va_start(ap, fmt);

    now = time(NULL);

    _lock_logger();
    vsnprintf(line, LOG_MAXLINELEN, fmt, ap);
    if (_log_open (log_id, now))
    {
        int len = create_log_entry (log_id, "", line);
        if (len > 0)
            loglist[log_id].size += len;
    }
    _unlock_logger();

    va_end(ap);

    fflush(loglist[log_id].logfile);
}

static int _get_log_id(void)
{
    int i;
    int id = -1;

    /* lock mutex */
    _lock_logger();

    for (i = 0; i < LOG_MAXLOGS; i++)
        if (loglist[i].in_use == 0) {
            loglist[i].in_use = 1;
            id = i;
            break;
        }
    if (id == -1)
    {
        int new_count = logs_allocated + 5;
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
#ifndef _WIN32
    pthread_mutex_lock(&_logger_mutex);
#else
    EnterCriticalSection(&_logger_mutex);
#endif
}

static void _unlock_logger(void)
{
#ifndef _WIN32
    pthread_mutex_unlock(&_logger_mutex);
#else
    LeaveCriticalSection(&_logger_mutex);
#endif    
}




