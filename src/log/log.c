/*
** Logging framework.
**
** This program is distributed under the GNU General Public License, version 2.
** A copy of this license is included with this source.

** Copyright 2010-2023, Karl Heyes <karl@kheyes.plus.com>
*  and others from the Xiph IceCast team over the years
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


static void *_logger_rwl;
static int _initialized = 0;

static log_locking_t        _locks;
static log_commit_callback  log_callback;


typedef struct _log_entry_t
{
    struct _log_entry_t *next;
    struct _log_entry_t *prev;
    struct _log_entry_t *next_on_priority;
    uint64_t id;
    unsigned int len;
    unsigned int plen;
    int flags;
    int priority;
#ifdef HAVE_CLOCK_GETTIME
    struct timespec tstamp;
#else
    struct timeval tstamp;
#endif
   char line [LOG_MAXLINELEN];
} log_entry_t;

typedef struct _log_priority
{
    log_level_t level;
    unsigned present;
    off_t size;
    log_entry_t *head;
    log_entry_t *tail;
} log_priority_t;

typedef struct log_tag
{
    uint8_t in_use;
    uint8_t archive_timestamp;
    uint8_t level;
    uint16_t flags;
    unsigned int duration;

    char *filename;
    FILE *logfile;
    off_t trigger_level;
    time_t reopen_at;

    // these need the mutex
    void *mutex;
    time_t recheck_time;
    off_t size;
    log_entry_t *checked_entry;
    log_entry_t *log_head;
    log_entry_t *log_tail;
    int priority_count;
    int freed_count;
    log_entry_t *freed;
    log_priority_t *priorities; // array

    char *buffer;
} log_t;

typedef struct
{
   int flags;
   int id;
   int line_len;
   int priority;
   int remain;
   uint8_t level;
   char *line;
} log_lineinfo_t;

typedef struct
{
   time_t now;
   off_t fsize;
   off_t psize;
   int id;
} log_run_t;


// set internally
#define LOG_CLOSING             (1<<8)
#define LOG_TIME                (1<<9)
#define LOG_MARK_ID             (1<<10)

int logs_allocated;
static log_t *loglist;

static int _get_log_id(void);
static int do_log_run (int log_id);

// for global rwlock using read lock
#define _lock_logger()      do { if (_locks.rwl) _locks.rwl (&_logger_rwl, __FILE__, __LINE__, 1); } while (0)
#define _wlock_logger()     do { if (_locks.rwl) _locks.rwl (&_logger_rwl, __FILE__, __LINE__, 2); } while (0)
#define _unlock_logger()    do { if (_locks.rwl) _locks.rwl (&_logger_rwl, __FILE__, __LINE__, 0); } while (0)
// for queue specific locking
#define _lock_q(N)          do { if (_locks.mxl) _locks.mxl (&loglist[(N)].mutex, __FILE__, __LINE__, 1); } while(0)
#define _unlock_q(N)        do { if (_locks.mxl) _locks.mxl (&loglist[(N)].mutex, __FILE__, __LINE__, 0); } while(0)

static char *_entry_line_start (int flags, log_entry_t*entry)
{
    char *line = entry->line;
    if (flags & LOG_MARK_ID)
        line += 24;
    return line;
}


// called from the log thread
//
static int _log_open (log_run_t *lr)
{
    int id = lr->id;
    int file_recheck = 0, reopen = 0, archive = 0, exists = 0;
    FILE *oldf = NULL;
    if (loglist [id] . in_use == 0)
        return 0;
    do
    {
        if (loglist [id].filename == NULL) break;
        if (loglist [id].recheck_time <= lr->now)
            file_recheck = 1;
        if ((loglist [id].trigger_level && lr->fsize > loglist [id].trigger_level) ||
                (loglist [id].duration && loglist [id].reopen_at <= lr->now))
            archive = 1;
        if (loglist [id].logfile == NULL || archive)
            file_recheck = reopen = 1;

        if (file_recheck)
        {
            _unlock_q (id);
            int r = -1;
            struct stat st;
            if (loglist [id].logfile)
            {
                if (access (loglist [id].filename, F_OK) == 0) // in case the log has been moved externally
                    r = fstat (fileno (loglist [id].logfile), &st);
            }
            else
                r = stat (loglist [id].filename, &st);

            if (r < 0)
            {
                reopen = 1;
                archive = 0;
            }
            else
            {
                if (S_ISREG (st.st_mode))
                {
                    // fprintf (stderr, "content check, trig %ld, file %ld, internal %ld\n", loglist [id].trigger_level, st.st_size, lr->fsize);
                    exists = 1;
                    if (lr->fsize != st.st_size)
                    {
                        lr->fsize = st.st_size;
                        archive = 0;
                    }
                }
                else
                {
                    reopen = 0;
                    lr->fsize = 0;
                }
            }
            loglist [id].recheck_time = lr->now + 10;
        }
        if (reopen)
        {
            if (loglist [id].logfile == stderr)
                break;
            oldf = loglist [id].logfile;
            char new_name [4096];
            if (archive)
            {
                if (loglist[id].archive_timestamp)
                {
                    char timestamp [128];

                    strftime (timestamp, sizeof (timestamp), "%Y%m%d_%H%M%S", localtime (&lr->now));
                    snprintf (new_name,  sizeof(new_name), "%s.%s", loglist[id].filename, timestamp);
                }
                else {
                    snprintf (new_name,  sizeof(new_name), "%s.old", loglist [id] . filename);
                }
                if (exists)
                {
#ifdef _WIN32
                    if (oldf)
                        fclose (oldf);  // windows does not allow for renames while open.
                    loglist [id].logfile = oldf = NULL;
                    remove (new_name);
#endif
                    rename (loglist [id].filename, new_name);
                    exists = 0;
                }
            }
            snprintf (new_name, sizeof new_name, "%s", loglist [id].filename);
            FILE *f = fopen (new_name, "a+t");
            if (f == NULL)
            {
                if (loglist [id].logfile != stderr)
                    loglist [id] . logfile = stderr;
                break;
            }
            loglist [id].logfile = f;
            if (exists == 0)
                lr->fsize = 0;
            if (loglist [id] . duration)
                loglist [id] . reopen_at = lr->now + loglist [id].duration;
        }
    } while (0);
    if (oldf)
        fclose (oldf);
    if (file_recheck)
        _lock_q (id);
    return 1;
}


void log_init_levels (int log_id, log_levels_t *ll, unsigned n)
{
    static const log_level_t defaults[] = {
        { .name = "0",     .keep = 15   },
        { .name = "1",     .keep = 15   },
        { .name = "2",     .keep = 15   },
        { .name = "3",     .keep = 15   },
        { .name = "4",     .keep = 15   },
    };
    if (log_id < 0 || loglist[log_id].priority_count == 0)
    {
        if (n == 0 || n > 5)
            n = sizeof (defaults) / sizeof (defaults[0]);
        memcpy (&ll->level[0], defaults, sizeof defaults);
        ll->flags = 0;
        ll->count = n;
        ll->mark = n-1;
    }
    else
    {
        for (int i = 0; i < loglist[log_id].priority_count; i++)
            ll->level [i] = loglist [log_id].priorities [i].level;
        ll->flags = loglist[log_id].flags;
        ll->count = loglist[log_id].priority_count;
        ll->mark = loglist [log_id].level;
    }
}


static void log_init (log_t *log)
{
    memset (log, 0, sizeof (*log));
    log->level = 2;
    log->trigger_level = 50*1024*1024;
    log->filename = NULL;
    log->logfile = NULL;
    log->buffer = NULL;
}


void log_initialize_lib (log_locking_t *locks)
{
    if (_initialized) return;
    logs_allocated = 0;
    loglist = NULL;
    if (locks)
        memcpy (&_locks, locks, sizeof (*locks));
    else
        memset (&_locks, 0, sizeof (*locks));

    if (_locks.rwc)
        _locks.rwc (&_logger_rwl, __FILE__, __LINE__, 3);
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
    loglist[log_id].log_head = NULL;
    loglist[log_id].log_tail = NULL;
    loglist[log_id].size = 0;
    loglist[log_id].flags = 0;
    loglist[log_id].reopen_at = 0;
    loglist[log_id].priority_count = 0;
    loglist[log_id].archive_timestamp = 0;
    if (_locks.mxc) _locks.mxc (&loglist [log_id].mutex, __FILE__, __LINE__, 3);

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
        _wlock_logger();
        free (loglist [id] . filename);
        loglist [id] . filename = strdup (filename);
        loglist [id].log_head = NULL;
        loglist [id].log_tail = NULL;
        loglist [id].logfile = NULL;
        loglist [id].size = 0;
        loglist [id].flags = 0;
        loglist [id].reopen_at = 0;
        loglist [id].archive_timestamp = 0;
        loglist [id].priority_count = 0;
        for (int i = 80; i ; i--)
        {
            log_entry_t *ent = calloc (1, sizeof (log_entry_t));
            ent->next = loglist [id].freed;
            loglist [id].freed = ent;
            loglist [id].freed_count++;
        }
        loglist [id].flags |= LOG_MARK_ID;
        if (_locks.mxc) _locks.mxc (&loglist [id].mutex, __FILE__, __LINE__, 3);
        _unlock_logger();
    }

    return id;
}


static void _set_priorities (int id, log_levels_t *level)
{
    if (loglist [id].in_use && loglist[id].log_head == NULL)
    {
        int count = level->count;
        log_priority_t *n = loglist[id].priorities;
        if (count != loglist[id].priority_count)
        {
            int newlen = count * sizeof (log_priority_t);
            n = realloc (loglist[id].priorities, newlen);
            if (n)
            {
                int oldlen = loglist[id].priority_count * sizeof (log_priority_t);
                memset (&n[loglist[id].priority_count], 0, newlen - oldlen);
                loglist[id].priorities = n;
                loglist[id].priority_count = count;
            }
        }
        for (int i=0; i < count; i++)
            loglist[id].priorities[i].level = level->level[i];
        loglist [id].level = level->mark;
        loglist [id].flags = (level->flags|LOG_MARK_ID);
    }
}


// called from first use if not set by user. will be read locked
//
static void default_set_priorities (int id)
{
    _unlock_logger();
    log_levels_t ll;
    _wlock_logger();
    log_init_levels (id, &ll, 1);
    _set_priorities (id, &ll);
    _unlock_logger();
    _lock_logger();
}


static void _release_entry (int log_id, log_entry_t *ent, int cache)
{
    if (ent == NULL) return;
    log_t *log = &loglist [log_id];
    if (cache && log->freed_count < 20)
    {
        ent->len = 0;
        ent->next = log->freed;
        log->freed = ent;
        log->freed_count++;
    }
    else
    {   // allow for some pruning in case
        free (ent);
    }
}

static void release_entry (int log_id, log_entry_t *ent, int cache)
{
    if (ent)
    {
        _lock_q (log_id);
        _release_entry (log_id, ent, cache);
        _unlock_q (log_id);
    }
}


static log_entry_t *_get_cached_entry (log_lineinfo_t *info)
{
    int id = info->id;
    log_t *log = &loglist [id];

    static uint64_t _next_eid = 1;

    _lock_q (id);
    uint64_t entry_id = _next_eid++;
    log_entry_t *ent = log->freed;
    while (1)
    {
        if (ent == NULL)
        {
            _unlock_q (id);
            ent = calloc (1, sizeof (log_entry_t));
        }
        else
        {
            log->freed_count--;
            log->freed = ent->next;
            _unlock_q (id);
            ent->next = NULL;
        }
        break;
    }
    ent->id = entry_id;
    int prelen = 0;
    if (info->flags & LOG_TIME)
    {
        prelen += 23;   // "[YYYY-MM-DD  HH:MM:SS] "
#ifdef HAVE_CLOCK_GETTIME
        clock_gettime (CLOCK_REALTIME, &ent->tstamp);
        const int ss = 10;  // .nS
#elif defined(HAVE_GETTIMEOFDAY)
        gettimeofday (&ent->tstamp, NULL);
        const int ss = 7;   // .uS
#else
        ent->tstamp.tv_sec = (uint64_t)time (NULL);
        const int ss = 1;
#endif
        if (loglist [id].flags & LOG_TIME_SS)
        {
            ent->flags |= LOG_TIME_SS;
            prelen += ss;        // "[YYYY-MM-DD  HH:MM:SS.*] "
        }
        ent->flags |= LOG_TIME;
    }
    ent->plen = prelen;
    ent->len = 0;
    ent->priority = info->priority;
    info->line = &ent->line[0];
    info->remain = LOG_MAXLINELEN;
    if (info->flags & LOG_MARK_ID)
    {
        int c = snprintf (&ent->line[0], LOG_MAXLINELEN, "%-24" PRIu64, entry_id);
        info->line += c;
        info->remain -= c;
    }
    return ent;
}


/* set the trigger level to trigger, represented in bytes */
void log_set_trigger(int id, unsigned long trigger)
{
    _wlock_logger();
    if (id >= 0 && id < LOG_MAXLOGS && loglist [id].in_use)
    {
        if (trigger < 100000)
            trigger = 100000;
        loglist [id] . trigger_level = trigger;
    }
    _unlock_logger();
}


void log_set_reopen_after (int id, unsigned int trigger)
{
    _wlock_logger();
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
    _wlock_logger();
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
     _wlock_logger();
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


// wrapper routine for compatability
void log_set_lines_kept (int log_id, unsigned int count)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
    if (count > 1000000) return;

    _wlock_logger ();
    log_levels_t ll;
    log_init_levels (log_id, &ll, 1);
    log_set_levels_keep (&ll, count);
    _set_priorities (log_id, &ll);

    _unlock_logger ();
}


void log_set_level(int log_id, unsigned level)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;

    uint16_t flags = level >> 8;
    loglist[log_id].flags |= (flags & LOG_TIME_SS);
    level &= 15;
    _wlock_logger();
    if (loglist[log_id].in_use)
        loglist[log_id].level = level;
    _unlock_logger();
}


void log_set_levels (int log_id, log_levels_t *levels)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
    _wlock_logger();
    _set_priorities (log_id, levels);
    _unlock_logger();
}


void log_set_levels_keep (log_levels_t *levels, unsigned int count)
{
    int i = levels->count == 1 ? 0 : 1;
    int remainder = count;
    int last = levels->count - 1;
    for (; i < last; i++)
    {
        int each = remainder/(levels->count-i);
        levels->level [i].keep = each;
        remainder -= each;
    }
    levels->level [i].keep = remainder;
}


void log_flush(int log_id)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
    if (loglist[log_id].in_use == 0) return;

    _wlock_logger();
    if (loglist[log_id].logfile)
        fflush(loglist[log_id].logfile);
    _unlock_logger();
}

void log_reopen(int log_id)
{
    if (log_id < 0 && log_id >= LOG_MAXLOGS)
        return;
    _wlock_logger();
    do
    {
        if (loglist [log_id] . filename == NULL || loglist [log_id].logfile == NULL)
            break;
        if (loglist [log_id].logfile)
        {
            fclose (loglist [log_id] . logfile);
            loglist [log_id].logfile = NULL;
        }
    } while (0);
    _unlock_logger();
}



// enter with q lock, exit with it unlock and destroyed
//
static void _log_close_internal (int log_id)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;

    for (int loop = 0; loop < 10; ++loop)
        if (do_log_run (log_id) == 0)
            break;

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
        _release_entry (log_id, to_go, 0);
    }
    while (loglist [log_id].freed)
    {
        log_entry_t *to_go = loglist [log_id].freed;
        loglist [log_id].freed = to_go->next;
        loglist [log_id].freed_count--;
        _release_entry (log_id, to_go, 0);
    }
    free (loglist [log_id].priorities);
    loglist [log_id].priorities = NULL;
    loglist [log_id].checked_entry = NULL;
    _unlock_q (log_id);
    if (_locks.mxc) _locks.mxc (&loglist [log_id].mutex, __FILE__, __LINE__, 0);
    loglist [log_id].in_use = 0;
}


void log_close(int log_id)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;

    _lock_logger();
    do
    {
        if (log_callback)
        {
            if (loglist [log_id].in_use != 1)
                break;
            _lock_q (log_id);
            loglist [log_id].flags |= LOG_CLOSING;
            _unlock_q (log_id);
            break;
        }
        _log_close_internal (log_id);
    } while (0);
    _unlock_logger();
}


void log_shutdown(void)
{
    if (_initialized == 0)
        return;
    int log_id;
    log_commit_entries ();
    // close 0 last as it is usually stderr
    for (log_id = 1; log_id < logs_allocated ; log_id++)
        log_close (log_id);
    log_close (0);
    log_commit_entries ();
    logs_allocated = 0;
    free (loglist);
    loglist = NULL;
    /* destroy mutexes */
    if (_locks.rwc)
        _locks.rwc (&_logger_rwl, __FILE__, __LINE__, 0);

    _initialized = 0;
}


static int _select_priority_entry (log_t *log)
{
    uint64_t earliest = log->checked_entry ? log->checked_entry->id : 0;
    int pri_id = -1;
    if (earliest > 0)
    {
        for (int i=0; i < log->priority_count; i++)
        {
           if (log->priorities[i].present <= log->priorities [i].level.keep)
               continue;
           if (log->priorities[i].head->id < earliest)
           {
              earliest = log->priorities[i].head->id;
              pri_id = i;
           }
        }
    }
    return pri_id;
}



static log_entry_t *log_entry_pop (int log_id)
{
    log_t *log = &loglist [log_id];
    int pri_id = _select_priority_entry (log);

    if (pri_id < 0)
        return NULL;
    log_entry_t *to_go = log->priorities[pri_id].head;
    // drop from priority list
    log->priorities[pri_id].head = to_go->next_on_priority;
    to_go->next_on_priority = NULL;
    log->priorities[pri_id].present--;
    int plen = (1 + to_go->len + to_go->plen);
    log->priorities[pri_id].size -= plen;

    // drop from timed list.
    if (to_go->prev)
        to_go->prev->next = to_go->next;
    else
        log->log_head = to_go->next;
    if (to_go->next)
        to_go->next->prev = to_go->prev;
    to_go->next = to_go->prev = NULL;
    return to_go;
}


static int _log_expand_preline (log_entry_t *next, char *preline, size_t prelen)
{
    int r = 0;
    if (next->flags & LOG_TIME)
    {
        struct tm thetime;
        time_t secs = next->tstamp.tv_sec;
        if (next->flags & LOG_TIME_SS)
        {
            r =  strftime (preline, prelen, "[%Y-%m-%d  %H:%M:%S", localtime_r(&secs, &thetime));
#ifdef HAVE_CLOCK_GETTIME
            r += snprintf (preline+r, prelen-r, ".%09ld] ", (long)next->tstamp.tv_nsec);
#else
            r += snprintf (preline+r, prelen-r, ".%06ld] ", (long)next->tstamp.tv_usec);
#endif
        }
        else
        {
            r = strftime (preline, prelen, "[%Y-%m-%d  %H:%M:%S] ", localtime_r(&secs, &thetime));
        }
    }
    return r;
}


// purge log entries back to least 1 on the specified log, assumes lock in use
//
static void do_purge (int log_id)
{
    int count = 0;
    while (1)
    {
        log_entry_t *to_go = log_entry_pop (log_id);

        if (to_go)
        {
            _release_entry (log_id, to_go, 1);
            if (++count > 50)
            {
                _unlock_q (log_id);
                count = 0; // reset count, allowing others to queue.
                _lock_q (log_id);
            }
            continue;
        }
        break;
    }
}


// flush out any waiting log entries
//
static int do_log_run (int log_id)
{
    log_entry_t *next, *checked;
    int loop = 0;
    int count = 0;

    checked = loglist [log_id].checked_entry;
    if (checked)
        next = checked->next;
    else
        next = loglist [log_id].log_head;
    if (next == NULL)
        return 0;
    log_run_t lr = { .id = log_id, .fsize = loglist [log_id].size, .now = time (NULL) };
    int flags = loglist [log_id].flags;

    while (next && _log_open (&lr))
    {
        checked = next;
        // fprintf (stderr, "   in log id %d, with (%s)\n", log_id, next->line);
        if (loglist [log_id].level >= next->priority)
        {
            _unlock_q (log_id);
            char preline [64] = "";
            _log_expand_preline (next, preline, sizeof preline);

            int len = fprintf (loglist [log_id].logfile, "%s%s\n", preline, _entry_line_start (flags, next));
            fflush (loglist [log_id].logfile);

            if (len > 0)
            {
#ifdef _WIN32
                len++;  // the \n translates to \r\n, but the return does not account for it
#endif
                lr.fsize += len;
            }
            loop = 0;
            count++;
            _lock_q (log_id);
        }
        else if (++loop > 50)
        {   // unlikely to trigger but provide an opening for the others
            _unlock_q (log_id);
            loop = 0;
            _lock_q (log_id);
        }
        next = next->next;
    }
    loglist [log_id].checked_entry = checked;
    loglist [log_id].size = lr.fsize;
    do_purge (log_id);
    return count;
}

void log_commit_entries ()
{
    int log_id, closing = 0;

    //fprintf (stderr, "in log commit\n");
    _lock_logger ();
    for (log_id = 0; log_id < logs_allocated ; log_id++)
    {
        if (loglist [log_id].in_use)
        {
            _lock_q (log_id);
            do_log_run (log_id);
            if (loglist [log_id].flags & LOG_CLOSING)
                closing++;
            _unlock_q (log_id);
        }
    }
    if (closing)
    {   // any logs flagged for closing then close them here under the main lock
        _unlock_logger ();
        _wlock_logger ();
        for (log_id = 0; closing && log_id < logs_allocated ; log_id++)
        {
            if (loglist [log_id].in_use && (loglist [log_id].flags & LOG_CLOSING))
            {
                _lock_q (log_id);
                _log_close_internal (log_id);
                closing--;
            }
        }
    }
    _unlock_logger ();
}


// set callback routine for whenever a log message is performed
//
void log_set_commit_callback (log_commit_callback f)
{
    log_callback = f;
}


static int queue_entry (int log_id, log_entry_t *ent)
{
    log_t *log = &loglist [log_id];
    log_priority_t *pri = &log->priorities [ent->priority];
    int plen = 1 + ent->plen + ent->len;    // add space for NL

    _lock_q (log_id);
    // timed order list update

    if (log->log_tail)
        log->log_tail->next = ent;
    else
        log->log_head = ent;
    ent->prev = log->log_tail;
    log->log_tail = ent;

    // priority order list update
    pri->size += plen;
    if (pri->tail)
        pri->tail->next_on_priority = ent;
    else
        pri->head = ent;

    pri->tail = ent;
    pri->present++;

    if (log_callback)
    {
        _unlock_q (log_id);
        //log_callback (log_id);
    }
    else
    {
        do_log_run (log_id);
        if (loglist [log_id].flags & LOG_CLOSING)
            _log_close_internal (log_id);   // log_close could of triggered
        else
            _unlock_q (log_id);
    }
    return 0;
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
        _wlock_logger ();  // normal initial route
        if (loglist [log_id].in_use == 0)
        {
            _unlock_logger ();
            return -1;
        }
        unsigned int len = 0;
        if (loglist [log_id].priorities)
        {
            int l = (level >= 0 && level < loglist[log_id].priority_count) ? level : loglist [log_id].level;
            while (1) {
                len += loglist [log_id].priorities [l].size;
                if (l == 0) break;
                l--;
            }
        }
        *_len = len;
        return 1;   // return without unlock as we expect to be called again after allocation
    }
    remain = *_len;

    if (level < 0)
        level = loglist[log_id].level;
    entry = loglist [log_id].log_head;
    ptr = *_contents;
    *ptr = '\0';
    while (entry && remain > 0)
    {
        if (entry->priority <= level)
        {
            char preline [64] = "";
            _log_expand_preline (entry, preline, sizeof preline);
            int len = snprintf (ptr, remain, "%s%s\n", preline, _entry_line_start (loglist [log_id].flags, entry));
            if (len < 0 || len > remain)
            {
                ptr [0] = 0;
                fprintf (stderr, "not enough space for content\n");
                break;
            }
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


static void lineinfo_complete (log_lineinfo_t *info, log_entry_t *ent)
{
    if (info->flags & LOG_MARK_ID)
        ent->len = LOG_MAXLINELEN - 24 - info->remain;
    else
        ent->len = LOG_MAXLINELEN - info->remain;
}


// helper function for the printfs in the write calls.
//
static int lineinfo_adj (log_lineinfo_t *info, int r)
{
    if (r < 0 || r > info->remain) return -1;
    if (r)
    {
        info->line += r;
        info->remain -= r;
    }
    return LOG_MAXLINELEN - info->remain;
}


void log_write(int log_id, unsigned priority, const char *cat, const char *func,
        const char *fmt, ...)
{
    const char *p = NULL;
    va_list ap;

    va_start(ap, fmt);
    _lock_logger();

    do {
        if (log_id < 0 || log_id >= LOG_MAXLOGS) break;         /* Bad log number */
        if (loglist[log_id].priority_count == 0)
            default_set_priorities (log_id);
        if (priority >= loglist[log_id].priority_count) break;  /* Bad priority */
        p = (loglist[log_id].priorities ? (loglist[log_id].priorities[priority].level.name) : "");

        log_lineinfo_t info = { .id = log_id, .priority = priority, .flags = loglist [log_id].flags|LOG_TIME };
        log_entry_t *entry = _get_cached_entry (&info);
        do
        {
            if (entry == NULL) break;
            if (lineinfo_adj (&info, snprintf  (info.line, info.remain, "%s %s%s ", p, cat, func)) < 0)
                break;
            if (lineinfo_adj (&info, vsnprintf (info.line, info.remain, fmt, ap)) < 0)
                break;
            lineinfo_complete (&info, entry);
            queue_entry (log_id, entry);
            entry = NULL;
        } while (0);
        release_entry (log_id, entry, 1);

    } while (0);
    _unlock_logger();
    va_end(ap);
}


void log_write_direct(int log_id, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _lock_logger();
    do
    {
        if (log_id < 0 || log_id >= LOG_MAXLOGS) break;
        if (loglist [log_id].in_use == 0) break;

        if (loglist[log_id].priority_count == 0)
            default_set_priorities (log_id);

        log_lineinfo_t info = { .id = log_id, .flags = loglist[log_id].flags };
        log_entry_t *entry = _get_cached_entry (&info);
        do
        {
            if (lineinfo_adj (&info, vsnprintf (info.line, info.remain, fmt, ap)) < 0)
                break;
            entry->len = lineinfo_adj (&info, 0);
            queue_entry (log_id, entry);
            entry = NULL;
        } while (0);
        release_entry (log_id, entry, 1);

    } while (0);
    _unlock_logger();
    va_end(ap);
}

static int _get_log_id(void)
{
    int i;
    int id = -1;

    /* lock mutex */
    _wlock_logger();

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

    _unlock_logger();

    return id;
}

