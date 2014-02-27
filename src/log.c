/*
 * log.c - log routines
 *
 * 2009, 2010 Mike Schiffman <mschiffm@cisco.com> 
 *
 * Copyright (c) 2010 by Cisco Systems, Inc.
 * All rights reserved.
 */

#include "nfex.h"

int
log_init(char *logfile, mmpd_t *m)
{
    m->log = fopen(logfile, "a");
    if (m->log == NULL)
    {
        return (-1);
    }

    return (1);
}

void
log_close(mmpd_t *m)
{
    fflush(m->log);
    fclose(m->log);
}

void
log_msg(u_int8_t priority, mmpd_t *m, char *fmt, ...)
{
    va_list args;
    char buf[MMP_LOG_MAX];
    time_t t;

    if (priority == MMP_LOG_DEBUG  && !(m->mmpd_flags & MMPD_DEBUG))
    {
        /** only log debug messages if debug mode is on */
        return;
    }

    memset(buf, 0, sizeof (buf));

    /** construct timestamp */
    t = time(NULL);
    ctime_r(&t, buf);
    /** replace newline with space */
    buf[24] = ' '; 

    /** set priority */
    switch (priority)
    {
        case MMP_LOG_FATAL:
            sprintf(&buf[strlen(buf)], "fatal: ");
            break;
        case MMP_LOG_ERROR:  
            sprintf(&buf[strlen(buf)], "error: ");
            break;
        case MMP_LOG_INFO:  
            sprintf(&buf[strlen(buf)], "info:  ");
            break;
        case MMP_LOG_DEBUG:  
            sprintf(&buf[strlen(buf)], "debug: ");
            break;
        default:
            sprintf(&buf[strlen(buf)], "unkwn: ");
            break;
    }

    va_start(args, fmt);
    vsprintf(&buf[strlen(buf)], fmt, args);

    fprintf(m->log, buf);
    va_end(args);
    fflush(m->log);

    /** VERBOSE mode means we'll dump everything to the console also */
    if (m->mmpd_flags & MMPD_VERBOSE)
    {
        printf("%s", buf);
    }
}

/** EOF */
