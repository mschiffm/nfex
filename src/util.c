/*
 * util.c - utilities
 *
 * 2009, 2010 Mike Schiffman <mschiffm@cisco.com> 
 *
 * Copyright (c) 2010 by Cisco Systems, Inc.
 * All rights reserved.
 * Based off of tcpxtract by Nicholas Harbour.
 */

/* Copyright (C) 2005 Nicholas Harbour
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* This file is part of
   Tcpxtract, a sniffer that extracts files based on headers
   by Nick Harbour
*/

#include "nfex.h"
#include <stdarg.h>
#include <math.h>

void
fprintip(FILE *stream, uint32_t ip, ncc_t *ncc)
{
    uint8_t addr[4];
#if (HAVE_GEOIP)
    GeoIPRecord *gir;
#endif

#if (HAVE_GEOIP)
        if (((ncc->flags) & NFEX_GEOIP) && ncc->gi)
        {
            gir = GeoIP_record_by_ipnum(ncc->gi, ntohl(ip));
            if (gir == NULL)
            {
                /** fall back on printing the IP address */
                goto print_simple;
            }
            if (gir->city && gir->country_code)
            {
                fprintf(stream, "%s, %s", gir->city, gir->country_code);
                return;
            }
            if (gir->city && gir->country_code == NULL)
            {
                fprintf(stream, "%s, ?", gir->city);
                return;
            }
            if (gir->city == NULL && gir->country_code)
            {
                fprintf(stream, "?, %s", gir->country_code);
                return;
            }
            if (gir->city == NULL && gir->country_code == NULL)
            {
                goto print_simple;
            }
        }
#else
        goto print_simple;
#endif /** HAVE_GEOIP */

print_simple:
    memcpy(addr, &ip, 4);
    fprintf(stream, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);

    return;
}

void *
emalloc(size_t size)
{
    void *p = malloc(size);

    if (p == NULL)
    {
        perror("Error in function emalloc()");
        exit(0);
    }

    return (p);
}

void *
ecalloc(size_t nmemb, size_t size)
{
    void *p = calloc(nmemb, size);

    if (p == NULL)
    {
        perror("Error in function ecalloc()");
        exit(0);
    }

    return (p);
}

void
error(char *msg)
{
    fprintf(stderr, "%s", msg);
    exit(EXIT_FAILURE);
}

void
convert_seconds(u_int32_t seconds, u_int32_t *d, u_int32_t *h, u_int32_t *m,
u_int32_t *s)
{
    u_int32_t d1, s1;

    d1 = floor(seconds / 86400);
    s1 = seconds - 86400 * d1;

    if (s1 < 0)
    {
        d1 -= 1;
        s1 += 86400;
    }

    *d = d1;
    *s = s1;

    *h = floor((*s) / 3600);
    *s -= 3600 * (*h);

    *m = floor((*s) / 60);
    *s -= 60 * (*m);
}

/** modified from tcpdump.c */
void
build_bpf_filter(register char **argv, char **buf)
{
    register char **p;
    register u_int len = 0;
    char *src, *dst;

    p = argv;
    if (*p == 0)
    {
        /** our default filter of "tcp" */
        strncpy(*buf, NFEX_PCAP_FILTER, 127);
        return;
    }

    /** bpf filter specified at commmand line, process tokenized input */
    while (*p)
    {
        len += strlen(*p++) + 1;
    }
    p = argv;
    dst = *buf;
    while ((src = *p++))
    {
        while ((*dst++ = *src++) != '\0');
        dst[-1] = ' ';
    }
    dst[-1] = '\0';
}


/** EOF */
