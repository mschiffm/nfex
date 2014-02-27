/*
 * extract.c - extraction routines
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
#include "extract.h"
#include "util.h"
#include "config.h"

/*
 * called once for each packet, this function starts, updates, and closes
 * file extractions.  this is the one-stop-shop for all your file extraction 
 * needs
 */
void
extract(extract_list_t **elist, srch_results_t *results, ht_node_t *session, 
const uint8_t *data, size_t size, ncc_t *ncc)
{
    srch_results_t *r;
    extract_list_t *e;

    /*
     * set all existing segment values to what they would be with no search 
     * results
     */
    for (e = *elist; e; e = e->next)
    {
        set_segment_marks(e, size);
    }

    /** look for new headers in the results set */
    for (r = results; r; r = r->next)
    {
        if (r->spectype == HEADER)
        {
            add_extract(elist, r->fileid, session, r->offset.start, 
                size, ncc);
        }
    }

    /** flip through any footers we found and close out those extracts */
    for (r = results; r; r = r->next)
    {
        if (r->spectype == FOOTER)
        {
            mark_footer(*elist, r);
        }
    }

    /** now lets do all the file writing and whatnot */
    for (e = *elist; e; e = e->next)
    {
        extract_segment(e, data, ncc);
    }

    /** remove any finished extractions from the list */
    sweep_extract_list(elist);
}

/* Add a new header match to the list of files being extracted */
static void
add_extract(extract_list_t **elist, fileid_t *fileid, ht_node_t *session, 
int offset, int size, ncc_t *ncc)
{
    int n;
    char *q;
    extract_list_t *p;
    char fname[FILENAME_BUFFER_SIZE] = {'\0'};


    /** open the file descriptor that we'll extract into */
    q = fname;
    n = open_extract(fileid->ext, session->ft.ip_src, session->ft.port_src,
            session->ft.ip_dst, session->ft.port_dst, &q, ncc);
    if (n == -1)
    {
        if (ncc->flags & NFEX_VERBOSE)
        {
            fprintf(stderr, "error extracting \"%s\" (", fileid->ext);
            fprintip(stderr, session->ft.ip_src, ncc);
            fprintf(stderr, ":%d -> ", ntohs(session->ft.port_src));
            fprintip(stderr, session->ft.ip_dst, ncc);
            fprintf(stderr, ":%d) to %s\n", ntohs(session->ft.port_dst), fname);
        }
        else
        {
            fprintf(stderr, "error extracting \"%s\" file\n", fileid->ext);
        }
        /** flag for removal */
        //p->finish++;
        return;
    }
    if (ncc->flags & NFEX_VERBOSE)
    {
        fprintf(stdout, "extracting \"%s\" (", fileid->ext);
        fprintip(stdout, session->ft.ip_src, ncc);
        fprintf(stdout, ":%d -> ", ntohs(session->ft.port_src));
        fprintip(stdout, session->ft.ip_dst, ncc);
        fprintf(stdout, ":%d) to %s\n", ntohs(session->ft.port_dst), fname);
    }
    ncc->stats.total_files++;

    /** add new entry to the front extract linked list */
    p = malloc(sizeof (*p));
    if (p == NULL)
    {
        fprintf(stderr, "malloc(): %s\n", strerror(errno));
        return;
    }
    memset(p, 0, sizeof (*p));

    p->next      = *elist;
    p->fileid    = fileid;
    p->timestamp = time(NULL);
    p->fd        = n;
    if (p->next)
    {
        p->next->prev = p;
    }

    p->segment.start = offset;
    if (fileid->maxlen <= size - offset)
    {
        p->segment.end = offset + fileid->maxlen;
    }
    else   
    {
        p->segment.end = size;
    }
    *elist = p;
}

/** open the next availible filename for writing */
static int 
open_extract(char *ext, uint32_t src_ip, uint16_t src_prt, uint32_t dst_ip, 
uint16_t dst_prt, char **fname, ncc_t *ncc)
{
    int n;
    uint8_t ip_addr_s[4], ip_addr_d[4];
    struct tm *time_machine;
    char timestamp[50] = {'\0'};

    /** build file name */
    ncc->filenum++;
    snprintf(*fname, FILENAME_BUFFER_SIZE, "%s%d-%06d.%s", 
        ncc->output_dir == NULL ? "" : ncc->output_dir, 
        getpid(), ncc->filenum, ext);

    /** open file */
    n = open(*fname, O_WRONLY|O_CREAT|O_EXCL, S_IRWXU|S_IRWXG|S_IRWXO);
    if (n == -1)
    {
        fprintf(stderr, "error opening file: %s: %s\n", *fname, 
            strerror(errno));
        ncc->stats.extraction_errors++;
        return (-1);
    }

    /** write out details to index file */
    fprintf(ncc->indexfp, "%s, ", ncc->device ? "live-capture" : ncc->capfname);
    memcpy(ip_addr_s, &src_ip, 4);
    memcpy(ip_addr_d, &dst_ip, 4);

    time_machine = gmtime(&ncc->stats.ts_last.tv_sec);
    strftime(timestamp, 50, "%Y-%m-%dT%H:%M:%S", time_machine);

    fprintf(ncc->indexfp, 
           "%s.%ldZ, %d.%d.%d.%d.%d, %d.%d.%d.%d.%d, %d-%06d.%s\n",
           timestamp, (long)ncc->stats.ts_last.tv_usec,
           ip_addr_s[0], ip_addr_s[1], ip_addr_s[2], ip_addr_s[3], 
           ntohs(src_prt),
           ip_addr_d[0], ip_addr_d[1], ip_addr_d[2], ip_addr_d[3],
           ntohs(dst_prt), getpid(), ncc->filenum, ext);

    fflush(ncc->indexfp);
    return (n);
}

/*
 * set segment start and end values to the contraints of the data buffer or 
 * maxlen
 */
static void
set_segment_marks(extract_list_t *elist, size_t size)
{
    extract_list_t *p;

    for (p = elist; p; p = p->next)
    {
        p->segment.start = 0;
        if (p->fileid->maxlen - p->nwritten < size)
        {
            p->segment.end = p->fileid->maxlen - p->nwritten;
            p->finish++;
        }
        else
        {
            p->segment.end = size;
        }
    }
}

/** adjust segment end values depending on footers found */
static void
mark_footer(extract_list_t *elist, srch_results_t *footer)
{
    extract_list_t *p;

    /*
     * this associates the first footer found with the last header found of a 
     * given type this is to accommodate embedded document types.  Somebody 
     * may have differing needs so this may want to be reworked later...
     */
    for (p = elist; p; p = p->next)
    {
        if (footer->fileid->id == p->fileid->id && 
            p->segment.start < footer->offset.start)
        {
            /** XXX this could extend beyond maxlen */
            p->segment.end = footer->offset.end;
            p->finish++;
            break;
        }
    }
}

/** write data to a specified extract file */
static void
extract_segment(extract_list_t *p, const uint8_t *data, ncc_t *ncc)
{
    size_t c, nbytes;

    nbytes = p->segment.end - p->segment.start;

    /** update timestamp */
    p->timestamp = time(NULL);
    c = write(p->fd, data + p->segment.start, nbytes);
    if (c != nbytes)
    {
        fprintf(stderr, "error writing fd: %d, wrote %ld of %ld bytes: %s\n", 
            p->fd, c, nbytes, strerror(errno));
        ncc->stats.extraction_errors++;
        return; 
    }
    p->nwritten += nbytes;
    sync();
}

/** remove all finished extracts from the list */
static void
sweep_extract_list(extract_list_t **elist)
{
    time_t now;
    extract_list_t *p, *nxt;

    now = time(NULL);
    for (p = *elist; p; p = p->next)
    {
        /** remove all finished or expired extracts */
        if (p->finish || (now - p->timestamp >= SESSION_THRESHOLD))
        {
//if ((now - p->timestamp >= SESSION_THRESHOLD)) fprintf(stderr, "******************expire\n");
//if (p->finish) fprintf(stderr, "*************finish\n");
            if (p->prev)
            {
                p->prev->next = p->next;
            }
            if (p->next)
            {
                p->next->prev = p->prev;
            }
            if (*elist == p)
            {
                *elist = p->next;
            }
            close(p->fd);
            free(p);
        }
    }
}

/** EOF */
