/*
 * sessionlist.c - session list stuff
 *
 * 2009, 2010 Mike Schiffman <mschiffm@cisco.com> 
 *
 * Copyright (c) 2010 by Cisco Systems, Inc.
 * All rights reserved.
 * Based off of tcpxtract by Nicholas Harbour.
 */

/* This file is part of
   Tcpxtract, a sniffer that extracts files based on headers
   by Nick Harbour
*/

#include "nfex.h"
#include "hash.h"
#include "extract.h"
#include "util.h"

ht_node_t *
ht_insert(four_tuple_t *ft, ncc_t *ncc)
{
    uint16_t n, j;
    ht_node_t *p;

    n = ht_hash(ft);

    if (ncc->ht[n] == NULL)
    {
        /** create first entry in this slot */
        ncc->ht[n] = malloc(sizeof (ht_node_t));
        if (ncc->ht[n] == NULL)
        {
            fprintf(stderr, "ht_insert(): malloc(): %s\n", strerror(errno));
            return (NULL);
        }
        memcpy(&(ncc->ht[n]->ft), ft, sizeof (four_tuple_t));
        ncc->ht[n]->timestamp    = time(NULL);
        ncc->ht[n]->srchptr_list = NULL;
        ncc->ht[n]->extract_list = NULL;
        ncc->ht[n]->next         = NULL; 
        ncc->ht[n]->prev         = NULL; 
        p = ncc->ht[n];

        /** update ht stats: non chained entry */
        ncc->stats.ht_nc++;
    }
    else  /** collision */
    {
        p = ht_find(ft, ncc);
        if (p)
        {
            return (p);
        }
        for (p = ncc->ht[n], j = 0; p->next; p = p->next, j++);
        /** end of chain, no duplicate, add a new one */
        p->next = malloc(sizeof (ht_node_t));
        if (p->next == NULL)
        {
            fprintf(stderr, "ht_insert(): malloc(): %s\n", strerror(errno));
            return (NULL);
        }
        memcpy(&(p->next->ft), ft, sizeof (four_tuple_t));
        p->next->timestamp    = time(NULL);
        p->next->srchptr_list = NULL;
        p->next->extract_list = NULL;
        p->next->next         = NULL; 
        p->next->prev         = p;

        /** update ht stats: chained entry */
        ncc->stats.ht_ic++; 
        /** update ht stats: longest chain */
        ncc->stats.ht_lc = j > ncc->stats.ht_lc ? j : ncc->stats.ht_lc;
    }

    if (ncc->flags & NFEX_DEBUG)
    {
        fprintf(stderr, "new session: ");
        fprintip(stderr, ft->ip_src, ncc);
        fprintf(stderr, ":%d -> ", ntohs(ft->port_src));
        fprintip(stderr, ft->ip_dst, ncc);
        fprintf(stderr, ":%d\n", ntohs(ft->port_dst));
    }

    /** update ht stats: total entries */
    ncc->stats.ht_entries++;
    return (p);
}


uint16_t
ht_hash(four_tuple_t *ft)
{
   int i;
   uint8_t *p;
   uint32_t hash;

   /* Fowler–Noll–Vo hash: http://en.wikipedia.org/wiki/Fowler_Noll_Vo_hash */
   for (hash = 0, i = 0, p = (uint8_t *)ft; i < 12; p++, i++)
   {
      hash *= FNV_PRIME;
      hash ^= (*p);
   }

   return (hash % NFEX_HT_SIZE);
}


ht_node_t *
ht_find(four_tuple_t *ft, ncc_t *ncc)
{
    uint16_t n;
    ht_node_t *p;

    n = ht_hash(ft);
    for (p = ncc->ht[n]; p; p = p->next)
    {
        if (memcmp(ft, &p->ft, sizeof (four_tuple_t)) == 0)
        {
            /** found him, update timestamp */
            p->timestamp = time(NULL);
            return (p);
        }
    }
    return (NULL);
}


void
ht_dump(ncc_t *ncc)
{
    time_t now;
    uint16_t n;
    ht_node_t *p;

    if (ncc->stats.ht_entries == 0)
    {
        printf("session table empty\n");
        return;
    }

    now = time(NULL);

    for (n = 0; n < NFEX_HT_SIZE; n++)
    {
        for (p = ncc->ht[n]; p; p = p->next)
        {
            fprintip(stdout, p->ft.ip_src, ncc);
            fprintf(stdout, ":%d -> ", ntohs(p->ft.port_src));
            fprintip(stdout, p->ft.ip_dst, ncc);
            fprintf(stdout, ":%d ", ntohs(p->ft.port_dst));
            fprintf(stdout, "%lds\n", now - p->timestamp);

        }
    }
}


void
ht_shutitdown(ncc_t *ncc)
{
    uint16_t n;
    ht_node_t *p, *q;

    for (n = 0; n < NFEX_HT_SIZE; n++)
    {
        for (p = ncc->ht[n]; p; p = q->next)
        {
            q = p;
            free (p);
        }
        ncc->ht[n] = NULL;
    }
    ncc->stats.ht_entries = 0;
}


void
ht_expire_session(ncc_t *ncc)
{
    time_t now;
    uint16_t n;
    uint32_t j;
    ht_node_t *p, **q;

    if (ncc->stats.ht_entries == 0)
    {
        printf("session table empty\n");
        return;
    }

    now = time(NULL);

    for (j = 0, n = 0; n < NFEX_HT_SIZE; n++)
    {
        for (p = ncc->ht[n]; p; p = p->next)
        {
            /** if the timestamp is older than SESSION_THRESHOLD, delete */
            if (now - p->timestamp >= SESSION_THRESHOLD)
            {
                if (p->prev == NULL)
                {
                    /** first entry in a chain */
                    free(p);
                    ncc->ht[n] = NULL;
		    /** update ht stats: non chained entry */
                    ncc->stats.ht_nc--;
                }
                else
                {
                    p->prev->next = p->next;
                    if (p->next)
                    {
                        p->next->prev = p->prev;
                    }
                    free(p);
		    /** update ht stats: chained entry */
                    ncc->stats.ht_ic--;
                }
                j++;
                /** update ht stats: total entries */
                ncc->stats.ht_entries--;
            }
        }
    }
    if (j && ncc->flags & NFEX_DEBUG)
    {
        printf("[DEBUG MODE] expired %d sessions from hash table\n", j);
    }
}


uint32_t
ht_count_extracts(ncc_t *ncc)
{
    uint16_t n, j;
    ht_node_t *p;

    for (n = 0, j = 0; n < NFEX_HT_SIZE; n++)
    {
        for (p = ncc->ht[n]; p; p = p->next)
        {
            if (p->extract_list)
            {
                if (p->extract_list->fd)
                {
                    j++;
                }
            }
        }
    }
    return (j);
}


void
ht_status(ncc_t *ncc)
{
    uint16_t n;

    if (ncc->stats.ht_entries == 0)
    {
        printf("session table empty\n");
        return;
    }

    printf("hash table status\n");
    printf("table size:\t\t\t%d\n", NFEX_HT_SIZE);
    printf("table population:\t\t%d\n", ncc->stats.ht_entries);
    printf("un-chained entries:\t\t%d\n", ncc->stats.ht_nc);
    printf("chained entries:\t\t%d\n", ncc->stats.ht_ic);
    printf("longest chain:\t\t\t%d\n", ncc->stats.ht_lc);
}

/** EOF */
