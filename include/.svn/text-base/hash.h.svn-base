/*
 * sessionlist.h - session tracking headers
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

#ifndef HASH_H
#define HASH_H

#include <sys/types.h>
#include <inttypes.h>
#include "search.h"
#include "extract.h"

#define FNV_PRIME         0x811C9DC5
#define SESSION_THRESHOLD 30        /** a session will stale out in 30s */
#define NFEX_HT_SIZE      33211     /** randomly chosen largish prime */

struct four_tuple
{
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
};
typedef struct four_tuple four_tuple_t;

struct hash_table_node
{
    four_tuple_t ft;                /* four tuple information */
    time_t timestamp;               /* the last time a packet was seen */
    srchptr_list_t *srchptr_list;   /* current search threads */
    extract_list_t *extract_list;   /* list of current files being extracted */
    struct hash_table_node *next;   /* next entry in the list */
    struct hash_table_node *prev;   /* prev entry in the list */
};
typedef struct hash_table_node ht_node_t;

#endif /* HASH_H */
