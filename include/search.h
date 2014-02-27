/*
 * search.h - lookie n find
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

#ifndef SEARCH_H
#define SEARCH_H

#include <sys/types.h>
#include <inttypes.h>

/** search node types */
enum srch_nodetype
{
    TABLE,
    COMPLETE
} srch_nodetype;
typedef enum srch_nodetype srch_nodetype_t;

/** specifier types */
enum spectype
{
    HEADER,
    FOOTER
} spectype;
typedef enum spectype spectype_t;

/** file identifier */
struct fileid
{
    int id;           /* id number of search pattern */
    char *ext;        /* file extension canonical type */
    u_long maxlen;    /* maximum length of file */
    size_t len;       /* the length of the HEADER or FOOTER */
};
typedef struct fileid fileid_t;

/** the compiled form of a set of search keywords */
struct srch_node
{
    srch_nodetype_t nodetype;          /* node type */
    spectype_t spectype;               /* specifier type */
    union
    {
        struct srch_node *table[256];  /* table of search node pointers */
        fileid_t fileid;               /* or a file identifier */
    } data;
};
typedef struct srch_node srch_node_t;

/** the list of concurrent search threads */
struct srchptr_list
{
    struct srchptr_list *next;         /* next entry in the list */
    struct srchptr_list *prev;         /* prev entry in the list */
    srch_node_t *node;                 /* a search node set */
};
typedef struct srchptr_list srchptr_list_t;

struct srch_results
{
    struct srch_results *next;         /* next entry in the list */
    struct srch_results *prev;         /* prev entry in the list */
    fileid_t *fileid;                  /* file identifier */
    spectype_t spectype;               /* specifier type */
    struct
    {
        int start;                     /* for HEADERs */
        int end;                       /* for FOOTERs */
    } offset;
};
typedef struct srch_results srch_results_t;

void search_compile(srch_node_t **, int, char *, u_long, char *, spectype_t);
extern srch_results_t *search(srch_node_t *, srchptr_list_t **, uint8_t *, 
size_t);
extern void free_results_list(srch_results_t **);

static srch_node_t *new_srch_node(srch_nodetype_t);
static srch_node_t *add_simple(srch_node_t *, uint8_t, int, int, char *,
unsigned long, spectype_t);
static srch_node_t *add_wildcard(srch_node_t *, int, int, char *,
unsigned long, spectype_t);
static void update_search(srch_node_t *, srchptr_list_t **, srch_results_t **,
uint8_t, int);
static void add_result(srch_results_t **, fileid_t *, spectype_t, int);

#endif /* SEARCH_H */
