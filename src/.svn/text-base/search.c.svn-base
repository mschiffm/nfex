/*
 * search.c - searching routines
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
#include "util.h"
#include "search.h"
#include "conf.h"

static size_t currlen;

void
search_compile(srch_node_t **srch_tree, int id, char *ext, u_long maxlen, 
char *spec, spectype_t type)
{
    srch_node_t *p;
    int ch, i, speclen;
    char c, code[3] = {'\0'};

    /** length of the raw HEADER or FOOTER (specifier) from config file */
    speclen = strlen(spec);
    if (speclen == 0)
    {
        return;
    }

    /** is this the first node? */
    if (*srch_tree == NULL)
    {
        *srch_tree = new_srch_node(TABLE);
    }

    i       = 0;
    currlen = 0;
    p       = *srch_tree;

    /** step through the HEADER or FOOTER and process it piece by piece */
    while (i < speclen)
    {
        if (spec[i] == '\\')
        {
            if (i + 1 >= speclen)
            {
                error("dangling \'\\\' in file type specifier");
            }
            switch (spec[++i])
            {
                case '\\':
                    p = add_simple(p, '\\', speclen - i, id, ext, maxlen, type);
                    break;
                case 'x':
                    if (i + 2 >= speclen)
                    {
                        error("invalid hex code in file type specifier");
                    }
                    code[0] = spec[++i];
                    code[1] = spec[++i];
                    sscanf(code, "%02x", &ch);
                    c = (char)ch;
                    p = add_simple(p, c, speclen - i, id, ext, maxlen, type);
                    break;
                case 'n':
                    p = add_simple(p, '\n', speclen - i, id, ext, maxlen, type);
                    break;
                case 't':
                    p = add_simple(p, '\t', speclen - i, id, ext, maxlen, type);
                    break;
                case 'r':
                    p = add_simple(p, '\r', speclen - i, id, ext, maxlen, type);
                    break;
                case '0':
                    p = add_simple(p, '\0', speclen - i, id, ext, maxlen, type);
                    break;
                case '?':
                    p = add_wildcard(p, speclen - i, id, ext, maxlen, type);
                    break;
                default:
                    error("invalid escape character in file format specifier");
                    break;
            }
        }
        else
        {
            p = add_simple(p, spec[i], speclen - i, id, ext, maxlen, type);
        }
        i++;
    }

    /** this assumes node_ptr is pointing to a COMPLETE node */
    p->data.fileid.len = currlen;
}


static srch_node_t *
new_srch_node(srch_nodetype_t nodetype)
{
    srch_node_t *p;

    //XXX will this break? orig code: p = ecalloc(sizeof (srch_node_t), 1);
    p = ecalloc(1, sizeof (srch_node_t));
    p->nodetype = nodetype;

    return (p);
}


static srch_node_t *
add_simple(srch_node_t *node, uint8_t c, int remaining, int id, char *ext, 
unsigned long maxlen, spectype_t type)
{
    srch_node_t *p, *q;
    
    currlen++;

    if (remaining == 1)
    {   
        /** if remaining is 1 then we need to point to a COMPLETE node */
        p                     = new_srch_node(COMPLETE);
        p->spectype           = type;
        p->data.fileid.id     = id;
        p->data.fileid.ext    = ext;
        p->data.fileid.maxlen = maxlen;
        node->data.table[c]   = p;
        q                     = p;
    }
    else if (node->data.table[c] == NULL)
    {
        p                   = new_srch_node(TABLE);
        node->data.table[c] = p;
        q                   = p;
    }
    else
    {
        q = node->data.table[c];
    }

    return (q);
}


static srch_node_t *
add_wildcard(srch_node_t *node, int remaining, int id, char *ext, unsigned long maxlen, spectype_t type)
{
    srch_node_t *p;
    int i;
    
    currlen++;

    if (remaining == 1)
    {   
        /** if remaining is 1 then we need to point to a COMPLETE node */
        p                     = new_srch_node(COMPLETE);
        p->spectype           = type;
        p->data.fileid.id     = id;
        p->data.fileid.ext    = ext;
        p->data.fileid.maxlen = maxlen;
        for (i = 0; i < 256; i++)
        {
            /** a specific char trumps a wildcard */
            if (node->data.table[i] == NULL)
            {
                /** shhh, that indicates a slight "feature" */
                node->data.table[i] = p;  
            }
        }
        return (p);
    }
    else
    {
        p = new_srch_node(TABLE);
        for (i = 0; i < 256; i++)
        {
            if (node->data.table[i] == NULL)
            {
                node->data.table[i] = p;
            }
        }
        return (p);
    }
}

/*
 * the overall search interface.  You call this bad boy and give it a
 * pointer to your data buffer (i.e. a packet)
 */
srch_results_t *
search(srch_node_t *tree, srchptr_list_t **srchptr_list, uint8_t *buf, 
size_t len)
{
    srch_results_t *p;
    int i;
    
    /** called once for every byte of data in the payload */
    for (p = NULL, i = 0; i < len; i++)
    {
        /** can this be optimized, can we run on blocks of data? */
        update_search(tree, srchptr_list, &p, buf[i], i); 
    }

    return (p);
}

static void
add_srchptr(srchptr_list_t **srchptr_list, srch_node_t *node)
{
    srchptr_list_t *p, *q;

    p = ecalloc(1, sizeof (srchptr_list_t));

    /** make this guy the front of the list */
    p->next = *srchptr_list;

    if (p->next)
    {
        /** fix pointer linkage */
        p->next->prev = p;
    }
    p->node       = node;
    *srchptr_list = p;

    //for (q = p->next; q && q != p; q = q->next) ;
}

static void
remv_srchptr(srchptr_list_t **srchptr_list, srchptr_list_t *p)
{
    if (p->prev)
    {
        p->prev->next = p->next;
    }

    if (p->next)
    {
        p->next->prev = p->prev;
    }

    if (*srchptr_list == p)
    {
        *srchptr_list = p->next;
    }

    free(p);
}

/*
 * I sincerely apologize for this function.  This is called once for every 
 * byte of data so I don't want to waste cycles with layers and layers of 
 * function calls. The end result is a long, complex and unmaintainable 
 * function that is quick
 *
 * The inner demon of the search mechanism.  This updates all state machine 
 * pointers with the current character and fixes the search results list 
 * appropriately
 *
 * FIXME: perhaps make this inline for speed
 */
static void
update_search(srch_node_t *tree, srchptr_list_t **srchptr_list, 
srch_results_t **results, uint8_t c, int offset)
{
    srch_node_t *node;
    srchptr_list_t *ptr;
    srchptr_list_t *nxt;

    if (*srchptr_list)
    {   
        /** start by updating existing threads */
        for (ptr = *srchptr_list; ptr; ptr = nxt)
        {
            nxt = ptr->next;
            if (ptr->node->data.table[c])
            {
                srch_node_t *node = ptr->node->data.table[c];
                switch (node->nodetype)
                {
                    case TABLE:
                        ptr->node = node;
                        break;
                    case COMPLETE:
                        add_result(results, &node->data.fileid, node->spectype,
                            offset);
                        remv_srchptr(srchptr_list, ptr);
                        break;
                    default:
                        error("Unknown node type");
                        break;
                }
            }
            else
            {
                remv_srchptr(srchptr_list, ptr);
            }
        }
    }

    /** now see if we want to start a new thread (i.e. a new potential match) */
    if (tree->data.table[c])
    {
        node = tree->data.table[c];
        switch (node->nodetype)
        {
            case TABLE:
                /** this should be 99.99% of them */
                add_srchptr(srchptr_list, node);
                break;
            case COMPLETE:
                /** In the unlikely event of a one byte header */
                add_result(results, &node->data.fileid, node->spectype, offset);
                break;
            default:
                error("Unknown node type");
                break;     
        }
    }
}

static void
update_search2(srch_node_t *tree, srchptr_list_t **srchptr_list, 
srch_results_t **results, uint8_t c, int offset)
{
    if (*srchptr_list)
    {   /** start by updating existing threads */
        srchptr_list_t *ptr;
        srchptr_list_t *nxt = NULL, *prv = NULL;
                
        for (ptr = *srchptr_list; ptr; prv = ptr, nxt = ptr->next, ptr = nxt)
        {
            if (ptr->node->data.table[c])
            {
                srch_node_t *node = ptr->node->data.table[c];
                switch (node->nodetype)
                {
                    case TABLE:
                        ptr->node = node;
                        break;
                    case COMPLETE:
                        add_result(results, &node->data.fileid, node->spectype,
                            offset);
                    
                        /* remove thread from list */
                        if (prv)
                        {
                            prv->next = nxt;
                        }
                        else
                        {
                            *srchptr_list = nxt;
                        }
                        if (nxt)
                        {
                            nxt->prev = prv;
                        }
                        free(ptr);
                        break;
                    default:
                        error("Unknown node type");
                        break;
                }
            }
            else
            { /*remove thread from list */
                if (prv)
                {
                    prv->next = nxt;
                }
                else
                {
                    *srchptr_list = nxt;
                }
                if (nxt)
                {
                    nxt->prev = prv;
                }
                free(ptr);
            }
        }
    }

    /* now see if we want to start a new thread (i.e. a new potential match) */
    if (tree->data.table[c])
    {
        srch_node_t *node = tree->data.table[c];
        srchptr_list_t *ptr;

        switch (node->nodetype)
        {
        case TABLE:            /* this should be 99.99% of them */
            if (*srchptr_list == NULL)
            {
                *srchptr_list = ecalloc(1, sizeof **srchptr_list);
                (*srchptr_list)->next = NULL;
                (*srchptr_list)->prev = NULL;
                ptr = *srchptr_list;
            }
            else
            {
                for (ptr = *srchptr_list; ptr->next; ptr = ptr->next);
                ptr->next = emalloc(sizeof *ptr->next);
                ptr->next->prev = ptr;
                ptr = ptr->next;
                ptr->next = NULL;
            }
            ptr->node = node;
            break;
        case COMPLETE:       /* In the unlikely event of a one byte header */
            add_result(results, &node->data.fileid, node->spectype, offset);
            break;
        default:
            error("Unknown node type");
            break;     
        }
    }
}

/* Add a result to a results list, allocating as needed */
static void 
add_result(srch_results_t **results, fileid_t *fileid, spectype_t spectype, 
int offset)
{
    srch_results_t **ptr, *prev = NULL;

    /* find the last element in the list, for setting prev */
    for (ptr = results; *ptr && (*ptr)->next; ptr = &(*ptr)->next);

    if (*ptr)
    {
        prev = *ptr;
        ptr = &(*ptr)->next;
    }
        
    *ptr = emalloc(sizeof **ptr);
    (*ptr)->next = NULL;
    (*ptr)->prev = NULL;
    (*ptr)->fileid = fileid;
    (*ptr)->spectype = spectype;
    (*ptr)->offset.start = offset - (fileid->len - 1);
    (*ptr)->offset.end = offset;
}

void
free_results_list(srch_results_t **results)
{
    srch_results_t *rptr, *nxt;

    for (rptr = *results; rptr; rptr = nxt)
    {
        nxt = rptr->next;
        free(rptr);
    }
    *results = NULL;
}

/* EOF */
