/*
 * extract.h - extraction header stuff
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

#ifndef EXTRACT_H
#define EXTRACT_H

#include <sys/types.h>
#include <inttypes.h>
#include "search.h"

#ifndef FILENAME_BUFFER_SIZE
#define FILENAME_BUFFER_SIZE 4096
#endif

struct extract_list
{
    struct extract_list *next;
    struct extract_list *prev;
    fileid_t *fileid;        /* the data about the file type */
    time_t timestamp;        /* update this guy everytime we touch him */
    int fd;                  /* file descriptor to write data to file */
    off_t nwritten;          /* number of bytes written */
    struct
    {                        /* this struct defines the area to be written */
        int start;
        int end;
    } segment;
    int finish;              /* set when a FOOTER is found */
};
typedef struct extract_list extract_list_t;

#endif /* EXTRACT_H */
