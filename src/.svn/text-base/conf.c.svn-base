/*
 * conf.c - main program driver
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
#include "conf.h"

static int id;

void
config_type(char *extension, char *maxlength, char *hspec, char *fspec, void *a)
{
    unsigned long maxlen;
    ncc_t *ncc;

    ncc = (ncc_t *)a;

    if (!sscanf(maxlength, "%lu", &maxlen))
    {
        error("Invalid maximum length in file format specifier");
    }

    search_compile(&(ncc->srch_machine), id, strdup(extension), maxlen, hspec, 
            HEADER);

    /** if a footer is specified in the confi file, compile it here */
    if (fspec)
    {
        search_compile(&(ncc->srch_machine), id, strdup(extension), maxlen, 
            fspec, FOOTER);
    }
    id++;
    printf("%2d %s search code compiled (%ld byte max)\n", id, extension, 
            maxlen);
}

/** EOF */
