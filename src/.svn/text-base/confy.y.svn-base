%{ /* -*-fundamental-*- */
/* $Id$ */
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

#include <stdlib.h>
#include "conf.h"
%}

%union {
     char *string;
}

%token <string> NUMBER 
%token <string> WORD
%token <string> SPECIFIER
%token ENDLINE
%parse-param {void *a}
%%


expressionlist: expression
	| expressionlist expression
	;

expression: WORD '(' NUMBER ',' SPECIFIER ')' ENDLINE			{config_type($1, $3, $5, NULL, a);}
	|	WORD '(' NUMBER ',' SPECIFIER ',' SPECIFIER ')' ENDLINE {config_type($1, $3, $5, $7, a);}
	|	WORD '(' NUMBER ',' SPECIFIER ',' NUMBER ')' ENDLINE 	{config_type($1, $3, $5, $7, a);}
	|	WORD '(' NUMBER ',' SPECIFIER ',' WORD ')' ENDLINE 		{config_type($1, $3, $5, $7, a);}
	|	WORD '(' NUMBER ',' WORD ')' ENDLINE					{config_type($1, $3, $5, NULL, a);}
	|	WORD '(' NUMBER ',' WORD ',' SPECIFIER ')' ENDLINE		{config_type($1, $3, $5, $7, a);}
	|	WORD '(' NUMBER ',' WORD ',' NUMBER	')' ENDLINE			{config_type($1, $3, $5, $7, a);}
	|	WORD '(' NUMBER ',' WORD ',' WORD ')' ENDLINE			{config_type($1, $3, $5, $7, a);}
	|	WORD '(' NUMBER ',' NUMBER ')' ENDLINE					{config_type($1, $3, $5, NULL, a);}
	|	WORD '(' NUMBER ',' NUMBER ',' SPECIFIER ')' ENDLINE	{config_type($1, $3, $5, $7, a);}
	|	WORD '(' NUMBER ',' NUMBER ',' NUMBER ')' ENDLINE		{config_type($1, $3, $5, $7, a);}
	|	WORD '(' NUMBER ',' NUMBER ',' WORD ')' ENDLINE			{config_type($1, $3, $5, $7, a);}
	;

%%
#include <stdio.h>
yyerror(char *s)
{
	printf("%s\n", s);
}
