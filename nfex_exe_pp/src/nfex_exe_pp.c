/*
 * nfex_exe_pp.c - post process nfex binaries looking for PE32s and malware
 *
 *  2009, 2010 Mike Schiffman <mschiffm@cisco.com> 
 *
 * Copyright (c) 2010 by Cisco Systems, Inc.
 * All rights reserved.
 */

/*
 * New logfile format:
 *
 * pcap, timestamp, srcip.port, dstip.port, filename, canonical malware name
 *
 * pcap:         path to original pcap file containting the extracted exe's
 * timestamp:    relative timestamp to start of packet as reported by pcap
 * srcip.port:   soruce ip address and source port
 * srcip.port:   destination ip addess and destination port
 * filename:     new filename for extracted binary: PID-counter-md5.exe
 * malware name: as reported by clamav; "name" or "*UNKNOWN" or "*ERROR"
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/types.h>
#include <strings.h>
#include <string.h>
#include "config.h"
#include <clamav.h>
#include "md5/global.h"
#include "md5/md5.h"
#include "pe32.h"

#define CLAMAV_UNKNOWN "*UNKNOWN"
#define CLAMAV_ERROR   "*ERROR"

struct cl_engine *clamav_init();
void md5file(int, unsigned char *);
void usage(char *);

int
main(int argc, char *argv[])
{
    int c, i, j, m, n, fd; 
    uint32_t pehdr, pesig;
    struct cl_engine *engine;
    FILE *oldlog, *newlog;
    char p[256], pp[128];
    unsigned char md5[16];
    char *q, *src_file, *timestamp, *src_ip, *dst_ip, *filename, *suffix;
    const char *vname;
    unsigned long int size;
    uint8_t b[512];
    dos_hdr_t *dos;

    if (argc != 2)
    {
        usage(argv[0]);
    }

    while ((c = getopt(argc, argv, "hv")) != EOF)
    {
        switch (c)
        {
            case 'h':
                usage(argv[0]);
                break;
            case 'v':
                printf("%s v%s\n", PACKAGE, VERSION);
                return (EXIT_SUCCESS);
                break;
            default:
                usage(argv[0]);
                break;
        }
    }

    /** open the nfex log file */
    oldlog = fopen(argv[optind], "r");
    if (oldlog == NULL)
    {
        fprintf(stderr, "can't open nfex logfile %s: %s\n", argv[optind], 
            strerror(errno));
        return (EXIT_FAILURE);
    }

    /** build the filename for the new log file based off the old one */
    memset(p, 0, sizeof (p));
    strncpy(p, argv[optind], sizeof (p) - 1);
    for (i = 0; p[i] != '.'; i++);
    strcpy(&p[i], "-pp.txt");

    /** open the nfex_pp log file (the one we'll create) */
    newlog = fopen(p, "w");
    if (newlog == NULL)
    {
        fprintf(stderr, "can't open new logfile %s: %s\n", p, strerror(errno));
        return (EXIT_FAILURE);
    }

    /** initialize the clamav library */
    engine = clamav_init();
    if (engine == NULL)
    {
        fprintf(stderr, "fatal error\n");
        close(fd);
        return (EXIT_FAILURE);
    }

    n        = sizeof (p);
    size     = 0;
    src_file = timestamp = src_ip = dst_ip = filename = NULL;
    pesig    = PE32_SIGNATURE;
next_entry:
    while(fgets(p, n, oldlog))
    {
        /** save all of these guys, we'll need them later */
        /** XXX: fix memory leak with the implied malloc() in strsep() */
        q = p;
        src_file  = strsep(&q, ",");
        if (src_file == NULL)
        {
            fprintf(stderr, "bad logfile entry: no src_file, skipping...\n");
            goto next_entry;
        }
        timestamp = strsep(&q, ",");
        if (timestamp == NULL)
        {
            fprintf(stderr, "bad logfile entry: no timestamp, skipping...\n");
            goto next_entry;
        }
        src_ip    = strsep(&q, ",");
        if (src_ip == NULL)
        {
            fprintf(stderr, "bad logfile entry: no src_ip, skipping...\n");
            goto next_entry;
        }
        dst_ip    = strsep(&q, ",");
        if (dst_ip == NULL)
        {
            fprintf(stderr, "bad logfile entry: no dst_ip, skipping...\n");
            goto next_entry;
        }
        filename  = strsep(&q, ",");
        if (filename == NULL)
        {
            fprintf(stderr, "bad logfile entry: no filename, skipping...\n");
            goto next_entry;
        }

        /** step over last bit of whitespace and replace newline with a NULL */
	for (i = 0; filename[i] == ' '; i++);
        filename = filename + i;
        filename[strlen(filename) - 1] = 0;
        fd = open(filename, O_RDONLY);
        if (fd == -1)
        {
            fprintf(stderr, "can't open %s: %s\n", filename, strerror(errno));
            goto next_entry;
        }

        printf("checking %s...\n", filename);
        i = read(fd, b, sizeof (b));
        if (i == -1)
        {
            fprintf(stderr, "can't read %s: %s\n", filename, strerror(errno));
            close(fd);
            goto next_entry;
        }
        /** overlay DOS header to our file buffer */
        dos = (dos_hdr_t *)b;

        /** MZ header check (will always be at 0x00 and 0x01) */
        if (dos->e_magic == 0x4d5a)
        {
            printf("MZ header not found at offset 0x00 and 0x01!\n");
            close(fd);
            goto next_entry;
        }
        printf("found MZ header\n");

        /** PE header offset is a 32-bit value */
        memcpy(&pehdr, b + dos->e_lfanew, sizeof (pehdr));
        if (memcmp(&pehdr, &pesig, sizeof (pehdr)) == 0)
        {
            printf("found PE header at 0x%x\n", dos->e_lfanew);

            /** write details to new log file */            
            fprintf(newlog, "%s,", src_file);
            fprintf(newlog, "%s,", timestamp);
            fprintf(newlog, "%s,", src_ip);
            fprintf(newlog, "%s,", dst_ip);
           
            /** md5 hash of file */ 
            md5file(fd, md5);
            
            /** build new filename for file based off of md5 */
            memset(pp, 0, sizeof (pp));
            sprintf(pp, "%s", filename);
            for (i = 0; pp[i] != '.'; i++);
            sprintf(&pp[i], "-");
            i += 1;

            /** print md5 string hex char by char */
            for (j = 0; j < 16; j++, i++)
            {
                sprintf(&pp[i + j], "%02x", md5[j]);
            }
            sprintf(&pp[i + j], ".exe");

            fprintf(newlog, " %s, ", pp);
            fflush(newlog);
            rename(filename, pp);

            /** see if we have malware */
            i = cl_scandesc(fd, &vname, &size, engine, CL_SCAN_STDOPT);
            if (i == CL_VIRUS)
            {
                printf("malware detected: %s is %s\n", filename, vname);
                fprintf(newlog, "%s\n", vname);
            }
            else
            {
                if (i == CL_CLEAN)
                {
                    printf("no malware detected.\n");
                    fprintf(newlog, "%s\n", CLAMAV_UNKNOWN);
                }
                else
                {
                    fprintf(stderr, "clamav error: %s\n", cl_strerror(i));
                    fprintf(newlog, "%s\n", CLAMAV_ERROR);
                }
            }

            close(fd);
            goto next_entry;
        }
        else
        {
            printf("didn't find PE header, deleting file\n");
            i = unlink(filename);
            if (i == -1)
            {
                fprintf(stderr, "can't unlink %s: %s\n", filename, 
                    strerror(errno));
            }
            close(fd);
        }
    }
    fclose(newlog);
    fclose(oldlog);
    /** delete old logfile */
    i = unlink(argv[optind]);
    if (i == -1)
    {
        fprintf(stderr, "can't unlink %s: %s\n", argv[1], strerror(errno));
    }

    printf("program completed, normal exit\n");
    return(EXIT_SUCCESS);
}

void
md5file(int fd, unsigned char *md5)
{
    MD5_CTX context;
    int n;
    unsigned char buffer[1024];

    memset(buffer, 0, sizeof (buffer));
    MDInit(&context);

    lseek(fd, SEEK_SET, 0);
    while (n = read(fd, buffer, 1024))
    {
        MDUpdate(&context, buffer, n);
    }
    MDFinal(md5, &context);
}


struct cl_engine *
clamav_init()
{
    int n;
    uint32_t sigs; 
    struct cl_engine *engine;

    /** make sure clamav is ready to go */
    printf("clamav: intializing...\n");
    n = cl_init(CL_INIT_DEFAULT);
    if (n != CL_SUCCESS)
    {
        fprintf(stderr, "can't initialize libclamav: %s\n", cl_strerror(n));
        return (NULL);
    }

    engine = cl_engine_new();
    if (engine == NULL)
    {
        fprintf(stderr, "can't create new engine\n");
        return (NULL);
    }

    /** load all available databases from default directory */
    if ((n = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT)) != CL_SUCCESS)
    {
        fprintf(stderr, "cl_load: %s\n", cl_strerror(n));
        cl_engine_free(engine);
        return (NULL);
    }

    printf("clamav: loaded %u signatures...\n", sigs);

    /** build engine */
    if ((n = cl_engine_compile(engine)) != CL_SUCCESS) {
        fprintf(stderr, "database init error: %s\n", cl_strerror(n));;
        cl_engine_free(engine);
        return (NULL);
    }

    return (engine);
}

void
usage(char *progname)
{
    printf("Usage: %s nfex_index_file\n", progname);
    exit(1);    
}

/** EOF */
