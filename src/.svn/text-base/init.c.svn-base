/*
 * init.c - initialization routines
 *
 * 2009, 2010 Mike Schiffman <mschiffm@cisco.com> 
 *
 * Copyright (c) 2010 by Cisco Systems, Inc.
 * All rights reserved.
 */
 
#include "nfex.h"

extern FILE *yyin;

ncc_t *
control_context_init(char *output_dir, char *yyinfname, char *device, 
char *capfname, char *geoip_data, char *bpf, u_int16_t flags, char *errbuf)
{
    int n;
    ncc_t *ncc;
    struct rlimit rl;
    struct termios term;
    bpf_u_int32 net, mask;
    struct stat stat_info;
    struct bpf_program filter_program;

    /** gather all the memory we need for a control context */  
    ncc = malloc(sizeof (ncc_t));
    if (ncc == NULL)
    {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "malloc(): %s\n", strerror(errno));
        return (NULL);
    }
    
    /** initialize certain elements of the control context */
    memset(ncc, 0, sizeof (ncc_t));
    ncc->flags    = flags;
    ncc->device   = device;
    strcpy(ncc->capfname, capfname);
    strcpy(ncc->output_dir, output_dir);

    /** initialize hash table */
    for (n = 0; n < NFEX_HT_SIZE; n++)
    {
        /** not needed!@ */
        ncc->ht[n] = NULL;
    }

    /** setup the output directory prefix stuff */
    if (ncc->output_dir[0])
    {
        if (stat(output_dir, &stat_info) == -1)
        {
            if (mkdir(output_dir, S_IRWXU|S_IRWXG|S_IRWXO) == -1)
            {
                fprintf(stderr, "can't create output dir %s:%s\n", output_dir,
                    strerror(errno));
            }
        }
    }

    if (yyinfname[0] == 0)
    {
        sprintf(ncc->yyinfname, "%s", NFEX_DEFAULT_CONFIG_FILE);
    }
    else
    {
        strcpy(ncc->yyinfname, yyinfname);
    }

    yyin = fopen(ncc->yyinfname, "r");
    if (yyin == NULL)
    {
        fprintf(stderr, "can't open config file %s: %s\n", ncc->yyinfname,
            strerror(errno));
        goto err;
    }
    printf("loading configuration file...\n");
    yyparse((void *)ncc);

    /** if a pcap file was specified, we go that route */
    if (ncc->capfname[0])
    {
        ncc->p = pcap_open_offline(capfname, errbuf);
        if (ncc->p == NULL)
        {
            fprintf(stderr, "can't open pcap file %s: %s\n", ncc->capfname, 
                errbuf);
            goto err;
        }
        ncc->pcap_fd = pcap_get_selectable_fd(ncc->p);

        if (fstat(ncc->pcap_fd, &stat_info) == -1)
        {
            fprintf(stderr, "can't stat %s, progress will be unavailable\n",
                capfname);
        }
        else
        {
            ncc->capfsize = stat_info.st_size;
        }

        /** need STDIN to nonblock if reading from file */
        n = fcntl(STDIN_FILENO, F_GETFL, 0);
        n |= O_NONBLOCK;
        if (fcntl(STDIN_FILENO, F_SETFL, n) == -1)
        {
            fprintf(stderr, "can't set STDIN to non-blocking: %s\n",
                strerror(errno));
            goto err;
        }
    }
    /** otherwise we go the network route */
    else
    {
        if (ncc->device == NULL)
        {
            ncc->device = pcap_lookupdev(errbuf);
            if (ncc->device == NULL)
            {
                fprintf(stderr, "can't find default device: %s\n", errbuf);
                goto err;
            } 
        }
    
        /** find the properties for the device */
        if (pcap_lookupnet(ncc->device, &net, &mask, errbuf) == -1)
        {
            fprintf(stderr, "can't get netmask for device %s\n", ncc->device);
            net  = 0;
            mask = 0;
        }
    
        /** open the session in promiscuous mode */
        ncc->p = pcap_open_live(ncc->device, BUFSIZ, 1, 0, errbuf);
        if (ncc->p == NULL)
        {
            fprintf(stderr, "can't open device %s: %s\n", ncc->device, errbuf);
            goto err;
        }
        ncc->pcap_fd = pcap_fileno(ncc->p);
    }

    /** compile and apply the filter */
    if (pcap_compile(ncc->p, &filter_program, bpf, 0, net) == -1)
    {
        fprintf(stderr, "can't parse filter %s: %s\n", bpf,
            pcap_geterr(ncc->p));
        goto err;
    }

    if (pcap_setfilter(ncc->p, &filter_program) == -1)
    {
        fprintf(stderr, "can't install filter %s: %s\n", bpf,
            pcap_geterr(ncc->p));
       goto err;
    }

   /**
     * We want to change the behavior of stdin to not echo characters
     * typed and more importantly we want each character to be handed
     * off as soon as it is pressed (not waiting for \r).  To do this
     * we have to manipulate the termios structure and change the normal
     * behavior of stdin.  First we get the current terminal state of 
     * stdin.  If any of this fails, we'll warn, but not quit.
     */
    if (tcgetattr(STDIN_FILENO, &(ncc->term)) == -1)
    {
       /** log_msg(MMP_LOG_ERROR, m, 
            "error getting terminal attributes, CLI will act weird: %s\n",
            strerror(errno)); */
        /* nonfatal */
    }
    else
    {
        /** create a copy to modify, we'll save the original to restore later */
        memcpy((struct termios *)&term, (struct termios *)&(ncc->term), 
           sizeof (struct termios));
        /** disable canonical mode and terminal echo */
        term.c_lflag &= ~ICANON;
        term.c_lflag &= ~ECHO;

        /** set our changed state "NOW" */
        if (tcsetattr(STDIN_FILENO, TCSANOW, &term) == -1)
        {
        /**log_msg(MMP_LOG_ERROR, m,
            "error setting terminal attributes, CLI will act weird: %s\n",
            strerror(errno)); */
            /** nonfatal */
        }
    }

    /** set start time */
    if (gettimeofday(&(ncc->stats.ts_start), NULL) == -1)
    {
       /** log_msg(MMP_LOG_ERROR, m,
            "error getting timeofday, can't track server uptime: %s\n",
            strerror(errno));*/

        /** nonfatal */
    }

    /** open the index file */
    snprintf(ncc->indexfname, FILENAME_BUFFER_SIZE, "%s%d-index.txt",
        ncc->output_dir == NULL ? "" : ncc->output_dir, getpid());

    ncc->indexfp = fopen(ncc->indexfname, "w");
    if (ncc->indexfp == NULL)
    {
        fprintf(stderr, "can't open index file: %s\n", strerror(errno));
        goto err;
    }

#if (HAVE_GEOIP)
    /** power up the MaxMind Geo IP targeting stuff */
    if (geoip_data[0] == 0)
    {
        sprintf(ncc->geoip_data, "%s", NFEX_GEOIP_CONFIG_FILE);
    }
    else
    {
        strcpy(ncc->geoip_data, geoip_data);
    }
    ncc->gi = GeoIP_open(ncc->geoip_data, GEOIP_MEMORY_CACHE);
    if (ncc->gi == NULL)
    {
        fprintf(stderr, "can't open geoip database, no geoip targeting\n");
        /** nontfatal */
    }
#endif /** HAVE_GEOIP */

    printf("what we're working with:\noutput dir:\t%s\nconfig file:\t%s\n", 
        ncc->output_dir, ncc->yyinfname);
    if (ncc->device)
    {
        printf("device\t\t%s\n", ncc->device);
    }
    else
    {
        printf("pcap file:\t%s\n", ncc->capfname);
        printf("pcap filesize:\t%zu bytes\n", ncc->capfsize); 
    }
    printf("pcap filter:\t%s\n", bpf);
    printf("index file:\t%s\n", ncc->indexfname);
#if (HAVE_GEOIP)
    printf("geoIP database:\t%s\n", ncc->geoip_data);
#endif
    if (flags & NFEX_VERBOSE)
    {
        printf("verbosity on\n");
    }
#if (HAVE_GEOIP)
    if (flags & NFEX_GEOIP)
    {
        printf("geoIP mode on\n");
    }
#endif /** HAVE_GEOIP */
    if (flags & NFEX_DEBUG)
    {
        printf("[DEBUG MODE ENABLED]\n");
        if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
        {
            printf("[DEBUG] can't get RLIMIT_CORE, no core dump possible: %s\n",
                strerror(errno));
        }
        else
        {
            printf("[DEBUG] we can only have %lld files open at one time\n",
                rl.rlim_cur);
        }
    }
    return (ncc);

err:
    control_context_destroy(ncc);
    return (NULL);
}

void
control_context_destroy(ncc_t *ncc)
{
    if (ncc->p)
    {
        pcap_close(ncc->p);
    }
    if (ncc->term.c_iflag)
    {
        tcsetattr(STDIN_FILENO, TCSANOW, &(ncc->term));
    }
#if (HAVE_GEOIP)
    if (ncc->gi)
    {
        GeoIP_delete(ncc->gi);
    }
#endif /** HAVE_GEOIP */
    ht_shutitdown(ncc);

    /** log_close(ncc); */

    free(ncc);
    ncc = NULL;
}

/** EOF */
