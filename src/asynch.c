/*
 * asynch.c - asynchronous routines
 *
 * 2009, 2010 Mike Schiffman <mschiffm@cisco.com> 
 *
 * Copyright (c) 2010 by Cisco Systems, Inc.
 * All rights reserved.
 * Based off of tcpxtract by Nicholas Harbour.
 */

#include "nfex.h" 
#include "config.h"

int
the_game(ncc_t *ncc)
{
    int c, n, j;
    fd_set read_set;

    /** file extraction */
    for (j = 0; ncc->capfname[1]; j++)
    {
        /*  
         * Not truly asynch as control will not be passed from pcap_dispatch
         * if a packet matching the filter is not found... This means the
         * program will block here (in file mode) if no packets match the 
         * filter that was specified at the command line.
         */
        c = pcap_dispatch(ncc->p, 100, process_packet, (uint8_t *)ncc);
        /** hand the keypress off be processed */
        switch (process_keypress(ncc))
        {
            case 2:
                /** user hit 'q'uit */
                fprintf(stderr, "user quit\n");
                return (2);
            default:
                break;
        }
        /** every 10,000 packets let's clean house */
        if (j == 100)
        {
            ht_expire_session(ncc);
            j = 0;
        }
        if (c < 0)
        {
            error(pcap_geterr(ncc->p));
        }
        else
        {
            if (c == 0)
            {
                /** no packets read, we must be done */
                return (1);
            }
        }
    }

    /** network extraction */
    for (j = 0; ; j++)
    {
        /** we multiplex input across the network and STDIN */
        FD_ZERO(&read_set);
        FD_SET(STDIN_FILENO, &read_set);
        FD_SET(ncc->pcap_fd, &read_set);

        /** check the status of our file descriptors */
        c = select(FD_SETSIZE, &read_set, 0, 0, NULL);
        if (c > 0)
        {
            /** input from the network */
            if (FD_ISSET(ncc->pcap_fd, &read_set))
            {
                n = pcap_dispatch(ncc->p, 100, process_packet, (u_char *)ncc);
                /** every 10,000 packets let's clean house */
                if (j == 100)
                {
                    ht_expire_session(ncc);
                    j = 0;
                }
                if (n == 0)
                {
                    return (EXIT_SUCCESS);
                }
            }
            /** input from the user */
            if (FD_ISSET(STDIN_FILENO, &read_set))
            {
                /** hand the keypress off be processed */
                switch (process_keypress(ncc))
                {
                    case 2:
                        /** user hit 'q'uit */
                        return (1);
                    default:
                        break;
                }
            }
        }
        if (c == -1)
        {
            perror("error fatal select");
            return (-1);
        }
    }
    /* NOTREACHED */
    return (1);
}

int
process_keypress(ncc_t *ncc)
{
    char buf[1];

    if (read(STDIN_FILENO, buf, 1) == -1)
    {
        /** nonfatal, silent failure */
        return (-2);
    }

    switch (buf[0])
    {
        case 'c':
            /* clear screen */
            fprintf(stderr,"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
            fprintf(stderr,"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
            fprintf(stderr,"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
            fprintf(stderr,"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
            break;
#if (HAVE_GEOIP)
        case 'g':
            if (ncc->flags & NFEX_GEOIP)
            {
                ncc->flags &= ~NFEX_GEOIP;
                printf("geoIP mode off\n");
            }
            else
            {
                ncc->flags |= NFEX_GEOIP;
                printf("geoIP mode on\n");
            }
            break;
#endif /** HAVE_GEOIP */
        case 'h':
            ht_status(ncc); 
            break;
        case 'f':
            //search_dump_types(ncc);
            break;
        case 'r':
            /* clear stats */
            /** FIXME: save uptime */
            memset(&ncc->stats, 0, sizeof (ncc->stats));
            printf("nfex statistics cleared\n");
            break;
        case 's':
            /* display statistics */
            stats(ncc, NFEX_STATS_UPDATE);
            break;
        case 'q':
            /* quit program */
            return (2);
        case 'V':
            printf("%s v%s\n", PACKAGE, VERSION);
            break;
        case 'v':
            if (ncc->flags & NFEX_VERBOSE)
            {
                ncc->flags &= ~NFEX_VERBOSE;
                printf("verbose mode off\n");
            }
            else
            {
                ncc->flags |= NFEX_VERBOSE;
                printf("verbose mode on\n");
            }
            break;
        case '?':
            /* help */
            printf("-[command summary]-\n");
            printf("[c]   - clear screen\n");
            printf("[f]   - show file search types\n");
#if (HAVE_GEOIP)
            printf("[g]   - toggle geoIP mode\n");
#endif /** HAVE_GEOIP */
            printf("[r]   - reset statistics\n");
            printf("[s]   - display statistics\n");
            printf("[q]   - quit\n");
            printf("[V]   - display program version\n");
            printf("[v]   - toggle verbose mode\n");
            printf("[?]   - help\n");
            if (ncc->flags & NFEX_DEBUG)
            {
                printf("[d]   - [DEBUG MODE] dump session list\n");
                printf("[h]   - [DEBUG MODE] hash table status\n");
            }
            break;
        case 'd':
            ht_dump(ncc);
            break;
        case 'n': /** XXX do something witih this */
            if (ncc->flags & NFEX_DEBUG)
            {
                ncc->flags &= ~NFEX_DEBUG;
                printf("[DEBUG MODE] notify all session updates off\n");
            }
            else
            {
                ncc->flags |= NFEX_DEBUG;
                printf("[DEBUG MODE] notify all session updates on\n");
            }
            break;
        default:
            break;
    }
    return (1);
}

void
stats(ncc_t *ncc, int mode)
{
    struct timeval r, e;
    u_int32_t day, hour, min, sec;

    gettimeofday(&e, NULL);
    PTIMERSUB(&e, &(ncc->stats.ts_start), &r);
    convert_seconds((u_int32_t)r.tv_sec, &day, &hour, &min, &sec);
    printf("%s", (mode == NFEX_STATS_UPDATE ?
        "up-time:\t\t\t" : "running-time:\t\t\t"));
    if (day > 0)
    {
        if (day == 1)
        {
            printf("%d day ", day);
        }
        else
        {
            printf("%d days ", day);
        }
    }
    if (hour > 0)
    {
        if (hour == 1)
        {
            printf("%d hour ", hour);
        }
        else
        {
            printf("%d hours ", hour);
        }
    }
    if (min > 0)
    {
        if (min == 1)
        {
            printf("%d minute ", min);
        }
        else
        {
            printf("%d minutes ", min);
        }
    }
    if (sec > 0)
    {
        if (sec == 1)
        {
            printf("%d second ", sec);
        }
        else
        {
            printf("%d seconds ", sec);
        }
    }
    else
    {
        printf("< 1 second");
    }
    printf("\n");
    if (mode == NFEX_STATS_UPDATE)
    {
       printf("sessions watched:\t\t%d\n", ncc->stats.ht_entries);
    }
    printf("packets churned:\t\t%d\n", ncc->stats.total_packets);
    printf("bytes churned:\t\t\t%lld\n", ncc->stats.total_bytes);
    if (ncc->capfname[0])
    {
        printf("pcap file processed:\t\t%.1f%%\n", 
            ((double)ncc->stats.total_bytes * 100) / (double)ncc->capfsize);
    }
    printf("files extracted:\t\t%d\n", ncc->stats.total_files);
    if (mode == NFEX_STATS_UPDATE)
    {
        printf("files currently extracting:\t%d\n", 
            ht_count_extracts(ncc));
    }
    printf("packet errors:\t\t\t%d\n", ncc->stats.packet_errors);
    printf("extraction errors:\t\t%d\n", ncc->stats.extraction_errors);
    fflush(stdout);
}

/** EOF */
