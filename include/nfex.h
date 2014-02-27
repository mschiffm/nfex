/*
 * nfex.h - top level header
 *
 * 2009, 2010 Mike Schiffman <mschiffm@cisco.com> 
 *
 * Copyright (c) 2010 by Cisco Systems, Inc.
 * All rights reserved.
 * Based off of tcpxtract by Nicholas Harbour.
 */

#ifndef NFEX_H
#define NFEX_H

#define _BSD_SOURCE 1

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#include <termios.h>
#include "hash.h"
#include "config.h"

#if (HAVE_GEOIP)
#include <GeoIP.h>
#include <GeoIPCity.h>
#ifndef NFEX_GEOIP_CONFIG_FILE
#define NFEX_GEOIP_CONFIG_FILE "/usr/local/etc/nfex/GeoIPCity.dat"
#endif
#endif

#ifndef NFEX_DEFAULT_CONFIG_FILE
#define NFEX_DEFAULT_CONFIG_FILE "/usr/local/etc/nfex/nfex.conf"
#endif

/** as we add more protocols this needs to change */
#define NFEX_PCAP_FILTER "tcp"

/* BEGIN MACROS */
/** simple way to subtract timeval based timers */
#define PTIMERSUB(tvp, uvp, vvp)                                             \
    do                                                                       \
    {                                                                        \
            (vvp)->tv_sec  = (tvp)->tv_sec  - (uvp)->tv_sec;                 \
            (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;                \
            if ((vvp)->tv_usec < 0)                                          \
            {                                                                \
                (vvp)->tv_sec--;                                             \
                (vvp)->tv_usec += 1000000;                                   \
            }                                                                \
    } while (0)

#ifndef MAX
#define MAX( x, y ) ((x) > (y) ? (x) : (y))
#endif
/* END MACROS */

/** statistics */
struct nfex_statistics
{
    uint32_t total_packets;           /* total packets seen */
    uint64_t total_bytes;             /* total bytes read */
    uint32_t total_files;             /* total files extracted */
    uint32_t packet_errors;           /* packet-level errors */
    uint32_t extraction_errors;       /* extraction errors */
    uint32_t ht_entries;              /* hash table: number of entries */
    uint32_t ht_nc;                   /* hash table: non-chained entries */
    uint32_t ht_ic;                   /* hash table: chained entries */
    uint32_t ht_lc;                   /* hash table: longest chain */
    struct timeval ts_start;          /* total uptime timestamp */
    struct timeval ts_last;           /* last file extracted timestamp */
    uint32_t ip_last;                 /* last packet seen ip */
};
typedef struct nfex_statistics n_stats_t;

/** monolithic opaque control context, everything imporant is here */
struct nfex_control_context
{
    pcap_t *p;                        /* pcap context */
    int pcap_fd;                      /* pcap fd used to select across */
    char *device;                     /* pcap device */
    ht_node_t *ht[NFEX_HT_SIZE];      /* our hash table of sessions */
    ht_node_t *session;               /* current session in focus */
    srch_node_t *srch_machine;
    struct termios term;              /* save terminal info to restore later */
    uint16_t flags;                   /* control context flags */
#define NFEX_VERBOSE       0x0001     /* toggle verbosity */
#define NFEX_GEOIP         0x0002     /* toggle geoIP mode */
#define NFEX_DEBUG         0x0004     /* debug mode */
#define NFEX_SESSIONS_LOCK 0x0008     /* locked, don't go in here */
    FILE *log;                        /* logfile FILE descriptor */
#if (HAVE_GEOIP)
    GeoIP *gi;                        /* geoip database pointer */
    char geoip_data[128];             /* geoip database path */
#endif /** HAVE_GEOIP */
    char yyinfname[128];
    char output_dir[128];             /* output directory prefix */
    u_int16_t filenum;                /* number of files we've written */
    char indexfname[128];
    FILE *indexfp;
    char capfname[128];               /* pcap capture file name */
    off_t capfsize;                   /* size of capfile */
    n_stats_t stats;                  /* stats */
    char errbuf[PCAP_ERRBUF_SIZE];    /* bad things reported here */
};
typedef struct nfex_control_context ncc_t;

/** call back when we have a packet */
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void quit_signal(int);

/** initialization functions */
ncc_t *control_context_init(char *, char *, char *, char *, char *, char *,
uint16_t, char *);
void control_context_destroy(ncc_t *);

/** main loop functions */
int the_game(ncc_t *);
int process_keypress(ncc_t *);

/**
 * log_init
 *
 * INPUTS
 * logfile: canonical name of the file to open, should be MMP_LOGFILE
 * ncc: pointer to ncc context
 *
 * RETURNS
 * 1 on success, -1 on failure
 *
 * DISCUSSION
 * opens logfile for appending, will create if it doesn't exist.
 *
 */
int log_init(char *logfile, ncc_t *ncc);

/**
 * log_msg
 *
 * INPUTS
 * priority: the level of the message (see above)
 * ncc: pointer to acc context
 * fmt: as used for printf family of functions
 * ...: as used for printf family of functions
 *
 * RETURNS
 * none
 *
 * DISCUSSION
 * writes a message to the system logfile, has a maximum length of
 * MMP_LOG_MAX (should this be tunable at boot time?)
 *
 *
 */
void log_msg(u_int8_t priority, ncc_t *ncc, char *fmt, ...);
void log_close(ncc_t *ncc);

/** extraction functions */
static void add_extract(extract_list_t **, fileid_t *, ht_node_t *, int, int,
ncc_t *);
static void set_segment_marks(extract_list_t *, size_t);
static void mark_footer(extract_list_t *, srch_results_t *);
static void extract_segment(extract_list_t *, const uint8_t *, ncc_t *);
static void sweep_extract_list(extract_list_t **);
static  int open_extract(char *ext, uint32_t src_ip, uint16_t src_prt, 
                         uint32_t dst_ip, uint16_t dst_prt, char **fname,
                         ncc_t *);
void extract(extract_list_t **elist, srch_results_t *results, 
             ht_node_t *session, const uint8_t *data, size_t size, ncc_t *ncc);

/** misc functions */
#define NFEX_STATS_UPDATE   0
#define NFEX_STATS_CLOSEOUT 1
void stats(ncc_t *n, int mode);
void usage(char *);
void quit_signal(int sig);
void print_hex(uint8_t *, uint16_t);
void convert_seconds(uint32_t, uint32_t *, uint32_t *, uint32_t *, 
                     uint32_t *);

/** session table functions */
ht_node_t *ht_insert(four_tuple_t *ft, ncc_t *ncc);
ht_node_t *ht_find(four_tuple_t *ft, ncc_t *ncc);
uint16_t ht_hash(four_tuple_t *ft);
uint32_t ht_count_extracts(ncc_t *ncc);
void ht_dump(ncc_t *ncc);
void ht_free(ncc_t *ncc);
void ht_status(ncc_t *ncc);
void ht_expire_session(ncc_t *ncc);

#endif /** NFEX_H */
/** EOF */
