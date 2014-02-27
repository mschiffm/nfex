/*
 * packet.c - pcap callback
 *
 * 2009, 2010 Mike Schiffman <mschiffm@cisco.com> 
 *
 * Copyright (c) 2010 by Cisco Systems, Inc.
 * All rights reserved.
 * Based off of tcpxtract by Nicholas Harbour.
 */

#include "nfex.h"
#include "config.h"
#include <libnet.h>

void
process_packet(u_char *user, const struct pcap_pkthdr *header, 
const u_char *packet)
{
    ncc_t *ncc;
    uint8_t *payload;
    four_tuple_t ft;
    int32_t payload_size;
    srch_results_t *results;
    struct libnet_ipv4_hdr *ip;
    struct libnet_tcp_hdr  *tcp;
    uint16_t ip_hl, tcp_hl, header_cruft;

    ncc = (ncc_t *)user;

    ip     = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);
    ip_hl  = ip->ip_hl << 2;

    /** this is a trival fix to handle IP options */
    if (ip_hl != 20) 
    {
        ncc->stats.packet_errors++;
        return;
    }

    switch (ip->ip_p)
    {
        case IPPROTO_TCP:
            tcp    = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + ip_hl);
            tcp_hl = tcp->th_off << 2;
            header_cruft = LIBNET_ETH_H + ip_hl + tcp_hl;
            break;
        default:
            return;          
    }

    ncc->stats.total_packets++;
    ncc->stats.total_bytes += (header->len + sizeof (struct pcap_pkthdr));

    payload_size = header->len - header_cruft;
    if (payload_size <= 0)
    {
        /** not an error per se, just no payload */
        return;
    }

    payload = (uint8_t *)(packet + header_cruft);

    /** copy over timestamp */
    ncc->stats.ts_last.tv_sec  = header->ts.tv_sec;
    ncc->stats.ts_last.tv_usec = header->ts.tv_usec;

    /** four tuple information aka "a session" */
    ft.ip_src   = ip->ip_src.s_addr;
    ft.ip_dst   = ip->ip_dst.s_addr;
    ft.port_src = tcp->th_sport;
    ft.port_dst = tcp->th_dport;

    /** attempt to add this session to the session table */
    ncc->session = ht_insert(&ft, ncc);

    /** pass payload to search interface to sift for our yumyums */
    results = search(ncc->srch_machine, &(ncc->session->srchptr_list), payload, 
        payload_size);

    extract(&(ncc->session->extract_list), results, ncc->session, payload, 
        payload_size, ncc);

    free_results_list(&results);
}

/** EOF */
