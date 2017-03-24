#ifndef __PARSER_H__
#define __PARSER_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdio.h>

typedef struct segs_ {
        u_short sport;
        u_short dport;
        tcp_seq seq;
        tcp_seq ack;
        struct segs_ *next;
}segs_t;

typedef struct seqs_ {
        tcp_seq seq;
        tcp_seq exp_ack;
	char *rqst;
	int rqst_len;
	char *resp;
	int resp_len;
	segs_t *segs;
	int segments;
        struct seqs_ *next;
}seqs_t;

typedef struct flows_ {
        u_short src_port;
        u_short dst_port;
        int flow_id;
        int tx_pkts;
        int rx_pkts;
	long int usec;
	long int sec;
	seqs_t *seqs;
        struct flows_ *next;
}flows_t;

typedef struct flow_context_ {
	flows_t *flows;
	int flow_count;
	int http_requests;
	long int usec;
	long int sec;
	long int start_usec;
	long int start_sec;
	int bytes;
	int pkts;
}flow_context_t;

struct my_tcp_custom_hdr{
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

#endif /* End of file */
