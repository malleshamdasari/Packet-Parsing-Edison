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

typedef struct seq_no_analysis_ {
	u_short src_port;
	u_short dst_port;
	int last_seq;
	int last_ack;
	struct seq_no_analysis_ *next;
}seq_no_analysis_t;

typedef struct part1b_ {
	tcp_seq src_seq;
	tcp_seq src_ack;
	u_short src_win;
	tcp_seq dst_seq;
	tcp_seq dst_ack;
	u_short dst_win;
}part1b_t;

typedef struct cwind_ {
	int idx;
	int icwind;
	int cwind[5];
}cwind_t;

typedef struct acks_ {
	tcp_seq ack;
	struct acks_ *next;
}acks_t;

typedef struct seqs_ {
	tcp_seq seq;
	long sec;
	long usec;
	tcp_seq exp_ack;
	long rtt;
	struct seqs_ *next;
}seqs_t;

typedef struct flows_ {
	u_short src_port;
	u_short dst_port;
	int tx_bytes;
	int flow_id;
	long start_sec;
	long start_usec;
	long end_sec;
	long end_usec;
	int dup_acks;
	int tx_pkts;
	int rx_pkts;
 	int retransmissions;
 	int retransmission_pkts;
	int frt;
	double rtt;
	cwind_t cwind;
	acks_t *acks;
        seqs_t *seqs;
	part1b_t p1b[2];
	struct flows_ *next;
}flows_t;

typedef struct flow_context_ {
	flows_t *flows;
	seq_no_analysis_t *sna;
	int flow_count;
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
