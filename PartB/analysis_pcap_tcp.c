#include "analysis_pcap_tcp.h"

flow_context_t flow_cntxt;

unsigned int swap_endian(unsigned int num)
{
	unsigned int b0,b1,b2,b3;
	unsigned int res;

	b0 = (num & 0x000000ff) << 24u;
	b1 = (num & 0x0000ff00) << 8u;
	b2 = (num & 0x00ff0000) >> 8u;
	b3 = (num & 0xff000000) >> 24u;
	
	res = b0 | b1 | b2 | b3;
	return res;
}

void put_seq(flows_t *flow, seqs_t *seq)
{
	seqs_t *p = flow->seqs;

	if(p) {
		while(p->next) {
			if (p->seq == seq->seq) {
				p->sec = seq->sec;
				p->usec = seq->usec;
				free(seq);
				return;
			}
			p = p->next;
		}
		p->next = seq;
	} else {
		flow->seqs = seq;
	}
}

void put_ack(flows_t *flow, acks_t *ack)
{
	acks_t *p = flow->acks;

	if(p) {
		while(p->next) 
			p = p->next;
		p->next = ack;
	} else {
		flow->acks = ack;
	}
}

void init_flow_context(flow_context_t *flow_cntxt)
{
	flow_cntxt->flows = NULL;
	flow_cntxt->flow_count = 0;
}

void put_flow_context(flow_context_t *flow_cntxt, flows_t *new_flow)
{
	flows_t *flows = flow_cntxt->flows;

	if(flows) {
		flows_t *p = flows;
		while(p->next)
			p = p->next;
		p->next = new_flow;
	} else {
		flow_cntxt->flows = new_flow;
	}
}

flows_t *get_flow_context(flow_context_t *flow_cntxt, u_short src_port, u_short dst_port)
{
	flows_t *flow = NULL;
	flows_t *p = flow_cntxt->flows;

	while(p) {
		if (p->src_port == src_port && p->dst_port == dst_port) {
			flow = p;
			break;
		}
		p = p->next;
	}

	return flow;
}

void delete_flow_context(flow_context_t *flow_cntxt)
{
	flows_t *curr = flow_cntxt->flows;
	flows_t *prev;
	seqs_t *p, *q;
	acks_t *r, *s;

	while (curr) {
		prev = curr;
		curr = curr->next;
		if (prev->seqs) {
			p = prev->seqs;
			while (p) {
				q = p;
				p = p->next;
				free(q);
			}
		}
		if (prev->acks) {
			r = prev->acks;
			while (r) {
				s = r;
				r = r->next;
				free(s);
			}
		}
		free(prev);
	}
}

int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
	  int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
	  y->tv_usec -= 1000000 * nsec;
	  y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
	  int nsec = (y->tv_usec - x->tv_usec) / 1000000;
	  y->tv_usec += 1000000 * nsec;
	  y->tv_sec -= nsec;
	}
	
	/* Compute the time remaining to wait.
	   tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;
	
	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

void do_part1b(flows_t *flow, struct my_tcp_custom_hdr *tcp, int flag)
{
	if (flag == 0){
	if (flow->tx_pkts == 3 || flow->tx_pkts == 4) {
		if (flow->tx_pkts == 3) {
			flow->p1b[0].src_seq = ntohl(tcp->th_seq);
			flow->p1b[0].src_ack = ntohl(tcp->th_ack);
			flow->p1b[0].src_win = ntohs(tcp->th_win)*16384;
		} else {
			flow->p1b[1].src_seq = ntohl(tcp->th_seq);
			flow->p1b[1].src_ack = ntohl(tcp->th_ack);
			flow->p1b[1].src_win = ntohs(tcp->th_win)*16384;
		}
	}
	}
	else {
	if (flow->rx_pkts == 2 || flow->rx_pkts == 3) {
		if (flow->rx_pkts == 2) {
			flow->p1b[0].dst_seq = ntohl(tcp->th_seq);
			flow->p1b[0].dst_ack = ntohl(tcp->th_ack);
			flow->p1b[0].dst_win = ntohs(tcp->th_win)*16384;
		} else {
			flow->p1b[1].dst_seq = ntohl(tcp->th_seq);
			flow->p1b[1].dst_ack = ntohl(tcp->th_ack);
			flow->p1b[1].dst_win = ntohs(tcp->th_win)*16384;
		}
	}
	}
}

int is_retransmission(flows_t *flow, struct my_tcp_custom_hdr *tcp)
{
	seqs_t *p = flow->seqs;

	while(p) {
		if ( p->seq == ntohl(tcp->th_seq)) {
			return 1;
		}
		p = p->next;
	}
	return 0;
}

int is_fast_retransmission(flows_t *flow, struct my_tcp_custom_hdr *tcp)
{
	acks_t *p = flow->acks;
	int count = 0;

	while (p) {
		if (p->ack == ntohl(tcp->th_seq))
			count++;
		p = p->next;
	}
	if (count >= 3)
		return 1;
	else
		return 0;
}

void calculate_rtt(flows_t *f, struct timeval end, struct my_tcp_custom_hdr *tcp)
{
	seqs_t *s = f->seqs;
	struct timeval r, start;

	while(s) {
		if (s->exp_ack == ntohl(tcp->th_ack)) {
			start.tv_sec = s->sec;
			start.tv_usec = s->usec;
			timeval_subtract(&r, &end, &start);
			s->rtt = r.tv_sec*1000000+r.tv_usec;
		}
		s = s->next;
	}
}

void process_packet(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len)
{
	struct ip *ip;
	struct my_tcp_custom_hdr *tcp;

	if (capture_len < sizeof(struct ether_header)) {
		printf("Ethernet header");
		return;
	}

	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);

	if (capture_len < sizeof(struct ip)) {
		printf("IP header\n");
		return;
	}

	ip = (struct ip*) packet;

	if (capture_len < ip->ip_hl*4) {
		printf("IP header with options \n");
		return;
	}

	if (ip->ip_p != IPPROTO_TCP) {
		printf("non tcp packet \n");
		return;
	}

	packet += ip->ip_hl*4;
	capture_len -= ip->ip_hl*4;

	if (capture_len < sizeof(struct my_tcp_custom_hdr)) {
		printf("TCP header \n");
		return;
	}

	tcp = (struct my_tcp_custom_hdr*) packet;
        if (((tcp->th_flags>>1)&1) && !((tcp->th_flags>>4)&1)) {
		flow_cntxt.flow_count++;
		flows_t *flow = (flows_t *)malloc(sizeof(flows_t));
		seqs_t *seq = (seqs_t *)malloc(sizeof(seqs_t));
		flow->src_port = ntohs(tcp->th_sport);
		flow->dst_port = ntohs(tcp->th_dport);
		flow->tx_bytes = capture_len+ip->ip_hl*4+sizeof(struct ether_header);
		flow->flow_id = flow_cntxt.flow_count;
		flow->start_sec = ts.tv_sec;
		flow->start_usec = ts.tv_usec;
		flow->tx_pkts = 1;
		flow->rx_pkts = 0;
		flow->retransmissions = 0;
		flow->retransmission_pkts = 0;
		seq->seq = ntohl(tcp->th_seq);
		seq->sec = ts.tv_sec;
		seq->usec = ts.tv_usec;
		seq->exp_ack = seq->seq+capture_len-(((tcp->th_offx2&240)>>4)*4)+1;
		seq->next = NULL;
		flow->seqs = NULL;
		flow->frt = 0;
		flow->cwind.idx = 0;
		put_seq(flow, seq);
		flow->next = NULL;
		put_flow_context(&flow_cntxt, flow);
	} else {
		flows_t *flow = NULL;
		flow = get_flow_context(&flow_cntxt, ntohs(tcp->th_sport), ntohs(tcp->th_dport));
		if(flow) {
			flow->tx_bytes += capture_len+ip->ip_hl*4+sizeof(struct ether_header);
			flow->end_sec = ts.tv_sec;
			flow->end_usec = ts.tv_usec;
			if (is_retransmission(flow, tcp)){
				flow->retransmissions += capture_len+ip->ip_hl*4+sizeof(struct ether_header);
				flow->retransmission_pkts++;
				if (is_fast_retransmission(flow, tcp))
					flow->frt++;
			}
			if (flow->tx_pkts != 1) {
				seqs_t *seq = (seqs_t *)malloc(sizeof(seqs_t));
				seq->seq = ntohl(tcp->th_seq);
				seq->sec = ts.tv_sec;
				seq->usec = ts.tv_usec;
				seq->exp_ack = seq->seq+capture_len-(((tcp->th_offx2&240)>>4)*4);
				seq->next = NULL;
				put_seq(flow, seq);
			}
			flow->tx_pkts++;
			do_part1b(flow, tcp, 0);
		} else {
			flow = get_flow_context(&flow_cntxt, ntohs(tcp->th_dport), ntohs(tcp->th_sport));
			if(flow) {
				acks_t *ack = (acks_t *)malloc(sizeof(acks_t));
				ack->ack = ntohl(tcp->th_ack);
				put_ack(flow, ack);
				flow->rx_pkts++;
				if (flow->rx_pkts == 2) {
					flow->cwind.icwind = flow->tx_pkts-2;
				} else if (flow->rx_pkts>2 && flow->cwind.idx < 5){
					
					flow->cwind.cwind[flow->cwind.idx] = flow->cwind.icwind+flow->cwind.idx;
					flow->cwind.idx++;
				}
				do_part1b(flow, tcp, 1);
				calculate_rtt(flow, ts, tcp);
			}
		}
	}
}

void calculate_avg_rtt(flows_t *f)
{
	seqs_t *s = f->seqs;
	int count = 0;

	while(s) {
		if (s->rtt>0) {
			f->rtt += s->rtt;
			count++;
		}
		s = s->next;
	}
	f->rtt = f->rtt/count;
}

void print_part1(flow_context_t *f)
{
	int c = 0;

	printf("\n\tNumber of TCP flows\t\t: %d\n",f->flow_count);
	printf("\t-------------------\n\n");
	flows_t *fs = f->flows;
	while (fs) {
		printf("\t\t***********************************\n");
		printf("\t\t************* Flow %d **************\n",fs->flow_id);
		printf("\t\t***********************************\n");
		//while (i<2) {
		//	printf("\tTransaction %d:\n",i);
		//	printf("\t\tSource Seq Number\t\t: %u\n",fs->p1b[i].src_seq);
		//	printf("\t\tSource Ack Number\t\t: %u\n",fs->p1b[i].src_ack);
		//	printf("\t\tSource Window Size\t\t: %u\n",fs->p1b[i].src_win);
		//	printf("\t\tDestination Seq Number\t\t: %u\n",fs->p1b[i].dst_seq);
		//	printf("\t\tDestination Ack Number\t\t: %u\n",fs->p1b[i].dst_ack);
		//	printf("\t\tDestination Window Size\t\t: %u\n",fs->p1b[i].dst_win);
		//	i++;
		//}
		//i = 0;
		//start.tv_sec = fs->start_sec;
		//start.tv_usec = fs->start_usec;
		//end.tv_sec = fs->end_sec;
		//end.tv_usec = fs->end_usec;
		//timeval_subtract(&r, &end, &start);
		//printf("\tThroughput: %f\n",((float)(fs->tx_bytes-fs->retransmissions)*8/(float)(r.tv_sec*1000000+r.tv_usec))*1000000);
		//printf("\tLossrate: %f\n",(float)(fs->retransmission_pkts)/(float)(fs->tx_pkts));
		//calculate_avg_rtt(fs);
		//printf("\tRTT: %f\n\n",fs->rtt);
		printf("\tFirst 5 Congestion Window Sizes: ");
		//printf("%d\n",fs->cwind.icwind);
		while(c<fs->cwind.idx)
			printf("%d\t",fs->cwind.cwind[c++]);
		printf("\n");
		c = 0;
		printf("\tNumber of Retransmits due to Triple Duplicates: %d\n",fs->frt);
		printf("\tNumber of Retransmits due to Timeout: %d\n\n",fs->retransmission_pkts-fs->frt);
		fs = fs->next;
	}
}

int main(int argc, char *argv[])
{
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;

	init_flow_context(&flow_cntxt);

	++argv; --argc;
	if ( argc != 1 ) {
		printf("Please pass the capture file as input argument\n");
		exit(1);
	}

	pcap = pcap_open_offline(argv[0], errbuf);
	if (pcap == NULL) {
		printf("error reading pcap file: %s\n", errbuf);
		exit(1);
	}

	while ((packet = pcap_next(pcap, &header)) != NULL)
		process_packet(packet, header.ts, header.caplen);

	print_part1(&flow_cntxt);
	delete_flow_context(&flow_cntxt); 
	pcap_close(pcap);
	return 0;
}
