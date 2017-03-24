#include "analysis_pcap_http.h"

flow_context_t flow_cntxt;

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

	while(curr) {
		prev = curr;
		curr = curr->next;
		free(prev);
	}
}

void put_seq(flows_t *flow, seqs_t *seq, char *pkt, int len)
{
        seqs_t *p = flow->seqs;
	
	if (len > 0) {
		seq->rqst = (char *)malloc(len);	
		memcpy(seq->rqst, pkt, len);
	}
	seq->rqst_len = len;
	seq->resp_len = 0;

        if(p) {
                while(p->next) {
                        p = p->next;
                }
                p->next = seq;
        } else
                flow->seqs = seq;
}

void put_seg(seqs_t *seq, segs_t *seg)
{
        segs_t *p = seq->segs;
	
        if(p) {
                while(p->next) {
                        p = p->next;
                }
                p->next = seg;
        } else
                seq->segs = seg;
}

int check_header(unsigned char *data, int Size)
{
	int i=0, size=0;
	char *temp = data;
	
	for (i=0; i<Size; i++) {
		if (temp[i] == '\r' && temp[i+1] == '\n' && temp[i+2] == '\r' && temp[i+3] == '\n')
			break;
		size++;
	}
	return size;
}

void PrintData (unsigned char* data , int size)
{
    int i, j; 
    int Size = 0;

    Size = check_header(data, size);
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else printf("."); //otherwise print a dot
            }
        } 
        #if 1
        if( i==Size-1)  //print the last spaces
        {
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) printf("%c",(unsigned char)data[j]);
                else printf(".");
            }
        }
	#endif
    }
    printf("\n\n");
}

void update_response(flows_t *f, struct my_tcp_custom_hdr *tcp, char *pkt, int len)
{
        seqs_t *s = f->seqs;
        struct timeval r, start;

        while(s) { 
                if (s->exp_ack == ntohl(tcp->th_ack)) {
			if (len > 0) {
				if (s->resp_len <= 0) {
					s->resp = (char *)malloc(len);
					memcpy(s->resp, pkt, len);
					s->resp_len = len;
					s->segments = 0;
					s->segs = NULL;
				} else {
					segs_t *seg = (segs_t *)malloc(sizeof(segs_t));
					seg->sport = ntohs(tcp->th_sport);	
					seg->dport = ntohs(tcp->th_dport);	
					seg->seq = ntohl(tcp->th_seq);
					seg->ack = ntohl(tcp->th_ack);
					seg->next = NULL;
					put_seg(s, seg);
					s->segments++;
				}
			}
                } 
                s = s->next;
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

void process_packet(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len)
{
	struct ip *ip;
	struct my_tcp_custom_hdr *tcp;
	unsigned int total_len = capture_len;
	static int x = 0;
	
	packet += 16;
	capture_len -= 16;

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
		printf("TCP header no data \n");
		return;
	}
	
	tcp = (struct my_tcp_custom_hdr*) packet;
	packet += ((tcp->th_offx2&240)>>4)*4;
	capture_len -= ((tcp->th_offx2&240)>>4)*4;

	if (((tcp->th_flags>>1)&1) && !((tcp->th_flags>>4)&1)) {
                flow_cntxt.flow_count++;
                flows_t *flow = (flows_t *)malloc(sizeof(flows_t));
		seqs_t *seq = (seqs_t *)malloc(sizeof(seqs_t));
                flow->src_port = ntohs(tcp->th_sport);
                flow->dst_port = ntohs(tcp->th_dport);
                flow->flow_id = flow_cntxt.flow_count;
		seq->seq = ntohl(tcp->th_seq);
                seq->exp_ack = seq->seq+capture_len;
                seq->next = NULL;
                flow->seqs = NULL;
		flow->tx_pkts = 1;
		flow->rx_pkts = 0;
		flow->usec = ts.tv_usec;
		flow->sec = ts.tv_sec;
                put_seq(flow, seq, (char *)packet, capture_len);
                flow->next = NULL;
                put_flow_context(&flow_cntxt, flow);
        } else {
		flows_t *flow;
		flow = get_flow_context(&flow_cntxt, ntohs(tcp->th_sport), ntohs(tcp->th_dport));
		if(flow) {
			if (flow->tx_pkts != 1) {
                                seqs_t *seq = (seqs_t *)malloc(sizeof(seqs_t));
                                seq->seq = ntohl(tcp->th_seq);
                                seq->exp_ack = seq->seq+capture_len;
                                seq->next = NULL;
                                put_seq(flow, seq, (char *)packet, capture_len);
                        }
			flow->tx_pkts++;
			flow_cntxt.usec = ts.tv_usec;
			flow_cntxt.sec = ts.tv_sec;
		} else {
			flow = get_flow_context(&flow_cntxt, ntohs(tcp->th_dport), ntohs(tcp->th_sport));
			if(flow) {
				update_response(flow, tcp, (char *)packet, capture_len);
				flow_cntxt.usec = ts.tv_usec;
				flow_cntxt.sec = ts.tv_sec;
				flow->rx_pkts++;
			}
		}
	}
	if (x == 0) {
		flow_cntxt.start_sec = ts.tv_sec;
		flow_cntxt.start_usec = ts.tv_usec;
		x++;
	}
	flow_cntxt.sec = ts.tv_sec;
	flow_cntxt.usec = ts.tv_usec;
	flow_cntxt.bytes += total_len;
	flow_cntxt.pkts += 1;
}

void print_http(flow_context_t *flow_cntxt)
{
	flows_t *f = flow_cntxt->flows;
	struct timeval start, end, result;
	
	if (flow_cntxt->flow_count > 6) {
	printf("\nThe HTTP Version is: HTTP/1.0\n");
	printf("-----------------------------\n\n");
	while (f) {
		if (f->flow_id == 1) {
			start.tv_usec = f->usec;	
			start.tv_sec = f->sec;	
		}
		seqs_t *s = f->seqs;
		while (s) {
			if (s->rqst_len > 0 && s->resp_len > 0) {
				printf("New Request\n");
				printf("-----------\n\n");
				printf("Request: ");
				PrintData(s->rqst, s->rqst_len);
				printf("Response: ");
				PrintData(s->resp, s->resp_len);
				if (s->segments > 0) {
					printf("\tTotal segmens for this request are: %d\n",s->segments);
					printf("\t--------------------------------------\n");
					segs_t *g = s->segs;
					int i = 0;
					while (g) {
						i++;
						printf("\tSegment %d: Src: %d Dst: %d Seq: %u Ack: %u\n\n",i,g->sport,g->dport,g->seq,g->ack);
						g = g->next;
					}
				} else 
					printf("\tThere is only one segment for this request\n\n");
			}
			s = s->next;
		}
		f = f->next;
	} }
	start.tv_usec = flow_cntxt->start_usec;	
	start.tv_sec = flow_cntxt->start_sec;	
	end.tv_usec = flow_cntxt->usec;
	end.tv_sec = flow_cntxt->sec;
	timeval_subtract(&result, &end, &start);
	if (flow_cntxt->flow_count == 6) {
		printf("\nThe HTTP Version is: HTTP/1.1\n");
	}
	else if (flow_cntxt->flow_count <3) {
		printf("\nThe HTTP Version is: HTTP/2.0\n");
		printf("-----------------------------\n\n");
	}
	printf("Total time of Page Load: %ld.%ld secs\n",result.tv_sec, result.tv_usec);
	printf("Total packets and bytes: %d and %d\n\n",flow_cntxt->pkts, flow_cntxt->bytes);
}

int main(int argc, char *argv[])
{
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;

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

	print_http(&flow_cntxt);
	pcap_close(pcap);
	return 0;
}
