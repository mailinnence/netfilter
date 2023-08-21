#include <signal.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>


char* hostname;

void handleCtrlC(int signal);

void handleCtrlC(int signal) {
    system("sudo iptables -F");
    exit(signal);
}

static u_int32_t print_pkt(struct nfq_q_handle *qh , struct nfq_data *tb, char *hostname) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    id = ntohl(ph->packet_id);

    struct ip *ip_header;
    struct tcphdr *tcp_header;

    if ((ret = nfq_get_payload(tb, &data)) >= 0) {
        ip_header = (struct ip *)data;
        tcp_header = (struct tcphdr *)(data + (ip_header->ip_hl << 2));

        if (ip_header->ip_p == IPPROTO_TCP) {
        	char *payload = (char *)(data + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
				
            if (ret > (ip_header->ip_hl << 2) + (tcp_header->th_off << 2) + 3 &&
                payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T') {
		
                char *findhost = strstr(payload, "Host: ");
                if (findhost) {
                    findhost += 6;
                    char *hostend = strchr(findhost, '\r');
                    
                    if (hostend) {
                        *hostend = '\0';

                        // 입력받은 호스트명과 비교
                        if (strcmp(findhost, hostname) == 0) {
                        
                            nfq_set_verdict(qh, id, NF_DROP, 0, NULL); 
                        }
                    }
                }
            }
        }
    }

    nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);  
}




static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
   	u_int32_t id = print_pkt(qh , nfa, hostname);
}




int main(int argc, char **argv) {


    hostname = argv[1];

    signal(SIGINT, handleCtrlC);
    system("sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    system("sudo iptables -A INPUT -j NFQUEUE --queue-num 0");

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;

    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    printf("opening library handle\n");
    h = nfq_open();

    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
           // printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);

            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    nfq_close(h);

    exit(0);
}
