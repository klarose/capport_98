	/* include readable_v41 */
#include	"icmpd.h"
#include	<netinet/in_systm.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/udp.h>
#include	<netinet/tcp.h>

#include 	"icmp_ext_hdr.h"
#include 	"icmp_capport.h"

void print_hex(uint8_t *raw, size_t len)
{
	for(int i = 0; i < len; ++i)
	{
		if(i  % 16 == 0)
		{
			printf("\n");
		}	
		else if(i % 8 == 0)
		{
			printf(" ");	
		}

		printf("%02x", raw[i]);	
	}

	printf("\n");
}
void setup_dest(struct sockaddr_in *dest,
		int sport,
		const struct ip *hip)
{
	bzero(dest, sizeof(*dest));
	
	dest->sin_family = AF_INET;
#ifdef	HAVE_SOCKADDR_SA_LEN
	dest->sin_len = sizeof(dest);
#endif
	memcpy(&dest->sin_addr, &hip->ip_dst, sizeof(struct in_addr));
	dest->sin_port = sport;
}

void send_message(const struct icmp *icmp,
		  const struct sockaddr_in *dest,
		  int has_capport)
{

	
	
	/* TODO: Add filtering by ip_proto */ 
		/* find client's Unix domain socket, send headers */
	for (int i = 0; i <= maxi; i++) {
		if (client[i].connfd >= 0 &&
			client[i].family == AF_INET)
		{	

			struct icmpd_err	icmpd_err;
			icmpd_err.icmpd_type = icmp->icmp_type;
			icmpd_err.icmpd_code = icmp->icmp_code;
			icmpd_err.icmpd_len = sizeof(struct sockaddr_in);
			memcpy(&icmpd_err.icmpd_dest, dest, sizeof(*dest));

				/* 4convert type & code to reasonable errno value */
			icmpd_err.icmpd_errno = EHOSTUNREACH;	/* default */
			icmpd_err.has_capport = has_capport;
			if (icmp->icmp_type == ICMP_UNREACH) {
				if (icmp->icmp_code == ICMP_UNREACH_PORT)
					icmpd_err.icmpd_errno = ECONNREFUSED;
				else if (icmp->icmp_code == ICMP_UNREACH_NEEDFRAG)
					icmpd_err.icmpd_errno = EMSGSIZE;
			}
			Write(client[i].connfd, &icmpd_err, sizeof(icmpd_err));
		}
	}
}

void handle_icmp(const struct ip* ip,
		 const struct ip* hip,
		 const struct icmp* icmp,
		 int has_capport)
{
	uint32_t hlen2 = hip->ip_hl << 2;

	struct sockaddr_in	dest;
	if (hip->ip_p == IPPROTO_UDP) {
		const struct udphdr *udp = (struct udphdr *) (((void*)hip) + hlen2);
		uint16_t sport = udp->uh_sport;

		setup_dest(&dest, sport, ip);
		send_message(icmp, &dest, has_capport);

	}
	else if(hip->ip_p == IPPROTO_TCP) {
		const struct tcphdr *tcp;
		tcp = (const struct tcphdr*) (((void*)hip) + hlen2);
		uint16_t sport = tcp->th_sport;
		setup_dest(&dest, sport, ip);
		send_message(icmp, &dest, has_capport);
	}
	else
	{
		setup_dest(&dest, 0, ip);
		send_message(icmp, &dest, has_capport);
	}
}
		       
void handle_unreach(const struct ip* ip,
		    const struct ip* hip,
		    const struct icmp* icmp)
{
	char srcstr[INET_ADDRSTRLEN];
	char dststr[INET_ADDRSTRLEN];

	printf("\tsrcip = %s, dstip = %s, proto = %d\n",
		   Inet_ntop(AF_INET, &hip->ip_src, srcstr, sizeof(srcstr)),
		   Inet_ntop(AF_INET, &hip->ip_dst, dststr, sizeof(dststr)),
		   hip->ip_p);

	const struct pkt_icmpunreachhdr_t *unreach;
	unreach = (const struct pkt_icmpunreachhdr_t*)(&icmp->icmp_cksum+1);
	uint16_t orig_pkt_len = unreach->len * 4;

	/* dump the first extension header */
	const struct pkt_icmpexthdr_t *exthdr = (((void*)(unreach+1)) + orig_pkt_len);
	uint16_t extVer = ntohs(exthdr->version_reserved) >> 12;
	int has_capport = 0;	
	if(extVer == 2)
	{
		const struct pkt_icmpobjhdr_t *obj = (struct pkt_icmpobjhdr_t*)(exthdr+1);
		
		if(obj->class_num == 3)
		{
			has_capport = 1;
			print_hex((uint8_t*)(obj+1), ntohs(obj->length));
		}
	}

	handle_icmp(ip, hip, icmp, has_capport);

}

void handle_capport(const struct ip* ip,
		    const struct ip* hip,
		    const struct icmp* icmp)
{
	const struct icmp_capport_header *capport_header;
	// capport_header = (struct icmp_capport_header*)(&icmp->icmp_void);
	capport_header = (struct icmp_capport_header*)(&icmp->icmp_cksum+1);
	int has_valid = (capport_header->flags >> VALIDITY_BIT) & 1;
	int has_delay = (capport_header->flags >> DELAY_BIT) & 1;
	int has_pc = (capport_header->flags >> POLICY_CLASS_BIT) & 1;

	int16_t orig_pkt_len = capport_header->length * 4;

	const uint32_t *cur_capport_extension = ((void*)hip) + orig_pkt_len;
	printf("Handling icmp capport message with flags %04x orig length: %u\n", capport_header->flags, orig_pkt_len);

	if(has_valid)
	{
		printf("Has valid footer: %08x\n", ntohl(*cur_capport_extension));
		cur_capport_extension++;
	}

	if(has_delay)
	{
		printf("Has delay footer: %08x\n", ntohl(*cur_capport_extension));
		cur_capport_extension++;
	}

	if(has_pc)
	{
		printf("Has policy class footer: %08x\n", ntohl(*cur_capport_extension));
		cur_capport_extension++;
	}

	
	// by default no capport on this. need to figure out something else to do here.
	handle_icmp(ip, hip, icmp, 0);
}
		
int
readable_v4(void)
{
	int			        hlen1, icmplen;
	char				buf[MAXLINE];
	ssize_t				n;
	socklen_t			len;
	struct ip			*ip, *hip;
	struct icmp			*icmp;
	struct sockaddr_in	from;

	len = sizeof(from);
	n = Recvfrom(fd4, buf, MAXLINE, 0, (SA *) &from, &len);

	ip = (struct ip *) buf;		/* start of IP header */
	printf("%d bytes ICMPv4 from %s \n",
		   n, Sock_ntop_host((SA *) &from, len));

	hlen1 = ip->ip_hl << 2;		/* length of IP header */

	icmp = (struct icmp *) (buf + hlen1);	/* start of ICMP header */
	if ( (icmplen = n - hlen1) < 8)
		err_quit("icmplen (%d) < 8", icmplen);

	hip = (struct ip *) (buf + hlen1 + 8);
	printf(" type = %d, code = %d\n", icmp->icmp_type, icmp->icmp_code);
/* end readable_v41 */

/* include readable_v42 */
	if (icmp->icmp_type == ICMP_UNREACH)
	{
		if (icmplen < 8 + 20 + 8)
			err_quit("icmplen (%d) < 8 + 20 + 8", icmplen);

		handle_unreach(ip, hip, icmp);
	}
	else if(icmp->icmp_type == ICMP_CAPPORT)
	{
		if (icmplen < 8 + 20 + 8)
			err_quit("icmplen (%d) < 8 + 20 + 8", icmplen);
		
		handle_capport(ip, hip, icmp);
		
	}
	return(--nready);
}
/* end readable_v42 */
