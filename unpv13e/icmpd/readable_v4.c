	/* include readable_v41 */
#include	"icmpd.h"
#include	<netinet/in_systm.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/udp.h>
#include	<netinet/tcp.h>

#include 	"icmp_ext_hdr.h"

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
		  const struct sockaddr_in *dest)
{
	const struct pkt_icmpunreachhdr_t *unreach;
	unreach = (const struct pkt_icmpunreachhdr_t*)(&icmp->icmp_cksum+1);
	uint16_t orig_pkt_len = ntohs(unreach->len) * 4;

	/* dump the first extension header */
	const struct pkt_icmpexthdr_t *exthdr = (((void*)(unreach+1)) + orig_pkt_len);
	uint16_t extVer = ntohs(exthdr->version_reserved) >> 12;
	uint16_t chksum = ntohs(exthdr->check);
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
		
int
readable_v4(void)
{
	int			        hlen1, hlen2, icmplen, sport;
	char				buf[MAXLINE];
	char				srcstr[INET_ADDRSTRLEN], dststr[INET_ADDRSTRLEN];
	ssize_t				n;
	socklen_t			len;
	struct ip			*ip, *hip;
	struct icmp			*icmp;
	struct udphdr		*udp;
	struct sockaddr_in	from, dest;

	len = sizeof(from);
	n = Recvfrom(fd4, buf, MAXLINE, 0, (SA *) &from, &len);

	ip = (struct ip *) buf;		/* start of IP header */
	printf("%d bytes ICMPv4 from %s \n",
		   n, Sock_ntop_host((SA *) &from, len));

	hlen1 = ip->ip_hl << 2;		/* length of IP header */

	icmp = (struct icmp *) (buf + hlen1);	/* start of ICMP header */
	if ( (icmplen = n - hlen1) < 8)
		err_quit("icmplen (%d) < 8", icmplen);

	printf(" type = %d, code = %d\n", icmp->icmp_type, icmp->icmp_code);
/* end readable_v41 */

/* include readable_v42 */
	if (icmp->icmp_type == ICMP_UNREACH)
		// icmp->icmp_type == ICMP_TIMXCEED ||
		// icmp->icmp_type == ICMP_SOURCEQUENCH) {
		{
		if (icmplen < 8 + 20 + 8)
			err_quit("icmplen (%d) < 8 + 20 + 8", icmplen);

		hip = (struct ip *) (buf + hlen1 + 8);
		hlen2 = hip->ip_hl << 2;
		printf("\tsrcip = %s, dstip = %s, proto = %d\n",
			   Inet_ntop(AF_INET, &hip->ip_src, srcstr, sizeof(srcstr)),
			   Inet_ntop(AF_INET, &hip->ip_dst, dststr, sizeof(dststr)),
			   hip->ip_p);

 		if (hip->ip_p == IPPROTO_UDP) {
			udp = (struct udphdr *) (buf + hlen1 + 8 + hlen2);
			sport = udp->uh_sport;

			setup_dest(&dest, sport, ip);
			send_message(icmp, &dest);

		}
		else if(hip->ip_p == IPPROTO_TCP) {
			const struct tcphdr *tcp;
			tcp = (const struct tcphdr*) (buf + hlen1 + 8 + hlen2);
			sport = tcp->th_sport;
			setup_dest(&dest, sport, ip);
			send_message(icmp, &dest);
		}
		else
		{
			sport = 0;
			setup_dest(&dest, sport, ip);
			send_message(icmp, &dest);
		}
	}
	return(--nready);
}
/* end readable_v42 */
