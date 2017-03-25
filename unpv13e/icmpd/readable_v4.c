/* include readable_v41 */
#include	"icmpd.h"
#include	<netinet/in_systm.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/udp.h>
#include	<netinet/tcp.h>

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
	
	/* TODO: Add filtering by ip_proto */ 
		/* 4find client's Unix domain socket, send headers */
	for (int i = 0; i <= maxi; i++) {
		if (client[i].connfd >= 0 &&
			client[i].family == AF_INET)
		{	

	printf("Sending for port %u\n", dest->sin_port);

			struct icmpd_err	icmpd_err;
			icmpd_err.icmpd_type = icmp->icmp_type;
			icmpd_err.icmpd_code = icmp->icmp_code;
			icmpd_err.icmpd_len = sizeof(struct sockaddr_in);
			memcpy(&icmpd_err.icmpd_dest, dest, sizeof(*dest));

				/* 4convert type & code to reasonable errno value */
			icmpd_err.icmpd_errno = EHOSTUNREACH;	/* default */
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

	printf("%d bytes ICMPv4 from %s:",
		   n, Sock_ntop_host((SA *) &from, len));

	ip = (struct ip *) buf;		/* start of IP header */
	hlen1 = ip->ip_hl << 2;		/* length of IP header */

	icmp = (struct icmp *) (buf + hlen1);	/* start of ICMP header */
	if ( (icmplen = n - hlen1) < 8)
		err_quit("icmplen (%d) < 8", icmplen);

	printf(" type = %d, code = %d\n", icmp->icmp_type, icmp->icmp_code);
/* end readable_v41 */

/* include readable_v42 */
	if (icmp->icmp_type == ICMP_UNREACH ||
		icmp->icmp_type == ICMP_TIMXCEED ||
		icmp->icmp_type == ICMP_SOURCEQUENCH) {
		if (icmplen < 8 + 20 + 8)
			err_quit("icmplen (%d) < 8 + 20 + 8", icmplen);

		hip = (struct ip *) (buf + hlen1 + 8);
		hlen2 = hip->ip_hl << 2;
		printf("\tsrcip = %s, dstip = %s, proto = %d\n",
			   Inet_ntop(AF_INET, &hip->ip_src, srcstr, sizeof(srcstr)),
			   Inet_ntop(AF_INET, &hip->ip_dst, dststr, sizeof(dststr)),
			   hip->ip_p);
	        bzero(&dest, sizeof(dest));
 		if (hip->ip_p == IPPROTO_UDP) {
			udp = (struct udphdr *) (buf + hlen1 + 8 + hlen2);
			sport = udp->uh_sport;

			setup_dest(&dest, sport, hip);
			send_message(icmp, &dest);

		}
		else if(hip->ip_p == IPPROTO_TCP) {
			const struct tcphdr *tcp;
			tcp = (const struct tcphdr*) (buf + hlen1 + 8 + hlen2);
			sport = tcp->th_sport;
			setup_dest(&dest, sport, hip);
			send_message(icmp, &dest);
		}
	}
	return(--nready);
}
/* end readable_v42 */
