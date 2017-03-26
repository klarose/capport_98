/* include dgcli011 */
#include	"unpicmpd.h"

void do_capport(const char *ip)
{
	printf("OMG Behind a captive portal!\n");
	
	char commandStr[256];
	snprintf(commandStr, sizeof(commandStr), "python3 pycapport.py %s", ip);	
	printf("Running %s ...", commandStr);
	int ret = system(commandStr);
	printf("%i\n", ret);
}

void
dg_cli(FILE *fp, int sockfd, const SA *pservaddr, socklen_t servlen)
{
	int				icmpfd, maxfdp1;
	char			sendline[MAXLINE], recvline[MAXLINE + 1];
	fd_set			rset;
	ssize_t			n;
	struct timeval	tv;
	struct icmpd_err icmpd_err;
	struct sockaddr_un sun;

	Sock_bind_wild(sockfd, pservaddr->sa_family);

	icmpfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
	sun.sun_family = AF_LOCAL;
	strcpy(sun.sun_path, ICMPD_PATH);
	Connect(icmpfd, (SA *)&sun, sizeof(sun));
	Write_fd(icmpfd, "1", 1, sockfd);
	n = Read(icmpfd, recvline, 1);
	if (n != 1 || recvline[0] != '1')
		err_quit("error creating icmp socket, n = %d, char = %c",
				 n, recvline[0]);

	FD_ZERO(&rset);
	maxfdp1 = max(sockfd, icmpfd) + 1;
/* end dgcli011 */

/* include dgcli012 */
	while (1) {

		tv.tv_sec = 5;
		tv.tv_usec = 0;
		FD_SET(sockfd, &rset);
		FD_SET(icmpfd, &rset);
		if ( (n = Select(maxfdp1, &rset, NULL, NULL, &tv)) == 0) {
			continue;
		}

		if (FD_ISSET(sockfd, &rset)) {
			n = Recvfrom(sockfd, recvline, MAXLINE, 0, NULL, NULL);
			recvline[n] = 0;	/* null terminate */
			Fputs(recvline, stdout);
		}

		if (FD_ISSET(icmpfd, &rset)) {
			if ( (n = Read(icmpfd, &icmpd_err, sizeof(icmpd_err))) == 0)
				err_quit("ICMP daemon terminated");
			else if (n != sizeof(icmpd_err))
				err_quit("n = %d, expected %d", n, sizeof(icmpd_err));
			printf("ICMP error: dest = %s, %s, type = %d, code = %d\n",
				   Sock_ntop(&icmpd_err.icmpd_dest, icmpd_err.icmpd_len),
				   strerror(icmpd_err.icmpd_errno),
				   icmpd_err.icmpd_type, icmpd_err.icmpd_code);
			if(icmpd_err.has_capport)
			{
				do_capport(Sock_ntop_host(&icmpd_err.icmpd_dest,
						          icmpd_err.icmpd_len));
			}
		}
	}
}
/* end dgcli012 */
