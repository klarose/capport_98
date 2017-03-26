#include	"unp.h"

int
main(int argc, char **argv)
{
	int					sockfd;
	socklen_t			salen;
	struct sockaddr		*sa;

	if (argc != 2)
		err_quit("usage: udpcli01 <capport_script>");

	sockfd = Udp_client("localhost", "0", &sa, &salen);

	dg_cli(stdin, sockfd, sa, salen, argv[1]);

	exit(0);
}
