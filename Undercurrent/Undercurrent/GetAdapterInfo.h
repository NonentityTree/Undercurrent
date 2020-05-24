#pragma once

#include <stdio.h>
#define HAVE_REMOTE
#include <pcap.h>
#include <remote-ext.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock.h>
#endif

class GetAdapterInfo
{
public:
	GetAdapterInfo();
	~GetAdapterInfo();

	// Function prototypes
	void ifprint(pcap_if_t* d);
	char* iptos(u_long in);
	char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen);
};

