#include "GetAdapterInfo.h"

#include <stdlib.h>
// ������IP��ַת��Ϊ�ַ���
#define IPTOSBUFFERS	12

//"rpcap://              ==> lists interfaces in the local machine\n"
//"rpcap://hostname:port ==> lists interfaces in a remote machine\n"
//"                          (rpcapd daemon must be up and running\n"
//"                           and it must accept 'null' authentication)\n"
//"file://foldername     ==> lists all pcap files in the give folder\n\n"


GetAdapterInfo::GetAdapterInfo()
{
	pcap_if_t* alldevs;			// ��ȡ�����������豸����
	pcap_if_t* d;					// ָ��һ�������豸
	char errbuf[PCAP_ERRBUF_SIZE + 1];	// ���󻺳���

	// ��ȡ�����豸�б�
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	// ��ӡÿ�������豸����Ϣ
	for (d = alldevs; d; d = d->next)
	{
		ifprint(d);
	}

	// �ͷ������豸����
	pcap_freealldevs(alldevs);
}


char* GetAdapterInfo::iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;

	p = (u_char*)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
char* GetAdapterInfo::ip6tos(struct sockaddr* sockaddr, char* address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif


	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}
#endif /* __MINGW32__ */

// ��ӡָ���ӿڵ���Ϣ������dָ��Ҫ��ӡ�Ľӿ�
void GetAdapterInfo::ifprint(pcap_if_t* d)
{
	pcap_addr_t* a;
	char ip6str[128];

	// ��ӡ����
	printf("%s\n", d->name);
	// ��ӡ������Ϣ
	if (d->description)
		printf("\tDescription: %s\n", d->description);
	// ��ӡ������Ϣ
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
	// ��ӡ��ַ��Ϣ
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);
		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
			break;
		case AF_INET6:		// IPv6
			printf("\tAddress Family Name: AF_INET6\n");
#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
			if (a->addr)
				printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
#endif
			break;
		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}

GetAdapterInfo::~GetAdapterInfo()
{

}

