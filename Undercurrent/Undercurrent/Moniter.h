#pragma once

#include "pcap.h"
#define HAVE_REMOTE
#include "remote-ext.h"
#include <stdlib.h>
#include <iostream>

/* packet handler ����ԭ�� */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
/*use_pacp_next_ex����ԭ�ͣ����ڲ�׽���ݰ�*/
void use_pacp_next_ex(pcap_t* adhandle);

class Moniter
{
public:
	Moniter();
	~Moniter();

	pcap_if_t* alldevs;		      // ��ȡ�����豸�б�
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* d;
};

