#pragma once

#include "pcap.h"
#define HAVE_REMOTE
#include "remote-ext.h"
#include <stdlib.h>
#include <iostream>

/* packet handler 函数原型 */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
/*use_pacp_next_ex函数原型，用于捕捉数据包*/
void use_pacp_next_ex(pcap_t* adhandle);

class Moniter
{
public:
	Moniter();
	~Moniter();

	pcap_if_t* alldevs;		      // 获取到的设备列表
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* d;
};

