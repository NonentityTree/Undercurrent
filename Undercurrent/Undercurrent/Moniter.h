#pragma once

#include "pcap.h"
#define HAVE_REMOTE
#include "remote-ext.h"
#include <stdlib.h>
#include <iostream>

/* packet handler ����ԭ�� */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

class Moniter
{
public:
	Moniter();
	~Moniter();
};

