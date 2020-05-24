#pragma once

#include "pcap.h"
#define HAVE_REMOTE
#include "remote-ext.h"
#include <stdlib.h>
#include <iostream>

/* packet handler º¯ÊýÔ­ÐÍ */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

class Moniter
{
public:
	Moniter();
	~Moniter();
};

