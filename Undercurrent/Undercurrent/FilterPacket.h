#pragma once
#include "pcap.h"
#define HAVE_REMOTE
#include "remote-ext.h"
#include <stdlib.h>
#include <iostream>
#include "Moniter.h"  //“˝»ÎMoniter¿‡

class FilterPacket
{ 
public:
	FilterPacket();
	~FilterPacket();
};

