
#include "pcap.h"
#include <stdlib.h>
#pragma once
class ProtocolAnalysis
{
public:
	ProtocolAnalysis();
	~ProtocolAnalysis();
	//TCP协议分析函数
	void tcp_protocol_analysis(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);

	struct tcp_header  //定义TCP数据包头部
	{
		u_int16_t tcp_source_port;         //源端口号(16位无符号整形)
		u_int16_t tcp_destination_port;    //目的端口号
		u_int32_t tcp_sequence;            //序列号
		u_int32_t tcp_acknowledgement;     //确认序列号
		#ifdef WORDS_BIGENDIAN             //判断系统的存储方式是否为大端
			u_int8_t tcp_offset: 4,		   //定义tcp_offset偏移变量占有4个字节
			tcp_reserved: 4;              //保留字段
		#else
			u_int8_t tcp_reserved : 4,
			tcp_offset : 4;
		#endif
		u_int8_t tcp_flags;                //标记位
		u_int16_t tcp_windows;             //窗口大小，TCP发送端当前可接受的字节数
		u_int16_t tcp_checksum;            //校验和
		u_int16_t tcp_urgent_pointer;      //紧急指针
	};

};

