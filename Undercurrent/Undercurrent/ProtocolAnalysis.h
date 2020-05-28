
#include "pcap.h"
#include <stdlib.h>
#pragma once
class ProtocolAnalysis
{
public:
	ProtocolAnalysis();
	~ProtocolAnalysis();
	//TCPЭ���������
	void tcp_protocol_analysis(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);

	struct tcp_header  //����TCP���ݰ�ͷ��
	{
		u_int16_t tcp_source_port;         //Դ�˿ں�(16λ�޷�������)
		u_int16_t tcp_destination_port;    //Ŀ�Ķ˿ں�
		u_int32_t tcp_sequence;            //���к�
		u_int32_t tcp_acknowledgement;     //ȷ�����к�
		#ifdef WORDS_BIGENDIAN             //�ж�ϵͳ�Ĵ洢��ʽ�Ƿ�Ϊ���
			u_int8_t tcp_offset: 4,		   //����tcp_offsetƫ�Ʊ���ռ��4���ֽ�
			tcp_reserved: 4;              //�����ֶ�
		#else
			u_int8_t tcp_reserved : 4,
			tcp_offset : 4;
		#endif
		u_int8_t tcp_flags;                //���λ
		u_int16_t tcp_windows;             //���ڴ�С��TCP���Ͷ˵�ǰ�ɽ��ܵ��ֽ���
		u_int16_t tcp_checksum;            //У���
		u_int16_t tcp_urgent_pointer;      //����ָ��
	};

};

