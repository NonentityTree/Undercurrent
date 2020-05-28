#include "ProtocolAnalysis.h"

ProtocolAnalysis::ProtocolAnalysis()
{

}

//TCPЭ���������
void tcp_protocol_analysis(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{

    ProtocolAnalysis::tcp_header* tcp_protocol; //����TCPЭ�����
	u_char flags;                               //��� 
	int header_length;                          //���� 
	u_short source_port;                        //Դ�˿�
	u_short destination_port;                   //Ŀ�Ķ˿� 
	u_short windows;                            //���ڴ�С
	u_short urgent_pointer;                     //����ָ��
	u_int sequence;                             //���к�
	u_int acknowledgement;                      //ȷ�Ϻ�
	u_int16_t checksum;                         //У���
	tcp_protocol = (ProtocolAnalysis::tcp_header*)(packet_content + 14 + 20); // ���TCPЭ������ 
	source_port = ntohs(tcp_protocol->tcp_source_port);                       //���Դ�˿� 
	destination_port = ntohs(tcp_protocol->tcp_destination_port);             //���Ŀ�Ķ˿� 
	header_length = tcp_protocol->tcp_offset * 4;                             //����
	sequence = ntohl(tcp_protocol->tcp_sequence);                             //������ 
	acknowledgement = ntohl(tcp_protocol->tcp_acknowledgement);               //ȷ�������� 
	windows = ntohs(tcp_protocol->tcp_windows);                               //���ڴ�С
	urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);                 //����ָ��
	flags = tcp_protocol->tcp_flags;                                          //��ʶ
	checksum = ntohs(tcp_protocol->tcp_checksum);                             //У���
	printf("-------  TCPЭ��   -------\n");
	printf("Դ�˿ں�:%d\n", source_port);
	printf("Ŀ�Ķ˿ں�:%d\n", destination_port);
	switch (destination_port)
	{
	case 80:
		printf("�ϲ�Э��ΪHTTPЭ��\n");
		break;
	case 21:
		printf("�ϲ�Э��ΪFTPЭ��\n");
		break;
	case 23:
		printf("�ϲ�Э��ΪTELNETЭ��\n");
		break;
	case 25:
		printf("�ϲ�Э��ΪSMTPЭ��\n");
		break;
	case 110:
		printf("�ϲ�Э��POP3Э��\n");
		break;
	default:
		break;
	}
	printf("������:%u\n", sequence);
	printf("ȷ�Ϻ�:%u\n", acknowledgement);
	printf("�ײ�����:%d\n", header_length);
	printf("����:%d\n", tcp_protocol->tcp_reserved);
	printf("���:");
	if (flags & 0x08)
		printf("PSH ");
	if (flags & 0x10)
		printf("ACK ");
	if (flags & 0x02)
		printf("SYN ");
	if (flags & 0x20)
		printf("URG ");
	if (flags & 0x01)
		printf("FIN ");
	if (flags & 0x04)
		printf("RST ");
	printf("\n");
	printf("���ڴ�С:%d\n", windows);
	printf("У���:%d\n", checksum);
	printf("����ָ��:%d\n", urgent_pointer);
}

ProtocolAnalysis::~ProtocolAnalysis()
{

}
