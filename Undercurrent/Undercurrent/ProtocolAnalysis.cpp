#include "ProtocolAnalysis.h"

ProtocolAnalysis::ProtocolAnalysis()
{

}

//TCP协议分析函数
void tcp_protocol_analysis(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{

    ProtocolAnalysis::tcp_header* tcp_protocol; //定义TCP协议变量
	u_char flags;                               //标记 
	int header_length;                          //长度 
	u_short source_port;                        //源端口
	u_short destination_port;                   //目的端口 
	u_short windows;                            //窗口大小
	u_short urgent_pointer;                     //紧急指针
	u_int sequence;                             //序列号
	u_int acknowledgement;                      //确认号
	u_int16_t checksum;                         //校验和
	tcp_protocol = (ProtocolAnalysis::tcp_header*)(packet_content + 14 + 20); // 获得TCP协议内容 
	source_port = ntohs(tcp_protocol->tcp_source_port);                       //获得源端口 
	destination_port = ntohs(tcp_protocol->tcp_destination_port);             //获得目的端口 
	header_length = tcp_protocol->tcp_offset * 4;                             //长度
	sequence = ntohl(tcp_protocol->tcp_sequence);                             //序列码 
	acknowledgement = ntohl(tcp_protocol->tcp_acknowledgement);               //确认序列码 
	windows = ntohs(tcp_protocol->tcp_windows);                               //窗口大小
	urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);                 //紧急指针
	flags = tcp_protocol->tcp_flags;                                          //标识
	checksum = ntohs(tcp_protocol->tcp_checksum);                             //校验和
	printf("-------  TCP协议   -------\n");
	printf("源端口号:%d\n", source_port);
	printf("目的端口号:%d\n", destination_port);
	switch (destination_port)
	{
	case 80:
		printf("上层协议为HTTP协议\n");
		break;
	case 21:
		printf("上层协议为FTP协议\n");
		break;
	case 23:
		printf("上层协议为TELNET协议\n");
		break;
	case 25:
		printf("上层协议为SMTP协议\n");
		break;
	case 110:
		printf("上层协议POP3协议\n");
		break;
	default:
		break;
	}
	printf("序列码:%u\n", sequence);
	printf("确认号:%u\n", acknowledgement);
	printf("首部长度:%d\n", header_length);
	printf("保留:%d\n", tcp_protocol->tcp_reserved);
	printf("标记:");
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
	printf("窗口大小:%d\n", windows);
	printf("校验和:%d\n", checksum);
	printf("紧急指针:%d\n", urgent_pointer);
}

ProtocolAnalysis::~ProtocolAnalysis()
{

}
