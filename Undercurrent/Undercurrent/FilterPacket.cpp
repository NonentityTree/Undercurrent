#include "FilterPacket.h"
FilterPacket::FilterPacket()
{
	Moniter moniter;
	pcap_if_t *alldevs=moniter.alldevs;		      // 获取到的设备列表
	pcap_if_t* d=moniter.d;				  //用于遍历设备列表
	pcap_t *adhandle=moniter.adhandle;			  //用于捕捉数据的WinPcap会话
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;

	
	/*检查数据链路层，这里只考虑以太网*/
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\n此程序只工作在以太网。\n");
		/*释放设备列表*/
		pcap_freealldevs(alldevs);
		return;
	}
	if (d->addresses != NULL)
		/*获得接口第一个地址的掩码*/
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/*如果接口没有地址，那么我们假设一个C类的掩码*/
		netmask = 0xfffffff;
	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\n无法编译过滤包，请检查语法。\n");
		/*释放设备列表*/
		pcap_freealldevs(alldevs);
		return;
	}
	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\n设置过滤器时出现错误");
		/*释放设备列表*/
		pcap_freealldevs(alldevs);
		return;
	}
	printf("\n正在监听%s...\n", d->description);
	/*释放设备列表*/
	pcap_freealldevs(alldevs);
}
FilterPacket::~FilterPacket()
{

}
