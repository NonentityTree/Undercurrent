#include "FilterPacket.h"
FilterPacket::FilterPacket()
{
	Moniter moniter;
	pcap_if_t *alldevs=moniter.alldevs;		      // ��ȡ�����豸�б�
	pcap_if_t* d=moniter.d;				  //���ڱ����豸�б�
	pcap_t *adhandle=moniter.adhandle;			  //���ڲ�׽���ݵ�WinPcap�Ự
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;

	
	/*���������·�㣬����ֻ������̫��*/
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\n�˳���ֻ��������̫����\n");
		/*�ͷ��豸�б�*/
		pcap_freealldevs(alldevs);
		return;
	}
	if (d->addresses != NULL)
		/*��ýӿڵ�һ����ַ������*/
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/*����ӿ�û�е�ַ����ô���Ǽ���һ��C�������*/
		netmask = 0xfffffff;
	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\n�޷�������˰��������﷨��\n");
		/*�ͷ��豸�б�*/
		pcap_freealldevs(alldevs);
		return;
	}
	//���ù�����
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\n���ù�����ʱ���ִ���");
		/*�ͷ��豸�б�*/
		pcap_freealldevs(alldevs);
		return;
	}
	printf("\n���ڼ���%s...\n", d->description);
	/*�ͷ��豸�б�*/
	pcap_freealldevs(alldevs);
}
FilterPacket::~FilterPacket()
{

}
