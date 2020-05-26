#include "Moniter.h"

Moniter::Moniter()
{
    /*pcap_if_t* alldevs;		      // ��ȡ�����豸�б�
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
	*/

    /* ��ȡ�����豸�б� */
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* ��ӡ�豸�б� */
    //pcap_if_t* d;
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (û����Ч��������Ϣ)\n");
    }
    // ���û���ҵ�����������
    if (i == 0)
    {
        printf("\nδ��������ӿڣ���ȷ��WinPcap����ȷ��װ��\n");
        return;
    }

    printf("������Ҫ�������ݰ�������ӿڱ�� (1-%d):", i);
    std::cin >> inum;

    if (inum < 1 || inum > i)
    {
        printf("\n�ӿڱ��Խ��.\n");
        /* �ͷ��豸�б� */
        pcap_freealldevs(alldevs);
        return;
    }

    /* ��ת��ѡ�е������� */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* ���豸 */
    if ((adhandle = pcap_open(d->name,							// �豸��
        65536,												// 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
        PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
        1000,													// ��ȡ��ʱʱ��
        NULL,													// Զ�̻�����֤
        errbuf													// ���󻺳��
    )) == NULL)
    {
        fprintf(stderr, "\n�޷���������������WinPcap��֧��%s \n", d->name);
        /* �ͷ��豸�б� */
        pcap_freealldevs(alldevs);
        return;
    }

    printf("\n��%s����������...\n", d->description);
    /* �ͷ��豸�б� */
    pcap_freealldevs(alldevs);
    /* ��ʼ���� */
	use_pacp_next_ex(adhandle);
    //pcap_loop(adhandle, 0, packet_handler, NULL);

}

/*ÿ�β������ݰ�ʱ���Զ����ûص����� */
/*void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm* ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
    /*local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
    // ��ӡ���յ�������
    printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
}  ;*/
 
/*��Ҫʹ��pacp_next_ex����ֱ�ӻ�����ݰ�*/
void use_pacp_next_ex(pcap_t* adhandle){
	struct tm *ltime;			//��ȡ���ݰ���ʱ��
	char timestr[16];//
	struct pcap_pkthdr *header; //���ݰ�ͷ
	const u_char *pkt_data;		//���ݰ�����

	int res;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/*��ʱʱ�䵽*/
			continue;
		/*��ʱ���ת��Ϊ��ʶ��ĸ�ʽ*/
		time_t local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec,header->len);
	}
	if (res == -1) {
		printf("���ݰ���ȡ����%s\n", pcap_geterr(adhandle));
		return ;
	}
	return;
}

Moniter::~Moniter()
{

}