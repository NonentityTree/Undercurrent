#include "Moniter.h"

Moniter::Moniter()
{
    pcap_if_t* alldevs;		// 获取到的设备列表
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* 获取本机设备列表 */
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* 打印设备列表 */
    pcap_if_t* d;
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (没有有效的描述信息)\n");
    }
    // 如果没有找到网络适配器
    if (i == 0)
    {
        printf("\n未发现网络接口！请确定WinPcap被正确安装。\n");
        return;
    }

    printf("请输入要捕获数据包的网络接口编号 (1-%d):", i);
    std::cin >> inum;

    if (inum < 1 || inum > i)
    {
        printf("\n接口编号越界.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return;
    }

    /* 跳转到选中的适配器 */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* 打开设备 */
    if ((adhandle = pcap_open(d->name,							// 设备名
        65536,												// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
        PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
        1000,													// 读取超时时间
        NULL,													// 远程机器验证
        errbuf													// 错误缓冲池
    )) == NULL)
    {
        fprintf(stderr, "\n无法打开网络适配器。WinPcap不支持%s \n", d->name);
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return;
    }

    printf("\n在%s上启动监听...\n", d->description);
    /* 释放设备列表 */
    pcap_freealldevs(alldevs);
    /* 开始捕获 */
    pcap_loop(adhandle, 0, packet_handler, NULL);
}

/* 每次捕获到数据包时，自动调用回调函数 */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm* ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
    // 打印接收到的数据
    printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
}

Moniter::~Moniter()
{

}