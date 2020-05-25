#include "CmdClient.h"

CmdClient::CmdClient()
{
}

CmdClient::~CmdClient()
{
}

int CmdClient::RunClient()
{
	WSADATA     wsd;					// ���ڳ�ʼ��Windows Socket   
	SOCKET      sHost;					// �����������ͨ�ŵ��׽���   
	SOCKADDR_IN servAddr;			// ��������ַ   
	char        buf[BUF_SIZE];			// ���ڽ������ݻ�����   
	int         retVal;							// ���ø���Socket�����ķ���ֵ   
	// ��ʼ��Windows Socket
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		printf("WSAStartup failed !\n");
		return 1;
	}
	// �����׽���   
	sHost = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (INVALID_SOCKET == sHost)
	{
		printf("socket failed !\n");
		WSACleanup();
		return -1;
	}
	// �����׽���Ϊ������ģʽ
	int iMode = 1;
	retVal = ioctlsocket(sHost, FIONBIO, (u_long FAR*) & iMode);
	if (retVal == SOCKET_ERROR)
	{
		printf("ioctlsocket failed !\n");
		WSACleanup();
		return -1;
	}
	// ���÷�������ַ   
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.S_un.S_addr = inet_addr("192.168.43.2");		// �û���Ҫ����ʵ������޸�
	servAddr.sin_port = htons(9990);								// ��ʵ��Ӧ���У����齫��������IP��ַ�Ͷ˿ںű����������ļ���
	int sServerAddlen = sizeof(servAddr);							// �����ַ�ĳ���       
	// ѭ���ȴ�
	while (true)
	{
		// ���ӷ�����   
		Sleep(200);
		retVal = connect(sHost, (LPSOCKADDR)&servAddr, sizeof(servAddr));
		Sleep(200);
		if (SOCKET_ERROR == retVal)
		{
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK || err == WSAEINVAL)			// �޷�������ɷ������׽����ϵĲ���
			{
				//Sleep(500);
				continue;
			}
			else if (err == WSAEISCONN)												// �ѽ�������
			{
				break;
			}
			else
			{
				continue;

				//printf("connect failed !\n");   
				//closesocket(sHost);   
				//WSACleanup();   
				//return -1;   
			}
		}
	}
	// ѭ��������������ַ���������ʾ������Ϣ��
	// ����quit��ʹ�����������˳���ͬʱ�ͻ��˳�������Ҳ���˳�
	while (true)
	{
		// ���������������   
		printf("Please input a string to send: ");
		// �������������
		std::string str;
		std::cin >> str;
		// ���û���������ݸ��Ƶ�buf��
		ZeroMemory(buf, BUF_SIZE);
		strcpy(buf, str.c_str());
		// ѭ���ȴ�
		while (true)
		{
			// ���������������
			retVal = send(sHost, buf, strlen(buf), 0);
			if (SOCKET_ERROR == retVal)
			{
				int err = WSAGetLastError();
				if (err == WSAEWOULDBLOCK)			// �޷�������ɷ������׽����ϵĲ���
				{
					Sleep(500);
					continue;
				}
				else
				{
					printf("send failed !\n");
					closesocket(sHost);
					WSACleanup();
					return -1;
				}
			}
			break;
		}

		while (true)
		{
			ZeroMemory(buf, BUF_SIZE);						// ��ս������ݵĻ�����
			retVal = recv(sHost, buf, sizeof(buf) + 1, 0);   // ���շ������ش�������   
			if (SOCKET_ERROR == retVal)
			{
				int err = WSAGetLastError();				// ��ȡ�������
				if (err == WSAEWOULDBLOCK)			// �������ݻ�������������
				{
					Sleep(100);
					printf("waiting back msg !\n");
					continue;
				}
				else if (err == WSAETIMEDOUT || err == WSAENETDOWN)
				{
					printf("recv failed !\n");
					closesocket(sHost);
					WSACleanup();
					return -1;
				}
				break;
			}
			break;
		}
		//ZeroMemory(buf,BUF_SIZE);						// ��ս������ݵĻ�����
		//retVal = recv(sHost,buf,sizeof(buf)+1,0);   // ���շ������ش�������   

		printf("Recv From Server: %s\n", buf);
		// ����յ�quit�����˳�
		if (strcmp(buf, "quit") == 0)
		{
			printf("quit!\n");
			break;
		}
	}
	// �ͷ���Դ   
	closesocket(sHost);
	WSACleanup();
	// ��ͣ�������������
	system("pause");
	return 0;
}
