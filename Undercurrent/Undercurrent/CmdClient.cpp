#include "CmdClient.h"

CmdClient::CmdClient()
{
}

CmdClient::~CmdClient()
{
}

int CmdClient::RunClient()
{
	WSADATA     wsd;					// 用于初始化Windows Socket   
	SOCKET      sHost;					// 与服务器进行通信的套接字   
	SOCKADDR_IN servAddr;			// 服务器地址   
	char        buf[BUF_SIZE];			// 用于接受数据缓冲区   
	int         retVal;							// 调用各种Socket函数的返回值   
	// 初始化Windows Socket
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		printf("WSAStartup failed !\n");
		return 1;
	}
	// 创建套接字   
	sHost = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (INVALID_SOCKET == sHost)
	{
		printf("socket failed !\n");
		WSACleanup();
		return -1;
	}
	// 设置套接字为非阻塞模式
	int iMode = 1;
	retVal = ioctlsocket(sHost, FIONBIO, (u_long FAR*) & iMode);
	if (retVal == SOCKET_ERROR)
	{
		printf("ioctlsocket failed !\n");
		WSACleanup();
		return -1;
	}
	// 设置服务器地址   
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.S_un.S_addr = inet_addr("192.168.43.2");		// 用户需要根据实际情况修改
	servAddr.sin_port = htons(9990);								// 在实际应用中，建议将服务器的IP地址和端口号保存在配置文件中
	int sServerAddlen = sizeof(servAddr);							// 计算地址的长度       
	// 循环等待
	while (true)
	{
		// 连接服务器   
		Sleep(200);
		retVal = connect(sHost, (LPSOCKADDR)&servAddr, sizeof(servAddr));
		Sleep(200);
		if (SOCKET_ERROR == retVal)
		{
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK || err == WSAEINVAL)			// 无法立即完成非阻塞套接字上的操作
			{
				//Sleep(500);
				continue;
			}
			else if (err == WSAEISCONN)												// 已建立连接
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
	// 循环向服务器发送字符串，并显示反馈信息。
	// 发送quit将使服务器程序退出，同时客户端程序自身也将退出
	while (true)
	{
		// 向服务器发送数据   
		printf("Please input a string to send: ");
		// 接收输入的数据
		std::string str;
		std::cin >> str;
		// 将用户输入的数据复制到buf中
		ZeroMemory(buf, BUF_SIZE);
		strcpy(buf, str.c_str());
		// 循环等待
		while (true)
		{
			// 向服务器发送数据
			retVal = send(sHost, buf, strlen(buf), 0);
			if (SOCKET_ERROR == retVal)
			{
				int err = WSAGetLastError();
				if (err == WSAEWOULDBLOCK)			// 无法立即完成非阻塞套接字上的操作
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
			ZeroMemory(buf, BUF_SIZE);						// 清空接收数据的缓冲区
			retVal = recv(sHost, buf, sizeof(buf) + 1, 0);   // 接收服务器回传的数据   
			if (SOCKET_ERROR == retVal)
			{
				int err = WSAGetLastError();				// 获取错误编码
				if (err == WSAEWOULDBLOCK)			// 接收数据缓冲区暂无数据
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
		//ZeroMemory(buf,BUF_SIZE);						// 清空接收数据的缓冲区
		//retVal = recv(sHost,buf,sizeof(buf)+1,0);   // 接收服务器回传的数据   

		printf("Recv From Server: %s\n", buf);
		// 如果收到quit，则退出
		if (strcmp(buf, "quit") == 0)
		{
			printf("quit!\n");
			break;
		}
	}
	// 释放资源   
	closesocket(sHost);
	WSACleanup();
	// 暂停，按任意键继续
	system("pause");
	return 0;
}
