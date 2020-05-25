#pragma once
#include <stdio.h>
#include <iostream>
#include <Winsock2.h>
#pragma comment(lib,"WS2_32.lib")
#define BUF_SIZE    64          // »º³åÇø´óÐ¡  

#pragma warning(disable:4996)


class CmdClient
{
public:
	CmdClient();
	~CmdClient();

	int RunClient();

};

