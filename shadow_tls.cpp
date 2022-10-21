// shadow_tls.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "shadow_tls_client.h"
#include "shadow_tls_server.h"

#include "debug_helper.h"

#include <thread>

void usage(char* pragma)
{
	printf("%s client|server [option]\n", pragma);
	printf("option:\n");
	printf("\tport for server default:9981\n");

	printf("\tserver_address for client eg:192.168.2.206:9981\n");
	printf("\tshadow_domain default:www.baidu.com\n");
}

int main(int argc, char* argv[])
{
	if(argc < 2)
	{
		usage(argv[0]);
		return 1;
	}

	WSADATA wsa{};
	WSAStartup(MAKEWORD(2,2), &wsa);

	if(strcmp(argv[1], "client") == 0)
	{
		std::string shadow_address = "www.baidu.com";
		if(argc == 4)
		{
			shadow_address = argv[3];
		}
		shadow_tls_client cli;
		cli.connect(argv[2], shadow_address);
		std::this_thread::sleep_for(std::chrono::minutes(1));
	}
	else if(strcmp(argv[1], "server") == 0)
	{
		unsigned short port = 9981;
		std::string shadow_address = "www.baidu.com";
		if(argc == 3)
			port = atoi(argv[2]);
		if(argc == 4)
			shadow_address = argv[3];
		shadow_tls_server srv;
		srv.start_server(port);
		std::this_thread::sleep_for(std::chrono::minutes(1));
	}
	else
	{
		usage(argv[0]);
		return 1;
	}

	WSACleanup();
	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
