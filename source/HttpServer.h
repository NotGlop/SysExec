#pragma once

#include <iostream>
#include <string.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#define SECURITY_WIN32

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "secur32.lib")

#include <sspi.h>
#include "SmbConnection.h"

#define LISTEN_PORT 8989
#define BACKLOG 5
#define HTTP_BUFF_SIZE 10000
#define HTTP_OK "HTTP/1.1 200 OK"
#define HTTP_UNAUTHORIZED "HTTP/1.1 401 Unauthorized"
#define HTTP_AUTHENTICATE "WWW-Authenticate: NTLM"

using namespace std;

class HttpServer
{
public:
	HttpServer();
public:
	void	run();
	WCHAR*	_cmd;
private:
	char	_request[HTTP_BUFF_SIZE];
	SOCKET	_client;
	bool	_firstAuth;
	bool	_endSession;
	char	_ntlmblock[4242];
	SmbConnection _smb_con;

	void handleRequest();
	void handleOptionRequest();
	
	void doSMBStuff();
};

