#pragma once
#include <process.h>

typedef struct {
	UCHAR  Protocol[4];
	UCHAR  Command;
	UINT32 Status;
	UCHAR  Flags;
	USHORT Flags2;
	USHORT PIDHigh;
	UCHAR  SecurityFeatures[8];
	USHORT Reserved;
	USHORT TID;
	USHORT PIDLow;
	USHORT UID;
	USHORT MID;
} SMB_Header;


#define SMB_COM_NEGOTIATE			0x72
#define SMB_COM_SESSION_SETUP_ANDX	0x73
#define SMB_COM_TREE_CONNECT_ANDX	0x75
#define SMB_COM_NT_CREATE_ANDX		0xa2
#define SMB_COM_TRANS_DCERPC		0x25

#define STATUS_SUCCESS				0x00000000

#define SMB_FLAGS_CASE_INSENSITIVE		0x08
#define SMB_FLAGS_CANONICALIZED_PATHS	0x10


class SmbConnection
{
public:
	SOCKET	_sockConnect;
	USHORT	_mid;	// message id
	char	_svc_handle[20];

	SmbConnection();
	~SmbConnection();

	void DoConnect();
	void ForgeSmbHeader(char* buffer, UCHAR command);
	void SendAndReceivePacket(char* buffer, int length, char* packet_name);

	void NegotiateExchange();

	// Establish session with {ntlmssp_buff} (type1 msg) of {ntlmssp_len} bytes
	// Fills {ntlmss_resp} (type2 msg) of <return int> bytes
	int SessionSetupExchange(char* ntlmssp_buff, int ntlmssp_len, char* ntlmssp_resp);
	void TreeConnectExchange();
	void NTCreateExchange();

	void TransDCERPC();
	void OpenSCManagerW();
	void OpenServiceW();
	void CreateServiceW(WCHAR* bin_path);
	void StartServiceW();
	void QueryServiceStatus();
	void DeleteService();
};