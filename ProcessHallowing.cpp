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


}
