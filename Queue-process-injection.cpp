#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <cstring>
using namespace std;


unsigned char shellCode[] = {
	0x90, 0x20, 0x24
};

unsigned shellCodeLength = sizeof(shellCode);


DWORD findProcessID(const wchar_t* processName) {
	DWORD processId = 0;

	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (processSnapshot == INVALID_HANDLE_VALUE) {
		cout << "Couldnt get process handles";
		return 0;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);

	if (Process32First(processSnapshot, &pe)) {
		do {
			if (wcscmp( pe.szExeFile, processName) ==0) {
				processId = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(processSnapshot, &pe));
	}

	CloseHandle(processSnapshot);

	return processId;
}
