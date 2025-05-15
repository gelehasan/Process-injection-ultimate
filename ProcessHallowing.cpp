#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
using namespace std;
