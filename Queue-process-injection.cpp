#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <cstring>
using namespace std;


unsigned char shellCode[] = {
	0x90, 0x20, 0x24
};

unsigned shellCodeLength = sizeof(shellCode);
