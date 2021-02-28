#pragma once
#ifndef _R6829_H0
#define _R6829_H0
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iterator>
#include <vector>
#include <time.h>
#include <Windows.h>
#include <winternl.h>
#include "MinHook\MinHook.h"
using namespace std;

#include "SystemProcessInformationEx.h"
#include "FileBothDirInformationEx.h"
#include "FileFullDirInformationEx.h"
#include "FileIdBothDirInformationEx.h"
#include "FileIdFullDirInformationEx.h"
#include "FileNamesInformationEx.h"

#define _6829_STR L"$6829"

//#pragma comment(lib, "user32.lib")
//#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ntdll.lib")
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <ntddndis.h>
//#include <scsi.h>
#include <intrin.h>
#include <windef.h>
#include <ntstatus.h>

//
// ntoskrnl.exe
//
static auto SYSCALL_NTUSERFINDWNDEX = 0x106e;
static auto SYSCALL_NTUSERWNDFROMPOINT = 0x1014;
static auto SYSCALL_NTUSERBUILDWNDLIST = 0x101c;
static auto SYSCALL_NTGETFOREGROUNDWND = 0x103c;
static auto SYSCALL_NTUSERQUERYWND = 0x1010;

//
// win32k.sys
//
static auto SYSCALL_NTQUERYSYSINFO = 0x0033;
static auto SYSCALL_NTOPENPROCESS = 0x0023;
static auto SYSCALL_NTALLOCVIRTUALMEM = 0x0015;
static auto SYSCALL_NTWRITEVIRTUALMEM = 0x0037;
static auto SYSCALL_NTFREEVIRTUALMEM = 0x001b;
static auto SYSCALL_NTDEVICEIOCTRLFILE = 0x0004;
static auto SYSCALL_NTLOADDRIVER = 0x0004;

#endif