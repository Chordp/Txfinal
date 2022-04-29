#include <Windows.h>
#include "Process.hpp"
#include <TlHelp32.h>


 HANDLE Process::hProcess;
 DWORD Process::Pid;
vector<DWORD> Process::GetProcessIdByName(string name	)
{
	std::vector<DWORD> found;
	auto hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hProcSnap)
		return found;

	PROCESSENTRY32 tEntry = { 0 };
	tEntry.dwSize = sizeof(PROCESSENTRY32W);

	// Iterate threads
	for (BOOL success = Process32First(hProcSnap, &tEntry);
		success != FALSE;
		success = Process32Next(hProcSnap, &tEntry))
	{
		if (name.empty() || string(tEntry.szExeFile) == name.c_str())
			found.emplace_back(tEntry.th32ProcessID);
	}

	return found;
}

void EnableDebugPriv()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		return;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL))
	{
		CloseHandle(hToken);
	}
}
void Process::Attach(DWORD PID)
{
	EnableDebugPriv();
	Pid = PID;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
}
HANDLE Process::GetBaseModule()
{
	MODULEENTRY32 moduleEntry;
	HANDLE handle = NULL;
	handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Pid); //  获取进程快照中包含在th32ProcessID中指定的进程的所有的模块。
	if (!handle) {
		CloseHandle(handle);
		return NULL;
	}
	ZeroMemory(&moduleEntry, sizeof(MODULEENTRY32));
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(handle, &moduleEntry)) {
		CloseHandle(handle);
		return NULL;
	}

	CloseHandle(handle);
	return moduleEntry.hModule;
}

HANDLE Process::GetProcessHandle()
{
	return hProcess;
}

bool Process::ReadMemory(PVOID address, PVOID buffer, size_t size)
{
	SIZE_T ret_size;
	return ReadProcessMemory(hProcess, address, buffer, size, &ret_size);
}
bool Process::WriteMemory(PVOID address, PVOID buffer, size_t size)
{
	SIZE_T ret_size;
	return WriteProcessMemory(hProcess, address, buffer, size, &ret_size);
}
HANDLE Process::GetProcessModuleHandle(string ModuleName)
{
	MODULEENTRY32 moduleEntry;
	HANDLE handle = NULL;
	handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Pid); //  获取进程快照中包含在th32ProcessID中指定的进程的所有的模块。
	if (!handle) {
		CloseHandle(handle);
		return NULL;
	}
	ZeroMemory(&moduleEntry, sizeof(MODULEENTRY32));
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(handle, &moduleEntry)) {
		CloseHandle(handle);
		return NULL;
	}
	do {
		if (string(moduleEntry.szModule) == ModuleName) {
			return moduleEntry.hModule;
		}
	} while (Module32Next(handle, &moduleEntry));
	CloseHandle(handle);
	return 0;
}