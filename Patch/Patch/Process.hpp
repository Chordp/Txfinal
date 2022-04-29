#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
using namespace std;
class Process
{
	static HANDLE hProcess;
	static DWORD Pid;
public:
	static vector<DWORD> GetProcessIdByName(string ProcessName);
	static void Attach(DWORD PID);
	template<class T> static T Read(PVOID address)
	{
		T buffer{};
		SIZE_T ret_size;
		ReadProcessMemory(hProcess, address, &buffer, sizeof(T), &ret_size);
		return buffer;
	}
	template<class T> static T Read(ULONG64 address)
	{

		return Read<T>((PVOID)address);
	}
	template <class T> static bool Write(PVOID address, T buffer)
	{
		SIZE_T ret_size;
		return WriteProcessMemory(hProcess, address, &buffer, sizeof(T), &ret_size);
	}
	static bool ReadMemory(PVOID address, PVOID buffer, size_t size);
	static bool WriteMemory(PVOID address, PVOID buffer, size_t size);
	
	static HANDLE GetProcessModuleHandle(string ModuleName);
	static HANDLE GetBaseModule();
	static HANDLE GetProcessHandle();
	
};

