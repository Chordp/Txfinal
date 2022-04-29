#include <iostream>
#include "Process.hpp"
#include <psapi.h>
#include "Shellcode.h"
#include "VirtualMachine.hpp"
#include <fstream>

#define __cpp_lib_format
#include <format>
#define INRANGE(x,a,b)    (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))
uint64_t FindPattern(std::string ModuleName, std::string Pattern)
{
	const char* pat = Pattern.c_str();
	DWORD64 firstMatch = 0;
	DWORD64 rangeStart = (DWORD64)GetModuleHandle(ModuleName.c_str());
	MODULEINFO miModInfo;
	K32GetModuleInformation(GetCurrentProcess(), (HMODULE)rangeStart, &miModInfo, sizeof(MODULEINFO));
	DWORD64 rangeEnd = rangeStart + miModInfo.SizeOfImage;
	for (DWORD64 pCur = rangeStart; pCur < rangeEnd; pCur++)
	{
		if (!*pat)
			return firstMatch;

		if (*(PBYTE)pat == '\?' || *(BYTE*)pCur == getByte(pat))
		{
			if (!firstMatch)
				firstMatch = pCur;

			if (!pat[2])
				return firstMatch;

			if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
				pat += 3;

			else
				pat += 2;
		}
		else
		{
			pat = Pattern.c_str();
			firstMatch = 0;
		}
	}

	return NULL;
}

//Draw(Reg[4], Reg[5], Reg[6], Reg[7], 0xFF2DDBE7)
string opcode = R"[====](
Reg[4] = 50
Reg[5] = 50
Reg[6] = 0x130bd0
)[====]";


void OutDataToHead(vector<uint32_t> Table)
{
	char* data = (char*)Table.data();
	for (size_t i = 0; i < Table.size() * sizeof(uint32_t); i++)
	{
		data[i] ^=0xcc;
	}
	ofstream OutFile("Table.h");
	OutFile << "uint32_t Table[] = {" << endl;
	int i = 0;
	for (auto x: Table)
	{
		OutFile << std::format("0x{:0>8x},", x);
		if (i > 0 && (i % 10) == 0)
			OutFile << endl;
		i++;
	}
	OutFile << endl <<"};";
}
void main()
{
	//auto FixOpcode = VM::OutVituralOpCodeTable(opcode);
	//VM::ExecVirtual(FixOpcode);
	//return;
	for (size_t i = 0; i < sizeof(OpCodeTable); i++)
	{
		OpCodeTable[i] ^= 0xCC;
	}
	std::vector<uint32_t> Table((uint32_t*)OpCodeTable, (uint32_t*)(OpCodeTable + sizeof(OpCodeTable)));
	std::vector<uint32_t> SpTable;
	for (size_t i = 0; i < 7; i++)
	{
		if (i == 6)
		{
			auto op = VM::GenFixOpcode(Table);
			auto table = VM::OutVituralOpCodeTable(op);
			OutDataToHead(table);
			//VM::ExecVirtual(table);
			
			break;
		}
		printf_s("====ExecVirtual[%ld]====\n", i);

		VM::ExecVirtual(Table);

		
	}
	system("pause");







}