#pragma once
#include <vector>
#include <string>
enum operate
{
	Decrypt = 0xEE2362FC,
	Xor1 = 0xEE69524A,
	Xor2 = 0xFF4578AE,
	RegSub = 0x9A8ECD52,
	Xor3 = 0x88659264,
	RegAdd = 0x89657EAD,
	RegSwap = 0x8E7CADF2,
	RegAssignment = 0x1132EADF,
	Draw = 0x7852AAEF,
	VmEnd = 0x9645AEDC

};
struct Opcode
{
	operate Type;
	union
	{
		struct
		{
			uint32_t Target;
			uint32_t Source;
		}Swap;
		struct
		{
			uint32_t Reg;
			uint32_t Value;
		}Assignment;

	}Data;


};
class VM
{
public:
	static void ExecVirtual(std::vector<uint32_t>& Vopcodes);
	static std::vector<Opcode> GenFixOpcode(std::vector<uint32_t>& Vopcodes);

	static std::vector<uint32_t> OutVituralOpCodeTable(std::vector<uint32_t>  Vopcodes);
	static std::vector<uint32_t> OutVituralOpCodeTable(const std::string& opcode);
	static std::vector<uint32_t> OutVituralOpCodeTable(const std::vector<Opcode>& opcode);

};
