#include <iostream>
#include <sstream>
#include <stack>
#include "VirtualMachine.hpp"
#include <regex>
using namespace std;


void VM::ExecVirtual(std::vector<uint32_t>& Vopcodes)
{
	int reg[10] = { 0 };
	uint32_t idx = 0;
	printf_s("Reg[8] = 50\n");
	printf_s("Reg[9] = 50\n");
	do
	{
		auto vidx = idx;
		auto branch = Vopcodes[idx];

		if (branch){
			switch (branch){
				case operate::Decrypt:{
					idx++;
					auto x = reg[0];
					auto y = reg[1];
					auto v = x * (y + 1);;
					reg[0] = Vopcodes[idx] ^ 'ACE';
					reg[1] = ((reg[0] ^ (y + x)) % 256
						+ (((reg[0] ^ (x * y)) % 256 + (((reg[0] ^ (y + v)) % 256) << 8)) << 8));
					printf_s("EE2362FC Reg[0],Reg[1] <- Decrypt(%d,%d)\n", reg[0], reg[1]);
					break;
				}
				case operate::Xor1:{
					auto i = 0i64;
					auto key = Vopcodes[vidx + 1];
					Vopcodes[idx] = -1;
					Vopcodes[vidx + 1] = -1;
					if (idx != 1)
					{
						do
							Vopcodes[i++] ^= key;
						while (i < idx - 1);
					}
					++idx;
					printf_s("EE69524A -> Xor 1\n");

					break;
				}
				case operate::Xor2: {
					idx += 2i64;
					auto count = Vopcodes[vidx + 1];
					auto key = Vopcodes[idx];
					if (count)
					{
						auto vidx_  = idx;
						do
						{
							Vopcodes[++vidx_] ^= key;
							key = Vopcodes[vidx_ - 1] + 0x12345678 * key;
							--count;
						} while (count);
					}
					Vopcodes[vidx] = -1;
					Vopcodes[vidx + 1] = -1;
					Vopcodes[idx] = -1;
					printf_s("FF4578AE -> Xor 2\n");
					break;
				}
				case operate::Xor3:{
					idx += 2i64;
					auto sidx = idx;
					auto count = (int)Vopcodes[vidx + 1];
					auto key = Vopcodes[idx];
					Vopcodes[vidx] = -1;
					Vopcodes[vidx + 1] = -1;
					Vopcodes[idx] = -1;
					if (count)
					{
						do
						{
							Vopcodes[++sidx] ^= key;
							--count;
						} while (count);
						printf_s("88659264 -> Xor 3\n");

					}
					break;

				}
				case operate::RegSub:
				{
					reg[0] -= reg[1];
					printf_s("9A8ECD52 Reg[0] -= Reg[1]\n");
					break;
				}
			
				case operate::RegAdd:
					reg[0] += reg[1];
					printf_s("89657EAD Reg[0] += Reg[1]\n");
					break;
				case operate::RegSwap:
				{
					idx += 2i64;
					reg[Vopcodes[idx]] = reg[Vopcodes[vidx + 1]];
					printf_s("8E7CADF2 Reg[%d] = Reg[%d]\n", Vopcodes[idx], Vopcodes[vidx + 1]);
					break;

				}
				case operate::RegAssignment: {
					idx += 2i64;
					reg[Vopcodes[idx]] = Vopcodes[vidx + 1];
					printf_s("1132EADF Reg[%d] = %d\n", Vopcodes[idx], Vopcodes[vidx + 1]);
					break;
				}
				case 0x9645AAED:
				{
					//if (Vopcodes[0] == 0xEE69624A && 
					//	Vopcodes[1] == 0x689EDC0A && 
					//	Vopcodes[2] == 0x98EFDBC9)
					//	printf_s("9645AAED -> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFFFFFF00)\n\n");
					// 压根没到这个分支
					break;
				}
				case operate::Draw:
				{
					if (Vopcodes[0] == 0xEE69624A && Vopcodes[1] == 0x689EDC0A && Vopcodes[2] == 0x98EFDBC9)
						printf_s("7852AAEF -> Draw(%d,%d,%x,%x,0xFF2DDBE7)\n\n",reg[4],reg[5],reg[6],reg[7]);
					break;
				}
				case operate::VmEnd: {
					printf_s("9645AEDC -> VMEnd\n");
					idx = 0x671i64;
					break;
				}
			}
		}	

		idx++;

	} while (idx < 0x671);


}

std::vector<Opcode> VM::GenFixOpcode(std::vector<uint32_t>& Vopcodes)
{
	int reg[10] = { 0 };
	uint32_t idx = 0;
	std::vector<Opcode> outData;
	//printf_s("Reg[8] = 50\n");
	//printf_s("Reg[9] = 50\n");
	reg[8] = 50;
	reg[9] = 50;
	do
	{
		auto vidx = idx;
		auto branch = Vopcodes[idx];

		if (branch) {
			switch (branch) {
			case operate::Decrypt: {
				++idx;
				auto x = reg[0];
				auto y = reg[1];
				auto v = x * (y + 1);;
				reg[0] = Vopcodes[idx] ^ 'ACE';
				reg[1] = ((reg[0] ^ (y + x)) % 256
					+ (((reg[0] ^ (x * y)) % 256 + (((reg[0] ^ (y + v)) % 256) << 8)) << 8));
				printf_s("EE2362FC Reg[0],Reg[1] <- Draw(%d,%d,%x,%x)\n", reg[4],reg[5],reg[0], reg[1]);
				//printf_s("EE2362FC Reg[0],Reg[1] <- Decrypt(%d,%d)\n", reg[0], reg[2]);
				break;
			}
			case operate::Xor1: {
				auto i = 0i64;
				auto key = Vopcodes[vidx + 1];
				Vopcodes[idx] = -1;
				Vopcodes[vidx + 1] = -1;
				if (idx != 1)
				{
					do
						Vopcodes[i++] ^= key;
					while (i < idx - 1);
				}
				++idx;
				//printf_s("EE69524A -> Xor 1\n");

				break;
			}
			case operate::Xor2: {
				idx += 2i64;
				auto count = Vopcodes[vidx + 1];
				auto key = Vopcodes[idx];
				if (count)
				{
					auto vidx_ = idx;
					do
					{
						Vopcodes[++vidx_] ^= key;
						key = Vopcodes[vidx_ - 1] + 0x12345678 * key;
						--count;
					} while (count);
				}
				Vopcodes[vidx] = -1;
				Vopcodes[vidx + 1] = -1;
				Vopcodes[idx] = -1;
				//printf_s("FF4578AE -> Xor 2\n");
				break;
			}
			case operate::Xor3: {
				idx += 2i64;
				auto sidx = idx;
				auto count = Vopcodes[vidx + 1];
				auto key = Vopcodes[idx];
				Vopcodes[vidx] = -1;
				Vopcodes[vidx + 1] = -1;
				Vopcodes[idx] = -1;
				if (count)
				{
					do
					{
						Vopcodes[++sidx] ^= key;
						--count;
					} while (count);
					//printf_s("88659264 -> Xor 3\n");

				}
				break;

			}
			case operate::RegSub:
			{
				reg[0] -= reg[1];
				//printf_s("9A8ECD52 Reg[0] -= Reg[1]\n");
				break;
			}

			case operate::RegAdd:
				reg[0] += reg[1];
				//printf_s("89657EAD Reg[0] += Reg[1]\n");
				break;
			case operate::RegSwap:
			{
				idx += 2i64;
				if (Vopcodes[idx] == 0 && Vopcodes[vidx + 1] == 1)
					Vopcodes[idx] = 3;

				reg[Vopcodes[idx]] = reg[Vopcodes[vidx + 1]];
				
				//printf_s("8E7CADF2 Reg[%d] = Reg[%d]\n", Vopcodes[idx], Vopcodes[vidx + 1]);
				break;

			}
			case operate::RegAssignment: {
				idx += 2i64;
				if (Vopcodes[vidx + 1] == 1000 || Vopcodes[vidx + 1] == 500)
					Vopcodes[vidx + 1] = 0;
				reg[Vopcodes[idx]] = Vopcodes[vidx + 1];

				//printf_s("1132EADF Reg[%d] = %d\n", Vopcodes[idx], Vopcodes[vidx + 1]);
				break;
			}
			case 0x9645AAED:
			{
				//if (Vopcodes[0] == 0xEE69624A && 
				//	Vopcodes[1] == 0x689EDC0A && 
				//	Vopcodes[2] == 0x98EFDBC9)
				//	printf_s("9645AAED -> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFFFFFF00)\n\n");
				// 压根没到这个分支
				break;
			}
			case operate::Draw:
			{
				if (Vopcodes[0] == 0xEE69624A && Vopcodes[1] == 0x689EDC0A && Vopcodes[2] == 0x98EFDBC9)
				{
					auto GenRegAssignment = [](int r,int value) {
						Opcode op;
						op.Type = operate::RegAssignment;
						op.Data.Assignment.Reg = r;
						op.Data.Assignment.Value = value;
						return op;
					};
					for (size_t i = 4; i <= 7; i++)
					{
						outData.push_back(GenRegAssignment(i, reg[i]));
					}
					Opcode op;
					op.Type = operate::Draw;
					outData.push_back(op);

					//printf_s("7852AAEF -> Draw(%d,%d,%d,%d,0xFF2DDBE7)\n\n", reg[4], reg[5], reg[6], reg[7]);

				}
				break;
			}
			case operate::VmEnd: {
				printf_s("9645AEDC -> VMEnd\n");
				idx = 0x671i64;
				break;
			}
			}
		}

		idx++;

	} while (idx < 0x671);
	return outData;
}

std::vector<Opcode> split(const std::string& str,char delimiter)
{
	std::vector<Opcode> op;
	std::string token;
	std::istringstream tokenStream(str);
	while (std::getline(tokenStream, token, delimiter))
	{
		const regex SwapReg("Reg\\[([0-9])\\]\\s*=\\s*Reg\\[([0-9])\\]");
		const regex AssignmentReg("^Reg\\[([0-9])\\]\\s*=\\s*([0-9]*)$");
		smatch m;
		if (regex_search(token, m, SwapReg))
		{
			Opcode opcode;
			opcode.Type = operate::RegSwap;
			opcode.Data.Swap.Target = std::stoi(m.str(1));
			opcode.Data.Swap.Source = std::stoi(m.str(2));
			op.push_back(opcode);
		}
		else if (regex_search(token, m, AssignmentReg))
		{
			Opcode opcode;
			opcode.Type = operate::RegAssignment;
			opcode.Data.Assignment.Reg = std::stoi(m.str(1));
			opcode.Data.Assignment.Value = std::stoi(m.str(2));
			op.push_back(opcode);
		}
	}
	
	return op;
}
std::vector<uint32_t> VM::OutVituralOpCodeTable(const std::string& opcode)
{
	auto opcodes = split(opcode, '\n');
	return OutVituralOpCodeTable(opcodes);

	
}
std::vector<uint32_t> VM::OutVituralOpCodeTable(const std::vector<Opcode>& opcodes)
{
	std::vector<uint32_t> outData;
	outData.push_back(0xEE69624A);
	outData.push_back(0x689EDC0A);
	outData.push_back(0x98EFDBC9);
	auto idx = 0;
	for (auto op : opcodes)
	{
		auto vidx = idx;
		switch (op.Type)
		{
		case operate::RegSwap: {

			outData.push_back(RegSwap);
			outData.push_back(op.Data.Swap.Target);
			outData.push_back(op.Data.Swap.Source);
			break;
		}
		case operate::RegAssignment:
		{

			outData.push_back(RegAssignment);
			outData.push_back(op.Data.Assignment.Value);

			outData.push_back(op.Data.Assignment.Reg);


			break;
		}
		case operate::Draw:
		{

			outData.push_back(Draw);
		}
		default:
			break;
		}
		idx++;
	}
	outData.push_back(operate::VmEnd);
	if (outData.size() < 0x671)
		outData.resize(0x671);
	return outData;
	
}
struct Save
{
	uint32_t Xor;
	uint32_t Key;
	uint32_t Index;
	uint32_t Count;
};

std::vector<uint32_t> VM::OutVituralOpCodeTable(std::vector<uint32_t> Vopcodes)
{
	std::vector<uint32_t> outData(Vopcodes.size());
	std::stack<Save> xorSave;
	uint32_t idx = 0;
	printf_s("Reg[8] = 50\n");
	printf_s("Reg[9] = 50\n");
	do
	{
		auto vidx = idx;
		auto branch = Vopcodes[idx];

		if (branch) {
			switch (branch) {
			case operate::Decrypt: {
				outData[idx] = operate::Decrypt;
				idx++;
				printf_s("EE2362FC Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],%d)\n", Vopcodes[idx]);
				break;
			}
			case operate::Xor1: {

				auto i = 0i64;
				auto key = Vopcodes[vidx + 1];
				Vopcodes[idx] = -1;
				Vopcodes[vidx + 1] = -1;
				
				if (idx != 1)
				{
					do{
						Vopcodes[i] ^= key;

						i++;
					}
					while (i < idx - 1);
				}
				++idx;
				printf_s("EE69524A -> Xor 1\n");

				break;
			}
			case operate::Xor2: {
				Vopcodes[idx] = operate::Xor2;

				idx += 2i64;
				
				auto count = Vopcodes[vidx + 1];
				auto key = Vopcodes[idx];
				outData[vidx + 1] = 0;
				outData[idx] = key;
				xorSave.push(Save{ 2u, key, idx, count });
				
				if (count)
				{
					auto vidx_ = idx;
					do
					{
						Vopcodes[vidx_] ^= key;
						key = Vopcodes[vidx_ - 1] + 0x12345678 * key;
						--count;
					} while (count);
				}
				Vopcodes[vidx] = -1;
				Vopcodes[vidx + 1] = -1;
				Vopcodes[idx] = -1;
				//printf_s("FF4578AE -> Xor 2\n");
				break;
			}
			case operate::RegSub:
			{
				outData[idx] = operate::RegSub;

				//printf_s("9A8ECD52 Reg[0] -= Reg[1]\n");
				break;
			}
			case operate::Xor3:
			{
				Vopcodes[idx] = operate::Xor3;
				idx += 2i64;
				auto sidx = idx;
				auto count = Vopcodes[vidx + 1];
				auto key = Vopcodes[idx];
				outData[vidx + 1] = 0;
				outData[idx] = key;
				
				xorSave.push(Save{ 3u, key, sidx, count });
				Vopcodes[vidx] = -1;
				Vopcodes[vidx + 1] = -1;
				Vopcodes[idx] = -1;
				if (count)
				{
					do
					{
						++sidx;
						Vopcodes[sidx] ^= key;
						--count;
					} while (count);
					//printf_s("88659264 -> Xor 3\n");

				}
				break;

			}
			case operate::RegAdd:
				outData[idx] = operate::RegAdd;
				
				//printf_s("89657EAD Reg[0] += Reg[1]\n");
				break;
			case operate::RegSwap:
			{
				/*
				Reg[3] = Reg[0]
				Reg[0] = Reg[1]
				Reg[1] = Reg[3]
				*/
				outData[idx] = operate::RegSwap;
				idx += 2i64;
			
				outData[idx] = Vopcodes[idx];
				outData[vidx + 1] = Vopcodes[vidx + 1];
				if (outData[idx] == 0 && outData[vidx + 1] == 1)
					outData[idx + 1] = 3;
				//printf_s("8E7CADF2 Reg[%d] = Reg[%d]\n", Vopcodes[idx], Vopcodes[vidx + 1]);
				break;

			}
			case operate::RegAssignment: {
				outData[idx] = operate::RegAssignment;

				idx += 2i64;
				outData[idx] = Vopcodes[idx];
				outData[vidx + 1] = Vopcodes[vidx + 1];

				if (outData[vidx + 1] == 1000 || outData[vidx + 1] == 500)
					outData[vidx + 1] = 0;
				//printf_s("1132EADF Reg[%d] = %d\n", Vopcodes[idx], Vopcodes[vidx + 1]);
				break;
			}
			case 0x9645AAED:
			{
				//if (Vopcodes[0] == 0xEE69624A && 
				//	Vopcodes[1] == 0x689EDC0A && 
				//	Vopcodes[2] == 0x98EFDBC9)
				//	printf_s("9645AAED -> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFFFFFF00)\n\n");
				// 压根没到这个分支
				break;
			}
			case operate::Draw:
			{

				if (Vopcodes[0] == 0xEE69624A && Vopcodes[1] == 0x689EDC0A && Vopcodes[2] == 0x98EFDBC9) {
					outData[idx] = operate::Draw;

					//printf_s("7852AAEF -> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)\n\n");

				}
				break;
			}
			case operate::VmEnd: {
				outData[idx] = operate::VmEnd;
				
				//printf_s("9645AEDC -> VMEnd\n");
				idx = 0x671i64;
				break;
			}
			}
		}

		idx++;

	} while (idx < 0x671);

	return outData;
}




