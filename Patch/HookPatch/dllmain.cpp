// dllmain.cpp : 定义 DLL 应用程序的入口点。
#define INITGUID

#include <Windows.h>
#include <thread>
#include <iostream>
#include <string>
#include <memory>
#include <psapi.h>
#include "defs.h"
#include <d3d11.h>
#include <wincodec.h>
#include <sstream>
#include "Inc/ScreenGrab.h"
#include "Table.h"
#include "include/MinHook.h"
#pragma comment(lib,"d3d11.lib")
#pragma comment(lib,"DirectXTK.lib")
using namespace std;
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
struct flag
{
	int x;
	int y;
	int k1;
	int k2;
};
template<class T = uint64_t, class call_pointer, class... Args>
T call_invoke(call_pointer call, Args... args)
{
	return reinterpret_cast<T(*)(Args...)>(call)(args...);
}

flag f[42];
uint8_t* draw_rect = 0;
uint8_t* draw_orig = 0;
__int64 __fastcall sub_420(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, __int64 a7)
{
	f[0] =  { 50  , 50 , 0x130bd0 , 0xf814b4 };
	f[1] =  { 50  , 122, 0x1bcd69 , 0xe9bdc5 };
	f[2] =  { 50  , 194, 0xd91997 , 0x4f7363 };
	f[3] =  { 50  , 266, 0xe82b18 , 0x28ec24 };
	f[4] =  { 50  , 338, 0x391faa , 0x22ae2e };
	f[5] =  { 50  , 410, 0xd77de2 , 0x2f62e };
	f[6] =  { 122 , 266, 0x71150  , 0x1894d4 };
	f[7] =  { 194 , 266, 0xc42e8b , 0xeb1f47 };
	f[8] =  { 266 , 266, 0x34cf2b , 0x534f3f };
	f[9] =  { 122 , 122, 0xd9e5f1 , 0xe9d505 };
	f[10] = { 194 , 194, 0xc42d8b , 0x38f0f };
	f[11] = { 770 , 50, 0xeabf17  , 0x8f7323 };
	f[12] = { 698 , 122, 0xc42d8b , 0x532fbf };
	f[13] = { 626 , 194, 0xd717af , 0x37cb9b };
	f[14] = { 554 , 266, 0xc460e9 , 0x314ddd };
	f[15] = { 482 , 338, 0xc7a989 , 0x11edbd };
	f[16] = { 554 , 338, 0xab7100 , 0xf0747c };
	f[17] = { 626 , 338, 0xc409a9 , 0xe12d6d };
	f[18] = { 842 , 50, 0xd77e8b  , 0x7bfff7 };
	f[19] = { 914 , 50, 0xd9ad01  , 0x4985c5 };
	f[20] = { 986 , 50, 0x39e156  , 0xf6c25a };
	f[21] = { 842 , 122, 0x13207c , 0x7438b8 };
	f[22] = { 914 , 194, 0xc9140b , 0xf3af5f };
	f[23] = { 986 , 266, 0x53071f , 0x779bfb };
	f[24] = { 1058 , 338, 0xd71106 , 0x5ee272 };
	f[25] = { 1130 , 338, 0xeb60a1 , 0x11551d };
	f[26] = { 1202 , 338, 0xeb67cd , 0xc5c9c9 };
	f[27] = { 1274 , 338, 0xd71161 , 0x1752d };
	f[28] = { 1130 , 50, 0x677611 , 0x41a58d };
	f[29] = { 1202 , 50, 0x40173d , 0x95f9d9 };
	f[30] = { 1274 , 50, 0xd77661 , 0x61b54d };
	f[31] = { 1346 , 50, 0xefff9a , 0xc27eee };
	f[32] = { 1202 , 122, 0xc404eb , 0xeb3fc7 };
	f[33] = { 1274 , 194, 0xd7c6ef , 0xdf9b53 };
	f[34] = { 1346 , 194, 0xd7701f , 0x171b1b };
	f[35] = { 1418 , 194, 0xd71171 , 0x91e53d };
	f[36] = { 1490 , 194, 0x3906ab , 0x138f3f };
	f[37] = { 1346 , 266, 0x96663 , 0x83f72f };
	f[38] = { 1418 , 338, 0x732157 , 0x47638b };
	f[39] = { 1490 , 338, 0x353730 , 0x587414 };
	f[40] = { 1562 , 338, 0x6257a9 , 0x69fdc5 };
	f[41] = { 1634 , 338, 0xd777af , 0xb7cb1b };



	for (auto& data : f)
	{
		
		call_invoke(draw_rect, data.x, data.y, data.k1, data.k2, 0xFF2DDBE7, a3, a4, a5, a6, a7);
		
		//reinterpret_cast<uint64_t(*)(int, int, int, int, int, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)>(draw_rect)
		//    (data.x, data.y, data.k1, data.k2, 0xFFFFFF00, a3, a4, a5, a6, a7);
	}
	return 0;
}
uint8_t* PresentMultiplaneOverlay_orig = 0;

void screenshot(IDXGISwapChain* pSwapChain)
{
	ID3D11Device* device;

	HRESULT gd = pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&device);
	if (device && gd == S_OK)
	{
		//Get context
		ID3D11DeviceContext* context;
		device->GetImmediateContext(&context);
		
		//get back buffer
		ID3D11Texture2D* backbufferTex;
		HRESULT gb = pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&backbufferTex);

		if (gb == S_OK)
		{
			HRESULT hr = DirectX::SaveWICTextureToFile(context, backbufferTex, GUID_ContainerFormatJpeg, L"d:\\dwm.jpg");
			if (hr == S_OK)
				cout << "截图成功" << endl;
		}
		//Capture Frame
	
	}

}
__int64 __fastcall  PresentMultiplaneOverlay(IDXGISwapChain* _this,
	int a2,
	int a3,
	int a4,
	const void* a5,
	unsigned int a6,
	const struct _DXGI_PRESENT_MULTIPLANE_OVERLAY* a7)
{

	auto hr = reinterpret_cast<decltype(&PresentMultiplaneOverlay)>(PresentMultiplaneOverlay_orig)(_this,a2,a3,a4,a5,a6,a7);
	if(GetAsyncKeyState(VK_HOME)& 0x8000)
		screenshot(_this);
	return hr;
}

void OnStart()
{
	MH_Initialize();

	FILE* file;
	AllocConsole();
	freopen_s(&file, "CONIN$", "r", stdin);
	freopen_s(&file, "CONOUT$", "w", stdout);
	uint64_t hook = 0;
	while (true)
	{
		hook = FindPattern("dxgi.dll", "68 ?? ?? ?? ?? C7 44 24 04 ?? ?? ?? ??");
		if (hook)
			break;
		Sleep(100);
	}
	uint8_t* Shellcode = 0;

	LODWORD(Shellcode) = *(DWORD*)(hook + 1);
	HIDWORD(Shellcode) = *(DWORD*)(hook + 9);

	Shellcode -= 0x860;

	draw_rect = Shellcode;
	auto draw = Shellcode + 0x420;
	//draw_orig = Shellcode + 0x420;

	MH_CreateHook(draw, &sub_420, (LPVOID*)&draw_orig);
	MH_EnableHook(draw);
	Sleep(1000);
	MH_CreateHook((PVOID)hook, PresentMultiplaneOverlay, (LPVOID*)&PresentMultiplaneOverlay_orig);
	MH_EnableHook((PVOID)hook);
	cout << (PVOID)Shellcode << endl;
	cout << (PVOID)hook << endl;

}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		thread(OnStart).detach();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

