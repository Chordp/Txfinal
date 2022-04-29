# 决赛 writeup

| 文件名                   | 作用                                     |
| ------------------------ | ---------------------------------------- |
| PatchDriver.sys          | patch释放和vad断链 flag                  |
| HookPatch.dll            | hook 方式 绘制flag和截图                 |
| print.exe                | 输出虚拟机操作码 修复操作码 输出正确坐标 |
| dump.mem                 | shellcode ida分析文件                    |
| 2022GameSafeRace.sys.i64 | 驱动 ida分析文件                         |
| Patch.zip                | vs项目压缩包                             |
| screenshot.dll           | 截图dll home 截图保存到d:\dwm.jpg        |
| HookPatch.dll            | patchdll 注入可以看到flag                |
| flag.jpg                 | 利用室友电脑所截的图                     |
| Table.h                  | 生成并加密回去的opcode                   |

## Patch

### 方案一

> hook并调用坐标绘制

搜索 比赛驱动的hook 

然后我再hook

注入压缩包中的[HookPatch.dll]() 可以看到效果

```
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
```



```
flag f[42];
uint8_t* draw_rect = 0;
uint8_t* draw_orig = 0;
__int64 __fastcall sub_420(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, __int64 a7)
{
	f[0] = { 50 , 50, 0x130bd0 , 0xf814b4 };
	f[1] = { 50 , 122, 0x1bcd69 , 0xe9bdc5 };
	f[2] = { 50 , 194, 0xd91997 , 0x4f7363 };
	f[3] = { 50 , 266, 0xe82b18 , 0x28ec24 };
	f[4] = { 50 , 338, 0x391faa , 0x22ae2e };
	f[5] = { 50 , 410, 0xd77de2 , 0x2f62e };
	f[6] = { 122 , 266, 0x71150 , 0x1894d4 };
	f[7] = { 194 , 266, 0xc42e8b , 0xeb1f47 };
	f[8] = { 266 , 266, 0x34cf2b , 0x534f3f };
	f[9] = { 122 , 122, 0xd9e5f1 , 0xe9d505 };
	f[10] = { 194 , 194, 0xc42d8b , 0x38f0f };
	f[11] = { 770 , 50, 0xeabf17 , 0x8f7323 };
	f[12] = { 698 , 122, 0xc42d8b , 0x532fbf };
	f[13] = { 626 , 194, 0xd717af , 0x37cb9b };
	f[14] = { 554 , 266, 0xc460e9 , 0x314ddd };
	f[15] = { 482 , 338, 0xc7a989 , 0x11edbd };
	f[16] = { 554 , 338, 0xab7100 , 0xf0747c };
	f[17] = { 626 , 338, 0xc409a9 , 0xe12d6d };
	f[18] = { 842 , 50, 0xd77e8b , 0x7bfff7 };
	f[19] = { 914 , 50, 0xd9ad01 , 0x4985c5 };
	f[20] = { 986 , 50, 0x39e156 , 0xf6c25a };
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

```

### 方案二

通过虚拟机模拟,得到绘制坐标信息 

再通过std::vector<uint32_t> VM::OutVituralOpCodeTable(const std::vector<Opcode>& opcodes)

生成新的opcode

利用驱动loadimg 回调

patch 目标驱动

由于是通过[loadimg]()进行patch 所以PatchDriver.sys 需要在比赛驱动之前加载



加载[PatchDriver.sys]() 后加载比赛驱动在运行[2022游戏安全技术竞赛决赛.exe]() 可以看到flag

注入screenshot.dll 按home 即可截图 截图文件在 d:\dwm.jpg

```cpp
EE2362FC Reg[0],Reg[1] <- Draw(50,50,130bd0,f814b4)
EE2362FC Reg[0],Reg[1] <- Draw(50,122,1bcd69,e9bdc5)
EE2362FC Reg[0],Reg[1] <- Draw(50,194,d91997,4f7363)
EE2362FC Reg[0],Reg[1] <- Draw(50,266,e82b18,28ec24)
EE2362FC Reg[0],Reg[1] <- Draw(50,338,391faa,22ae2e)
EE2362FC Reg[0],Reg[1] <- Draw(50,410,d77de2,2f62e)
EE2362FC Reg[0],Reg[1] <- Draw(122,266,71150,1894d4)
EE2362FC Reg[0],Reg[1] <- Draw(194,266,c42e8b,eb1f47)
EE2362FC Reg[0],Reg[1] <- Draw(266,266,34cf2b,534f3f)
EE2362FC Reg[0],Reg[1] <- Draw(122,122,d9e5f1,e9d505)
EE2362FC Reg[0],Reg[1] <- Draw(194,194,c42d8b,38f0f)
EE2362FC Reg[0],Reg[1] <- Draw(770,50,eabf17,8f7323)
EE2362FC Reg[0],Reg[1] <- Draw(698,122,c42d8b,532fbf)
EE2362FC Reg[0],Reg[1] <- Draw(626,194,d717af,37cb9b)
EE2362FC Reg[0],Reg[1] <- Draw(554,266,c460e9,314ddd)
EE2362FC Reg[0],Reg[1] <- Draw(482,338,c7a989,11edbd)
EE2362FC Reg[0],Reg[1] <- Draw(554,338,ab7100,f0747c)
EE2362FC Reg[0],Reg[1] <- Draw(626,338,c409a9,e12d6d)
EE2362FC Reg[0],Reg[1] <- Draw(842,50,d77e8b,7bfff7)
EE2362FC Reg[0],Reg[1] <- Draw(914,50,d9ad01,4985c5)
EE2362FC Reg[0],Reg[1] <- Draw(986,50,39e156,f6c25a)
EE2362FC Reg[0],Reg[1] <- Draw(842,122,13207c,7438b8)
EE2362FC Reg[0],Reg[1] <- Draw(914,194,c9140b,f3af5f)
EE2362FC Reg[0],Reg[1] <- Draw(986,266,53071f,779bfb)
EE2362FC Reg[0],Reg[1] <- Draw(1058,338,d71106,5ee272)
EE2362FC Reg[0],Reg[1] <- Draw(1130,338,eb60a1,11551d)
EE2362FC Reg[0],Reg[1] <- Draw(1202,338,eb67cd,c5c9c9)
EE2362FC Reg[0],Reg[1] <- Draw(1274,338,d71161,1752d)
EE2362FC Reg[0],Reg[1] <- Draw(1130,50,677611,41a58d)
EE2362FC Reg[0],Reg[1] <- Draw(1202,50,40173d,95f9d9)
EE2362FC Reg[0],Reg[1] <- Draw(1274,50,d77661,61b54d)
EE2362FC Reg[0],Reg[1] <- Draw(1346,50,efff9a,c27eee)
EE2362FC Reg[0],Reg[1] <- Draw(1202,122,c404eb,eb3fc7)
EE2362FC Reg[0],Reg[1] <- Draw(1274,194,d7c6ef,df9b53)
EE2362FC Reg[0],Reg[1] <- Draw(1346,194,d7701f,171b1b)
EE2362FC Reg[0],Reg[1] <- Draw(1418,194,d71171,91e53d)
EE2362FC Reg[0],Reg[1] <- Draw(1490,194,3906ab,138f3f)
EE2362FC Reg[0],Reg[1] <- Draw(1346,266,96663,83f72f)
EE2362FC Reg[0],Reg[1] <- Draw(1418,338,732157,47638b)
EE2362FC Reg[0],Reg[1] <- Draw(1490,338,353730,587414)
EE2362FC Reg[0],Reg[1] <- Draw(1562,338,6257a9,69fdc5)
EE2362FC Reg[0],Reg[1] <- Draw(1634,338,d777af,b7cb1b)
```



```cpp
VOID LoadImageNotify(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	if (FullImageName != nullptr && MmIsAddressValid(FullImageName))
	{
		if (ProcessId == 0) // 是否是驱动
		{
			auto ImageName = FullImageName->Buffer;
			if (wcsstr(ImageName, L"2022GameSafeRace.sys"))
			{
				auto PatchFree = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x18a4;
				auto JmpAddress = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x19ea;
				char jmp[] = {
					0xe9,0x00,0x00,0x00,0x00
				};
				*(uint32_t*)(jmp + 1) = (ULONG64)(JmpAddress - PatchFree - 5);
				// patch free
				MdlCopyMemory(PatchFree, &jmp, sizeof(jmp));
				// patch vad断链
				PatchFree = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x1aae;
				JmpAddress = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x1ac9;
				*(uint32_t*)(jmp + 1) = (ULONG64)(JmpAddress - PatchFree - 5);

				MdlCopyMemory(PatchFree, &jmp, sizeof(jmp));

				MdlCopyMemory(PatchFree, &jmp, sizeof(jmp));
				//patch表
				PatchFree = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x4030;

				MdlCopyMemory(PatchFree, Table, sizeof(Table));



			}
		}
	}
}
```



## 驱动分析

### 通讯

#### 注册回调

```
NTSTATUS __fastcall sub_140001438(void *a1, BOOLEAN a2)
{
  SYSTEM_FIRMWARE_TABLE_HANDLER SystemInformation; // [rsp+20h] [rbp-28h] BYREF

  SystemInformation.DriverObject = a1;
  SystemInformation.Register = a2;
  SystemInformation.FirmwareTableHandler = (PFNFTH)sub_1400013E0;
  SystemInformation.ProviderSignature = 0x52414E44;
  return ZwSetSystemInformation(SystemRegisterFirmwareTableInformationHandler, &SystemInformation, 0x18ui64);
}
```

```
__int64 __fastcall sub_140003530(PVOID Parameter)
{
  HANDLE ProcessHeap; // rax
  char *v2; // rdx
  __int64 result; // rax
  ULONG ReturnLength; // [rsp+38h] [rbp+10h] BYREF

  ProcessHeap = GetProcessHeap();
  v2 = (char *)HeapAlloc(ProcessHeap, 8u, 0x28ui64);
  result = 0i64;
  *(_OWORD *)v2 = 0i64;
  *((_OWORD *)v2 + 1) = 0i64;
  *((_QWORD *)v2 + 4) = 0i64;
  if ( v2 )
  {
    *((_DWORD *)v2 + 2) = 0;
    *((_DWORD *)v2 + 1) = 1;
    *(_DWORD *)v2 = 1380011588;
    *((_DWORD *)v2 + 3) = 20;
    *(_QWORD *)(v2 + 20) = 8193i64;
    *((_QWORD *)v2 + 4) = D3DCompile;
    ReturnLength = 40;
    NtQuerySystemInformation(SystemFirmwareTableInformation, v2, 0x28u, &ReturnLength);
    return 0i64;
  }
  return result;
}
```



### 获取DWM PEPROCESS

> 循环遍历进程名有DWM的进程
>
> 起始Processid 为 0x100000
>
> 每次循环减4

```cpp
PEPROCESS GetDwmProcess()//0x140001318
{
  PEPROCESS v0; // rdi
  unsigned int ProcessId; // esi
  void *ProcessImageFileName; // rbx
  void *ProcessPeb; // rbx
  struct _KAPC_STATE ApcState; // [rsp+20h] [rbp-60h] BYREF
  int SubStr; // [rsp+A0h] [rbp+20h] BYREF
  PEPROCESS Process; // [rsp+A8h] [rbp+28h] BYREF

  v0 = 0i64;
  ProcessId = 0x100000;
  while ( 1 )
  {
    if ( PsLookupProcessByProcessId((HANDLE)ProcessId, &Process) < 0 )
      goto LABEL_7;
    ObfDereferenceObject(Process);
    ProcessImageFileName = (void *)PsGetProcessImageFileName(Process);
    if ( !MmIsAddressValid(ProcessImageFileName) )
      goto LABEL_7;
    SubStr = 'mwd';
    if ( !strstr((const char *)ProcessImageFileName, (const char *)&SubStr) )
      goto LABEL_7;
    ProcessPeb = (void *)PsGetProcessPeb(Process);
    KeStackAttachProcess(Process, &ApcState);
    if ( MmIsAddressValid(ProcessPeb) )
      break;
    KeUnstackDetachProcess(&ApcState);
LABEL_7:
    ProcessId -= 4;
    if ( ProcessId <= 8 )
      return v0;
  }
  v0 = Process;
  KeUnstackDetachProcess(&ApcState);
  return v0;
}
```

### 注入shellcode

> 大概流程,获取DWM **EPROCESS**
>
> 获取 D3DCompile 地址
>
> 搜索内存 获取 **CDXGISwapChain::PresentMultiplaneOverlay**
>
> 申请内存 复制**shellcode** 和 **VmOpcodeTable** 到DWM中 并解密
>
> HookMem = CDXGISwapChain::PresentMultiplaneOverlay 头部字节 加上
>
> ```
> 68 00006F99           - push 0000000000000000 { 0 }
> C7 44 24 04 00000000  - mov [rsp+04],00000000 { 0 }
> C3                    - ret 
> ```
>
> = 跳回 PresentMultiplaneOverlay
>
> hook **CDXGISwapChain::PresentMultiplaneOverlay** 跳到shellcode + 860
>
> v31 = PresentMultiplaneOverlay(v43, a2, v49, a4, v72, a5, v71);
>
> sub_860+D18 Address:0x1578 Offset:0x1578
>
> 这里执行 hookmem
>
> 延迟5秒恢复hook
>
> 延迟15秒释放内存

#### 获取模块

```cpp
ProcessId = PsGetProcessId(DwmProcess);
GetModuleHandle(ProcessId, &Handle, "D3DCOMPILER_47.dll");// 从Ldr链里获取模块地址
KeStackAttachProcess(Dwm, &ApcState);       // 附加DWM
if ( Handle )                               // 如果模块存在
    D3DCompile = GetProAddress((__int64)Handle, (__int64)"D3DCompile");// 获取函数D3DCompile地址
KeUnstackDetachProcess(&ApcState);          // 解除附加
Handle = 0i64;
v25 = 0i64;
GetModuleHandle(ProcessId, &Handle, "dxgi.dll");// 获取dxgi模块地址
```

#### 查找PresentMultiplaneOverlay

```cpp
 v5 = (char *)Handle;
    if ( Handle )
    {
      v6 = (char *)Handle;
      for ( i = Handle < (char *)Handle + v25; i; i = v6 < (char *)Handle + v25 )
      {
        if ( *(_QWORD *)v6 == qword_140004000 && *((_QWORD *)v6 + 1) == qword_140004008 && v6[0x10] == byte_140004010 )// 搜索特征码 PresentMultiplaneOverlay
        {
          PresentMultiplaneOverlay = v6;
          break;
        }
        ++v6;
      }
    }
    if ( unk_14000712C == 17134 && Handle )     // 如果为1803
    {
      v8 = (char *)Handle + v25;
      while ( v5 < v8 )
      {
        if ( !memcmp(v5, &unk_140004018, 0x15ui64) )// 搜索特征码
        {
          PresentMultiplaneOverlay = v5;
          break;
        }
        ++v5;
      }
    }
```

#### 申请内存 并 copy Shellcode

```cpp
  KeStackAttachProcess(Dwm, &ApcState);
      ZwAllocateVirtualMemory((HANDLE)0xFFFFFFFFFFFFFFFFi64, &BaseAddress, 0i64, &RegionSize, 0x1000u, 0x40u);// 申请shellcode 内存
      ZwAllocateVirtualMemory((HANDLE)0xFFFFFFFFFFFFFFFFi64, &HookMem, 0i64, &v23, 0x1000u, 0x40u);// hook内存?
      if ( BaseAddress && HookMem )
      {
        memcpy_s(BaseAddress, 0x30BAui64, dword_140005A00, 0x16E6ui64);// 复制shellcode 到申请的内存中
        v9 = 0;
        v10 = 0i64;
        do
        {
          ++v9;
          *((_BYTE *)BaseAddress + v10++) ^= 0xC3u;
        }
        while ( v9 < 0x16E6 );                  // 解密shellcode
        memcpy_s((char *)BaseAddress + 0x16E6, 0x19D4ui64, dword_140004030, 0x19C4ui64);// 复制VmOpcodeTable到申请的内存中
        v11 = 0;
        v12 = 0i64;
        do
        {
          ++v11;
          *((_BYTE *)BaseAddress + v12 + 0x16E6) ^= 0xCCu;// 解密 VmOpcodeTable
          ++v12;
        }
        while ( v11 < 0x19C4 );
        *(_QWORD *)((char *)BaseAddress + 0x30AA) = D3DCompile;
        *(_QWORD *)((char *)BaseAddress + 0x30B2) = HookMem;
        *(_DWORD *)((char *)BaseAddress + dword_1400059F4) = 0x30A6 - dword_1400059F4;
        *(_DWORD *)((char *)BaseAddress + dword_1400059F8) = 0x30AE - dword_1400059F8;
        *(_DWORD *)((char *)BaseAddress + dword_1400070EC) = 0x671;
        *(_DWORD *)((char *)BaseAddress + dword_1400070E8) = 0x16E2 - dword_1400070E8;
        memcpy_s(HookMem, 14ui64, &loc_1400070F8, 14ui64);// PresentMultiplaneOverlay 头部字节码
        v13 = (char *)HookMem;
        *(_DWORD *)((char *)HookMem + 15) = (_DWORD)PresentMultiplaneOverlay + 14;
        *(_DWORD *)(v13 + 0x17) = ((unsigned __int64)PresentMultiplaneOverlay + 14) >> 32;
        v13[14] = 0x68;
        *(_DWORD *)(v13 + 0x13) = 0x42444C7;
        v13[27] = 0xC3;
```



#### Hook **PresentMultiplaneOverlay**

> 利用MDL 强行写入shellcode 到**PresentMultiplaneOverlay**
>
> Hook shellcode 大概
>
> ```
> push 00000000 //push 低32位
> mov [rsp+04] //mov 高32位
> ret //jmp [rsp] pop
> ```

```cpp
KeUnstackDetachProcess(&ApcState);
KeStackAttachProcess(Dwm, &ApcState);
if ( BaseAddress && HookMem )
{
    if ( MmIsAddressValid(PresentMultiplaneOverlay) )
    {
        Mdl = IoAllocateMdl(PresentMultiplaneOverlay, 0x100u, 0, 0, 0i64);
        MmProbeAndLockPages(Mdl, 1, IoReadAccess);
        v15 = (char *)MmMapLockedPagesSpecifyCache(Mdl, 0, MmNonCached, 0i64, 0, 0x10u);// hook
        if ( v15 )
        {   // 68 00000000           - push 00000000 { 0 }
            // C7 44 24 04 00000000  - mov [rsp+04],00000000 { 0 }
            // C3                    - ret 
            // shellcode
            v16 = (char *)BaseAddress + dword_1400070F0;// sub_860,各种初始化
            *(_DWORD *)(v15 + 1) = (_DWORD)v16;
            *(_DWORD *)(v15 + 9) = HIDWORD(v16);// 往里面写数据
            *v15 = 0x68;                        // push shellcode sub_860
            *(_DWORD *)(v15 + 5) = 69485767;    // mov [rsp+04],00000000
            v15[13] = 0xC3;                     // ret
        }
        MmUnmapLockedPages(v15, Mdl);
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
    }
```

#### VAD断链?

> 直接patch吧 一看就知道啥东西
>
> 没仔细看导致我minhook失败调我半天

```
v27[0] = (__int64)BaseAddress;
v29 = 0;
v27[1] = 0x30BAi64;
v28 = (unsigned int)PsGetProcessId(Dwm);
sub_140001A84((__int64)v27);
```

#### 延迟5秒 并恢复hook

> 延迟5秒恢复PresentMultiplaneOverlay 的hook
>
> loc_1400070F8 里是PresentMultiplaneOverlay头部字节

```cpp
Interval.QuadPart = -50000000i64;
KeDelayExecutionThread(0, 0, &Interval);  // 恢复hook
KeStackAttachProcess(Dwm, &ApcState);
if ( BaseAddress )
{
    if ( HookMem )
    {
        sub_140001B30();
        if ( MmIsAddressValid(PresentMultiplaneOverlay) )
        {
            v17 = IoAllocateMdl(PresentMultiplaneOverlay, 0x100u, 0, 0, 0i64);
            MmProbeAndLockPages(v17, 1, IoReadAccess);
            v18 = MmMapLockedPagesSpecifyCache(v17, 0, MmNonCached, 0i64, 0, 0x10u);// mdl强写
            if ( v18 )
            {                                   // 
                // 48 8B C4              - mov rax,rsp
                // 55                    - push rbp
                // 56                    - push rsi
                // 57                    - push rdi
                // 41 54                 - push r12
                // 41 55                 - push r13
                // 41 56                 - push r14
                // 41 57                 - push r15
                *(_QWORD *)v18 = loc_1400070F8;
                v18[2] = loc_140007100;
                *((_WORD *)v18 + 6) = loc_140007104;
            }
            MmUnmapLockedPages(v18, v17);
            MmUnlockPages(v17);
            IoFreeMdl(v17);
        }
    }
}
KeUnstackDetachProcess(&ApcState);
```

#### 延迟15秒释放shellcode

> 不用解释

```cpp
KeUnstackDetachProcess(&ApcState);
Interval.QuadPart = -15000000i64;         // 释放shellcode
KeDelayExecutionThread(0, 0, &Interval);
KeStackAttachProcess(Dwm, &ApcState);
if ( BaseAddress )
{
    if ( HookMem )
    {
        ZwFreeVirtualMemory((HANDLE)0xFFFFFFFFFFFFFFFFi64, &BaseAddress, &RegionSize, 0x4000u);// 释放shellcode
        ZwFreeVirtualMemory((HANDLE)0xFFFFFFFFFFFFFFFFi64, &HookMem, &v23, 0x4000u);
    }
}
KeUnstackDetachProcess(&ApcState);
```





​			

#### 完整分析

```cpp
void inject_shellcode()
{
  __int64 D3DCompile; // r15
  void *PresentMultiplaneOverlay; // rsi
  struct _KPROCESS *DwmProcess; // rax
  struct _KPROCESS *Dwm; // rdi
  HANDLE ProcessId; // rbx
  char *v5; // rbx
  char *v6; // rcx
  bool i; // cf
  char *v8; // r14
  unsigned int v9; // edx
  __int64 v10; // rcx
  unsigned int v11; // edx
  __int64 v12; // rcx
  char *v13; // rax
  struct _MDL *Mdl; // rbx
  char *v15; // rax
  char *v16; // rdx
  struct _MDL *v17; // rbx
  _DWORD *v18; // rax
  PVOID BaseAddress; // [rsp+38h] [rbp-49h] BYREF
  PVOID HookMem; // [rsp+40h] [rbp-41h] BYREF
  union _LARGE_INTEGER Interval; // [rsp+48h] [rbp-39h] BYREF
  ULONG_PTR RegionSize; // [rsp+50h] [rbp-31h] BYREF
  ULONG_PTR v23; // [rsp+58h] [rbp-29h] BYREF
  void *Handle; // [rsp+60h] [rbp-21h] BYREF
  __int64 v25; // [rsp+68h] [rbp-19h]
  struct _KAPC_STATE ApcState; // [rsp+70h] [rbp-11h] BYREF
  __int64 v27[2]; // [rsp+A0h] [rbp+1Fh] BYREF
  unsigned int v28; // [rsp+B0h] [rbp+2Fh]
  int v29; // [rsp+B4h] [rbp+33h]

  v23 = 0x1000i64;
  D3DCompile = 0i64;
  BaseAddress = 0i64;
  PresentMultiplaneOverlay = 0i64;
  HookMem = 0i64;
  RegionSize = 0x30BAi64;
  DwmProcess = GetDwmProcess();
  Dwm = DwmProcess;
  if ( DwmProcess )
  {
    Handle = 0i64;
    v25 = 0i64;
    ProcessId = PsGetProcessId(DwmProcess);
    GetModuleHandle(ProcessId, &Handle, "D3DCOMPILER_47.dll");// 从Ldr链里获取模块地址
    KeStackAttachProcess(Dwm, &ApcState);       // 附加DWM
    if ( Handle )                               // 如果模块存在
      D3DCompile = GetProAddress((__int64)Handle, (__int64)"D3DCompile");// 获取函数D3DCompile地址
    KeUnstackDetachProcess(&ApcState);          // 解除附加
    Handle = 0i64;
    v25 = 0i64;
    GetModuleHandle(ProcessId, &Handle, "dxgi.dll");// 获取dxgi模块地址
    KeStackAttachProcess(Dwm, &ApcState);
    v5 = (char *)Handle;
    if ( Handle )
    {
      v6 = (char *)Handle;
      for ( i = Handle < (char *)Handle + v25; i; i = v6 < (char *)Handle + v25 )
      {
        if ( *(_QWORD *)v6 == qword_140004000 && *((_QWORD *)v6 + 1) == qword_140004008 && v6[0x10] == byte_140004010 )// 搜索特征码 PresentMultiplaneOverlay
        {
          PresentMultiplaneOverlay = v6;
          break;
        }
        ++v6;
      }
    }
    if ( VersionInformation.dwBuildNumber == 17134 && Handle )// 如果为1803
    {
      v8 = (char *)Handle + v25;
      while ( v5 < v8 )
      {
        if ( !memcmp(v5, &unk_140004018, 0x15ui64) )// 搜索特征码
        {
          PresentMultiplaneOverlay = v5;
          break;
        }
        ++v5;
      }
    }
    KeUnstackDetachProcess(&ApcState);
    if ( D3DCompile && PresentMultiplaneOverlay )// 老方案 只不过放驱动里了
    {
      KeStackAttachProcess(Dwm, &ApcState);
      ZwAllocateVirtualMemory((HANDLE)0xFFFFFFFFFFFFFFFFi64, &BaseAddress, 0i64, &RegionSize, 0x1000u, 0x40u);// 申请shellcode 内存
      ZwAllocateVirtualMemory((HANDLE)0xFFFFFFFFFFFFFFFFi64, &HookMem, 0i64, &v23, 0x1000u, 0x40u);// hook内存?
      if ( BaseAddress && HookMem )
      {
        memcpy_s(BaseAddress, 0x30BAui64, &unk_140005A00, 0x16E6ui64);// 复制shellcode 到申请的内存中
        v9 = 0;
        v10 = 0i64;
        do
        {
          ++v9;
          *((_BYTE *)BaseAddress + v10++) ^= 0xC3u;
        }
        while ( v9 < 0x16E6 );                  // 解密shellcode
        memcpy_s((char *)BaseAddress + 0x16E6, 0x19D4ui64, dword_140004030, 0x19C4ui64);// 复制VmOpcodeTable到申请的内存中
        v11 = 0;
        v12 = 0i64;
        do
        {
          ++v11;
          *((_BYTE *)BaseAddress + v12 + 5862) ^= 0xCCu;// 解密 VmOpcodeTable
          ++v12;
        }
        while ( v11 < 0x19C4 );
        *(_QWORD *)((char *)BaseAddress + 0x30AA) = D3DCompile;
        *(_QWORD *)((char *)BaseAddress + 0x30B2) = HookMem;
        *(_DWORD *)((char *)BaseAddress + dword_1400059F4) = 0x30A6 - dword_1400059F4;
        *(_DWORD *)((char *)BaseAddress + dword_1400059F8) = 0x30AE - dword_1400059F8;
        *(_DWORD *)((char *)BaseAddress + dword_1400070EC) = 0x671;
        *(_DWORD *)((char *)BaseAddress + dword_1400070E8) = 0x16E2 - dword_1400070E8;
        memcpy_s(HookMem, 14ui64, &qword_1400070F8, 14ui64);// PresentMultiplaneOverlay 头部字节码
        v13 = (char *)HookMem;
        *(_DWORD *)((char *)HookMem + 15) = (_DWORD)PresentMultiplaneOverlay + 14;
        *(_DWORD *)(v13 + 0x17) = ((unsigned __int64)PresentMultiplaneOverlay + 14) >> 32;
        v13[14] = 0x68;
        *(_DWORD *)(v13 + 0x13) = 0x42444C7;
        v13[27] = 0xC3;
      }
      KeUnstackDetachProcess(&ApcState);
      KeStackAttachProcess(Dwm, &ApcState);
      if ( BaseAddress && HookMem )
      {
        if ( MmIsAddressValid(PresentMultiplaneOverlay) )
        {
          Mdl = IoAllocateMdl(PresentMultiplaneOverlay, 0x100u, 0, 0, 0i64);
          MmProbeAndLockPages(Mdl, 1, IoReadAccess);
          v15 = (char *)MmMapLockedPagesSpecifyCache(Mdl, 0, MmNonCached, 0i64, 0, 0x10u);// hook
          if ( v15 )
          {                                     // 68 00000000           - push 00000000 { 0 }
                                                // C7 44 24 04 00000000  - mov [rsp+04],00000000 { 0 }
                                                // C3                    - ret 
                                                // shellcode
            v16 = (char *)BaseAddress + dword_1400070F0;// sub_860,各种初始化
            *(_DWORD *)(v15 + 1) = (_DWORD)v16;
            *(_DWORD *)(v15 + 9) = HIDWORD(v16);// 往里面写数据
            *v15 = 0x68;                        // push shellcode sub_860
            *(_DWORD *)(v15 + 5) = 69485767;    // mov [rsp+04],00000000
            v15[13] = 0xC3;                     // ret
          }
          MmUnmapLockedPages(v15, Mdl);
          MmUnlockPages(Mdl);
          IoFreeMdl(Mdl);
        }
        v27[0] = (__int64)BaseAddress;
        v29 = 0;
        v27[1] = 0x30BAi64;
        v28 = (unsigned int)PsGetProcessId(Dwm);
        sub_140001A84((__int64)v27);
      }
      KeUnstackDetachProcess(&ApcState);
      Interval.QuadPart = -50000000i64;
      KeDelayExecutionThread(0, 0, &Interval);  // 恢复hook
      KeStackAttachProcess(Dwm, &ApcState);
      if ( BaseAddress )
      {
        if ( HookMem )
        {
          sub_140001B30();
          if ( MmIsAddressValid(PresentMultiplaneOverlay) )
          {
            v17 = IoAllocateMdl(PresentMultiplaneOverlay, 0x100u, 0, 0, 0i64);
            MmProbeAndLockPages(v17, 1, IoReadAccess);
            v18 = MmMapLockedPagesSpecifyCache(v17, 0, MmNonCached, 0i64, 0, 0x10u);// mdl强写
            if ( v18 )
            {                                   // 
                                                // 48 8B C4              - mov rax,rsp
                                                // 55                    - push rbp
                                                // 56                    - push rsi
                                                // 57                    - push rdi
                                                // 41 54                 - push r12
                                                // 41 55                 - push r13
                                                // 41 56                 - push r14
                                                // 41 57                 - push r15
              *(_QWORD *)v18 = qword_1400070F8;
              v18[2] = dword_140007100;
              *((_WORD *)v18 + 6) = word_140007104;
            }
            MmUnmapLockedPages(v18, v17);
            MmUnlockPages(v17);
            IoFreeMdl(v17);
          }
        }
      }
      KeUnstackDetachProcess(&ApcState);
      Interval.QuadPart = -15000000i64;         // 释放shellcode
      KeDelayExecutionThread(0, 0, &Interval);
      KeStackAttachProcess(Dwm, &ApcState);
      if ( BaseAddress )
      {
        if ( HookMem )
        {
          ZwFreeVirtualMemory((HANDLE)0xFFFFFFFFFFFFFFFFi64, &BaseAddress, &RegionSize, 0x4000u);// 释放shellcode
          ZwFreeVirtualMemory((HANDLE)0xFFFFFFFFFFFFFFFFi64, &HookMem, &v23, 0x4000u);
        }
      }
      KeUnstackDetachProcess(&ApcState);
    }
  }
}
```

### Patch Free

> 大概流程
>
> 注册loadimg回调
>
> 比赛sys加载 触发回调
>
> ![image-20220423202130093](决赛 writeup.assets\image-20220423202130093.png)
>
> 然后jmp 到
>
> ```
> loc_1400019EA:                ; CODE XREF: sub_1400014A0+5D↑j
> .text:00000001400019EA                                                             ; sub_1400014A0+173↑j
> .text:00000001400019EA                                                             ; sub_1400014A0+17C↑j
> .text:00000001400019EA 48 8B 4D 37                   mov     rcx, [rbp+57h+var_20]
> .text:00000001400019EE 48 33 CC                      xor     rcx, rsp              ; StackCookie
> .text:00000001400019F1 E8 EA 01 00 00                call    __security_check_cookie
> .text:00000001400019F1
> .text:00000001400019F6 4C 8D 9C 24 C0 00 00 00       lea     r11, [rsp+0D0h+var_10]
> .text:00000001400019FE 49 8B 5B 20                   mov     rbx, [r11+20h]
> .text:0000000140001A02 49 8B 73 28                   mov     rsi, [r11+28h]
> .text:0000000140001A06 49 8B 7B 30                   mov     rdi, [r11+30h]
> .text:0000000140001A0A 4D 8B 63 38                   mov     r12, [r11+38h]
> .text:0000000140001A0E 49 8B E3                      mov     rsp, r11
> .text:0000000140001A11 41 5F                         pop     r15
> .text:0000000140001A13 41 5E                         pop     r14
> .text:0000000140001A15 5D                            pop     rbp
> .text:0000000140001A16 C3                            retn
> ```
>
> 
>
> 

#### Mdl强写

```cpp
void MdlCopyMemory(PVOID address,PVOID buffer,size_t size)
{
	__try
	{
		if (MmIsAddressValid((PVOID)address))
		{
			auto pMdl = IoAllocateMdl(address, size, FALSE, FALSE, nullptr);
			if (pMdl)
			{
				MmBuildMdlForNonPagedPool(pMdl);

				auto lock = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

				if (lock)
				{
					RtlCopyMemory(lock, buffer, size);
					MmUnmapLockedPages(lock, pMdl);
				}
				ExFreePool(pMdl);

			}
		}
	}
	__except (1)
	{

	}

}
```

#### Lodimg



```cpp
VOID LoadImageNotify(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	if (FullImageName != nullptr && MmIsAddressValid(FullImageName))
	{
		if (ProcessId == 0) // 是否是驱动
		{
			auto ImageName = FullImageName->Buffer;
			if (wcsstr(ImageName, L"2022GameSafeRace.sys"))
			{
				auto PatchFree = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x18a4;
				auto JmpAddress = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x19ea;
				char jmp[] = {
					0xe9,0x00,0x00,0x00,0x00
				};
				*(uint32_t*)(jmp + 1) = (ULONG64)(JmpAddress - PatchFree + 5);

				MdlCopyMemory(PatchFree, &jmp, sizeof(jmp));
			}
		}
	}
}

```



#### 完整代码

```cpp
#include <ntifs.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <cstdint>
#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
void MdlCopyMemory(PVOID address,PVOID buffer,size_t size)
{
	__try
	{
		if (MmIsAddressValid((PVOID)address))
		{
			auto pMdl = IoAllocateMdl(address, size, FALSE, FALSE, nullptr);
			if (pMdl)
			{
				MmBuildMdlForNonPagedPool(pMdl);

				auto lock = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

				if (lock)
				{
					RtlCopyMemory(lock, buffer, size);
					MmUnmapLockedPages(lock, pMdl);
				}
				ExFreePool(pMdl);

			}
		}
	}
	__except (1)
	{

	}

}
VOID LoadImageNotify(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	if (FullImageName != nullptr && MmIsAddressValid(FullImageName))
	{
		if (ProcessId == 0) // 是否是驱动
		{
			auto ImageName = FullImageName->Buffer;
			if (wcsstr(ImageName, L"2022GameSafeRace.sys"))
			{
				auto PatchFree = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x18a4;
				auto JmpAddress = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x19ea;
				char jmp[] = {
					0xe9,0x00,0x00,0x00,0x00
				};
				*(uint32_t*)(jmp + 1) = (ULONG64)(JmpAddress - PatchFree + 5);

				MdlCopyMemory(PatchFree, &jmp, sizeof(jmp));
			}
		}
	}
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	PsRemoveLoadImageNotifyRoutine(LoadImageNotify);
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	pDriverObj->DriverUnload = DriverUnload;
	auto status = PsSetLoadImageNotifyRoutine(LoadImageNotify);
	return status;
}
```

## Exe分析

> WinMain下段跟

```
CreateThread(0i64, 0i64, (LPTHREAD_START_ROUTINE)sub_140003530, 0i64, 0, &ThreadId);
```

>  发现这段参加线程
>
> 点进去一看
>
> 发现NtQuerySystemInformation
>
> 明显是通过 NtQuerySystemInformation触发回调

```
__int64 __fastcall sub_140003530(PVOID Parameter)
{
  HANDLE ProcessHeap; // rax
  char *v2; // rdx
  __int64 result; // rax
  ULONG ReturnLength; // [rsp+38h] [rbp+10h] BYREF

  ProcessHeap = GetProcessHeap();
  v2 = (char *)HeapAlloc(ProcessHeap, 8u, 0x28ui64);
  result = 0i64;
  *(_OWORD *)v2 = 0i64;
  *((_OWORD *)v2 + 1) = 0i64;
  *((_QWORD *)v2 + 4) = 0i64;
  if ( v2 )
  {
    *((_DWORD *)v2 + 2) = 0;
    *((_DWORD *)v2 + 1) = 1;
    *(_DWORD *)v2 = 1380011588;
    *((_DWORD *)v2 + 3) = 20;
    *(_QWORD *)(v2 + 20) = 8193i64;
    *((_QWORD *)v2 + 4) = D3DCompile;
    ReturnLength = 40;
    NtQuerySystemInformation(SystemFirmwareTableInformation, v2, 0x28u, &ReturnLength);
    return 0i64;
  }
  return result;
}
```



## shellcode 分析

> dump下shellcode 分析
>
> 卧槽? 这不是咱老朋友吗
>
> 不过虚拟机进化了

### DrawRect

```
__int64 __fastcall DrawRect(
        int a1,
        int a2,
        int a3,
        int a4,
        float a5,
        __int64 a6,
        __int64 a7,
        __int64 a8,
        __int64 a9,
        __int64 a10)
{
  __int64 v14; // r14
  unsigned int v15; // ebx
  int v16; // ecx
  float v17; // xmm9_4
  float v18; // xmm11_4
  float v19; // xmm7_4
  float v20; // xmm10_4
  float *v21; // rcx
  float v22; // xmm0_4
  float v23; // xmm8_4
  float v24; // xmm6_4
  float v25; // xmm3_4
  float v26; // xmm1_4
  float v27; // xmm8_4
  float v28; // xmm7_4
  float v29; // xmm5_4
  float v30; // xmm4_4
  float v31; // xmm2_4
  __int64 v32; // rax
  float *v34; // [rsp+30h] [rbp-C8h] BYREF
  char v35[8]; // [rsp+40h] [rbp-B8h] BYREF
  float v36; // [rsp+48h] [rbp-B0h]
  float v37; // [rsp+4Ch] [rbp-ACh]
  int v38; // [rsp+108h] [rbp+10h] BYREF
  int v39; // [rsp+110h] [rbp+18h] BYREF
  int v40; // [rsp+118h] [rbp+20h] BYREF

  v14 = a6;
  v38 = 1;
  v15 = LODWORD(a5) + (a3 ^ (a1 + a2)) % 256 - a4 % 256;
  (*(void (__fastcall **)(__int64, int *, char *))(*(_QWORD *)a6 + 760i64))(a6, &v38, v35);
  v16 = (a3 ^ (a2 * a1)) % 256 - (a4 >> 8) % 256;
  v17 = (float)(v37 - (float)(2 * (v16 + a2) - 1)) / v37;
  v18 = (float)(v37 - (float)(2 * a2 + 99)) / v37;
  v19 = (float)((float)(2 * (v16 + a1) - 1) - v36) / v36;
  v20 = (float)((float)(2 * a1 + 99) - v36) / v36;
  (*(void (__fastcall **)(__int64, __int64, _QWORD, __int64, _DWORD, float **))(*(_QWORD *)v14 + 112i64))(
    v14,
    a7,
    0i64,
    4i64,
    0,
    &v34);
  v21 = v34;
  a5 = 255.0;
  v34[2] = (float)0;
  v22 = a5;
  v23 = (float)((a3 ^ (a2 + a1 * (a2 + 1))) % 256 - (a4 >> 16) % 256);
  v24 = v23 + v19;
  v25 = v23 + v17;
  *v21 = v23 + v19;
  v26 = v23 + v20;
  v21[1] = v23 + v17;
  v27 = v23 + v18;
  v28 = (float)BYTE2(v15) / v22;
  v29 = (float)(unsigned __int8)(v15 >> 12) / v22;
  v30 = (float)(unsigned __int8)v15 / v22;
  v21[3] = v28;
  v21[4] = v29;
  v31 = (float)HIBYTE(v15) / v22;
  v21[6] = v31;
  v21[9] = (float)0;
  v21[13] = v31;
  v21[16] = (float)0;
  v21[20] = v31;
  v21[27] = v31;
  v21[5] = v30;
  v21[7] = v26;
  v21[8] = v25;
  v21[10] = v28;
  v21[11] = v29;
  v21[12] = v30;
  v21[14] = v24;
  v21[15] = v27;
  v21[17] = v28;
  v21[18] = v29;
  v21[19] = v30;
  v21[21] = v26;
  v21[22] = v27;
  v21[24] = v28;
  v21[25] = v29;
  v21[26] = v30;
  v21[23] = (float)0;
  (*(void (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)v14 + 120i64))(v14, a7, 0i64);
  v32 = *(_QWORD *)v14;
  v40 = 28;
  v39 = 0;
  (*(void (__fastcall **)(__int64, _QWORD, __int64, __int64 *, int *, int *))(v32 + 144))(
    v14,
    0i64,
    1i64,
    &a7,
    &v40,
    &v39);
  (*(void (__fastcall **)(__int64, __int64))(*(_QWORD *)v14 + 192i64))(v14, 5i64);
  (*(void (__fastcall **)(__int64, __int64))(*(_QWORD *)v14 + 136i64))(v14, a8);
  (*(void (__fastcall **)(__int64, __int64, _QWORD, _QWORD))(*(_QWORD *)v14 + 88i64))(v14, a9, 0i64, 0i64);
  (*(void (__fastcall **)(__int64, __int64, _QWORD, _QWORD))(*(_QWORD *)v14 + 72i64))(v14, a10, 0i64, 0i64);
  (*(void (__fastcall **)(__int64, _QWORD, _QWORD, _QWORD))(*(_QWORD *)v14 + 184i64))(v14, 0i64, 0i64, 0i64);
  return (*(__int64 (__fastcall **)(__int64, __int64))(*(_QWORD *)v14 + 104i64))(v14, 4i64);
}
```

### 加强版虚拟机

```cpp
__int64 __fastcall sub_420(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, __int64 a7)
{
  unsigned __int64 idx; // rsi
  unsigned __int64 vidx; // r8
  signed int branch; // ecx
  unsigned __int64 v12; // rdx
  __int64 v13; // rcx
  unsigned int v14; // r9d
  __int64 v15; // r8
  __int64 v16; // r9
  unsigned int v17; // edx
  unsigned __int64 v18; // r10
  unsigned __int64 v19; // rcx
  unsigned int v20; // r9d
  int v21; // r9d
  int v22; // eax
  __int64 result; // rax
  int reg[10]; // [rsp+60h] [rbp-21h] BYREF

  idx = 0i64;
  memset(reg, 0, 32);
  reg[8] = 50;
  reg[9] = 50;
  do
  {
    vidx = idx;
    branch = opcode[idx];
    if ( branch > (int)0x9A8ECD52 )
    {
      switch ( branch )
      {
        case 0xEE2362FC:
          ++idx;
          v21 = reg[0];
          v22 = reg[0] * (reg[1] + 1);
          reg[0] = opcode[idx] ^ 0x414345;
          reg[1] = (reg[0] ^ (reg[1] + v21)) % 256
                 + (((reg[0] ^ (v21 * reg[1])) % 256 + (((reg[0] ^ (reg[1] + v22)) % 256) << 8)) << 8);
          break;
        case 0xEE69524A:
          v19 = 0i64;
          v20 = opcode[vidx + 1];
          opcode[idx] = -1;
          opcode[vidx + 1] = -1;
          if ( idx != 1 )
          {
            do
              opcode[v19++] ^= v20;
            while ( v19 < idx - 1 );
          }
          ++idx;
          break;
        case 0xFF4578AE:
          idx += 2i64;
          v16 = (int)opcode[vidx + 1];
          v17 = opcode[idx];
          if ( (_DWORD)v16 )
          {
            v18 = idx;
            do
            {
              opcode[++v18] ^= v17;
              v17 = opcode[v18 - 1] + 0x12345678 * v17;
              --v16;
            }
            while ( v16 );
          }
          opcode[vidx] = -1;
          opcode[vidx + 1] = -1;
          opcode[idx] = -1;
          break;
        case 0x1132EADF:
          idx += 2i64;
          reg[opcode[idx]] = opcode[vidx + 1];
          break;
        default:
          if ( branch == 0x7852AAEF && opcode[0] == 0xEE69624A && opcode[1] == 0x689EDC0A && opcode[2] == 0x98EFDBC9 )
            sub_0(reg[4], reg[5], reg[6], reg[7], 0xFF2DDBE7, a3, a4, a5, a6, a7);
          break;
      }
    }
    else
    {
      switch ( branch )
      {
        case 0x9A8ECD52:
          reg[0] -= reg[1];
          break;
        case 0x88659264:
          idx += 2i64;
          v12 = idx;
          v13 = (int)opcode[vidx + 1];
          v14 = opcode[idx];
          opcode[vidx] = -1;
          opcode[vidx + 1] = -1;
          v15 = v13;
          opcode[idx] = -1;
          if ( (_DWORD)v13 )
          {
            do
            {
              opcode[++v12] ^= v14;
              --v15;
            }
            while ( v15 );
          }
          break;
        case 0x89657EAD:
          reg[0] += reg[1];
          break;
        case 0x8E7CADF2:
          idx += 2i64;
          reg[opcode[idx]] = reg[opcode[vidx + 1]];
          break;
        case 0x9645AAED:
          if ( opcode[0] == 0xEE69624A && opcode[1] == 0x689EDC0A && opcode[2] == 0x98EFDBC9 )
            sub_0(reg[4], reg[5], reg[6], reg[7], 0xFFFFFF00, a3, a4, a5, a6, a7);
          break;
        case 0x9645AEDC:
          idx = 0x671i64;
          break;
      }
    }
    result = 0x671i64;
    ++idx;
  }
  while ( idx < 0x671 );
  return result;
}
```



### 虚拟机分析

虚拟机经过六次解密达到最终结果

```
====ExecVirtual[0]====
Reg[8] = 50
Reg[9] = 50
-> Xor 1
-> VMEnd
====ExecVirtual[1]====
Reg[8] = 50
Reg[9] = 50
-> Xor 1
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],3301906)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 360
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7631989)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 432
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],2299116)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 504
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9843946)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> VMEnd
====ExecVirtual[2]====
Reg[8] = 50
Reg[9] = 50
-> Xor 1
Reg[0] = Reg[8]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],3301906)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 360
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7631989)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 432
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],2299116)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 504
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9843946)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> VMEnd
====ExecVirtual[3]====
Reg[8] = 50
Reg[9] = 50
-> Xor 1
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7882222)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],4728102)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],3301906)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 360
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7631989)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 432
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],2299116)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 504
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9843946)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> VMEnd
====ExecVirtual[4]====
Reg[8] = 50
Reg[9] = 50
-> Xor 1
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9843546)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9851444)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 360
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7882222)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],4728102)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],3301906)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 360
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7631989)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 432
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],2299116)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
Reg[0] = Reg[8]
Reg[1] = 504
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9843946)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> VMEnd
====ExecVirtual[5]====
Reg[8] = 50
Reg[9] = 50
-> Xor 1
Reg[0] = Reg[8]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9844004)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],11451615)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],8734638)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9864618)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9843546)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9851444)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 360
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7882222)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],4728102)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],3301906)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 360
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7631989)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 432
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],2299116)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 504
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9843946)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

-> VMEnd
====ExecVirtual[6]====
Reg[8] = 50
Reg[9] = 50
-> Xor 3
-> Xor 2
Reg[0] = Reg[8]
Reg[4] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = 1000
Reg[0] -= Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],5392533)
Reg[3] = Reg[0]
Reg[0] = Reg[1]
Reg[1] = Reg[3]
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[5]
Reg[1] = 500
Reg[0] -= Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],5934636)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[4] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = 1000
Reg[0] -= Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9984722)
Reg[3] = Reg[0]
Reg[0] = Reg[1]
Reg[1] = Reg[3]
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

-> Xor 3
Reg[0] = Reg[8]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],11102301)
Reg[3] = Reg[0]
Reg[0] = Reg[3]
Reg[1] = Reg[3]
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[4] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = 1000
Reg[0] -= Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
-> Xor 2
Reg[5] = Reg[0]
Reg[0] = Reg[5]
Reg[1] = 500
Reg[0] -= Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7888111)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 360
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9846439)
Reg[3] = Reg[0]
Reg[0] = Reg[1]
Reg[1] = Reg[3]
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = 1000
Reg[0] -= Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[5]
Reg[1] = 500
Reg[0] -= Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],4608533)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 216
Reg[0] += Reg[1]
-> Xor 3
Reg[5] = Reg[0]
Reg[0] = Reg[5]
Reg[1] = 500
Reg[0] -= Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],8744398)
Reg[3] = Reg[0]
Reg[0] = Reg[1]
Reg[1] = Reg[3]
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = 1000
Reg[0] -= Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7703662)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[5]
Reg[1] = 500
Reg[0] -= Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
-> Xor 3
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],10004148)
Reg[3] = Reg[0]
Reg[#] = Reg[1]
Reg[1] = Reg[3]
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = 1000
Reg[0] -= Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],8744654)
Reg[3] = Reg[0]
Reg[0] = Reg[1]
Reg[1] = Reg[3]
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 720
Reg[0] += Reg[1]
Reg[8] = Reg[0]
-> Xor 2
Reg[0] = Reg[8]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],11271250)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 72
Reg[0] -= Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],8744654)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 144
Reg[0] -= Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
-> Xor 3
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9852138)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] -= Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],8725420)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 288
Reg[0] -= Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],8841932)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] -= Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],15348293)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 144
Reg[0] -= Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],8735468)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9846222)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],10022468)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7905811)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],5399353)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],8935246)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],1197146)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9851459)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 360
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],11150308)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 432
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],11150472)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 504
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9851428)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 360
Reg[0] += Reg[1]
Reg[8] = Reg[0]
Reg[0] = Reg[8]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],2504020)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],87160)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9844004)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],11451615)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 72
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],8734638)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9864618)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9843546)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9851444)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 360
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 144
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7882222)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 216
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],4728102)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],3301906)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 360
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],7631989)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 432
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],2299116)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

Reg[0] = Reg[8]
Reg[1] = 504
Reg[0] += Reg[1]
Reg[4] = Reg[0]
Reg[0] = Reg[9]
Reg[1] = 288
Reg[0] += Reg[1]
Reg[5] = Reg[0]
Reg[0] = Reg[4]
Reg[1] = Reg[5]
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],9843946)
Reg[6] = Reg[0]
Reg[7] = Reg[1]
-> Draw(Reg[4],Reg[5],Reg[6],Reg[7],0xFF2DDBE7)

-> VMEnd
```

还是老样子

```
Reg[1] = 1000
Reg[0] -= Reg[1]
```

这里1000,500导致的坐标负数

```
Reg[0],Reg[1] <- Decrypt(Reg[0],Reg[1],5392533)
Reg[3] = Reg[0]
Reg[0] = Reg[1]
Reg[1] = Reg[3]
Reg[6] = Reg[0]
Reg[7] = Reg[1]
```

这里导致的交换reg[5] reg[6]



### 生成新表

patch 500 1000导致的负数,

patch 交换 reg[5] reg[6]

```cpp
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
```

通过模拟执行得到rect信息 利用这些信息生成新的opcode

```cpp
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
```





## 截图

### 方案1

在我的dll直接实现,刚好比赛驱动用比赛驱动的hook

[ScreenGrab · microsoft/DirectXTK Wiki (github.com)](https://github.com/microsoft/DirectXTK/wiki/ScreenGrab)

```
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
```

从交换链里获取Device

再GetBuffer

再调用 dxtk SaveWICTextureToFile 保存到文件





### 方案2

[lainswork/dwm-screen-shot: 将shellcode注入dwm.exe以进行屏幕截取 (github.com)](https://github.com/lainswork/dwm-screen-shot)

[lainswork/shellcode-factory: shellcode 生成框架 (github.com)](https://github.com/lainswork/shellcode-factory)

利用shellcode 生成框架

通过符号获取hook地址

修改页面属性

veh 捕获异常 hook 获取交换链

利用交换链 getbuffer

exe 直接读这个buff 绘制出来

其实和我的方案一一毛一样 除了是shellcode

### 方案3

[Abusing DComposition to render on external windows | secret club](https://secret.club/2020/05/12/abusing-compositions.html)

劫持dwm窗口应该是个思路吧

劫持线程到自己exe

应该可以截图到吧

没具体实现

### 方案4

NVidia 游戏内覆盖截图

他那个基于显卡 直接copy的显存 经朋友测试的确可以截到

本来想看看的 毕竟上次泄露nv的驱动源码 但是我电脑不支持此方案

[NVIDIA Capture SDK | NVIDIA Developer](https://developer.nvidia.com/capture-sdk)

*NvFBC*  nv的视频录制sdk 是直接从显存里copy数据

按理也可以截图

不过最高支持win10 1803 我win11 所以没办法

所以这里没有测试方案

[video-sdk-samples/nvEncDXGIOutputDuplicationSample at master · NVIDIA/video-sdk-samples (github.com)](https://github.com/NVIDIA/video-sdk-samples/tree/master/nvEncDXGIOutputDuplicationSample)

他官方推荐的代替方案

后来我又去实现了他文档放弃win10 所推荐的dx方案

**IDXGIOutput** 发现并不能截图dwm

![image-20220424192056570](决赛 writeup.assets\image-20220424192056570.png)



后续...

amd 方案

[高级媒体框架 - GPU 打开 (gpuopen.com)](https://gpuopen.com/advanced-media-framework/)
