#include <windows.h>
#include <stdio.h>
#include <intrin.h>

#include "hook.h"
#include "Disassembler\hde32.h"

//use _InterlockedCompareExchange64 instead of inline ASM (depends on compiler)
#define NO_INLINE_ASM

TdefOldMessageBoxA OldMessageBoxA;
TdefOldMessageBoxW OldMessageBoxW;

LPVOID OriginalMemArea;

HOOK_ARRAY HookArray[] =
{
	{"user32.dll", "MessageBoxA", (LPVOID)&NewMessageBoxA, &OldMessageBoxA, 0},
	{"user32.dll", "MessageBoxW", (LPVOID)&NewMessageBoxW, &OldMessageBoxW, 0},
};

void HookAll()
{
	int i, NumEntries = sizeof(HookArray) / sizeof(HOOK_ARRAY);

	//Needs 25 bytes for each hooked function to hold original byte + return jump
	OriginalMemArea = VirtualAlloc(NULL, 25 * NumEntries, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(!OriginalMemArea)
		return;

	for(i = 0; i < NumEntries; i++)
	{
		//Split the allocated memory into a block of 25 bytes for each hooked function
		*(LPVOID *)HookArray[i].original = (LPVOID)((DWORD)OriginalMemArea + (i * 25));
		HookFunction(HookArray[i].dll, HookArray[i].name, HookArray[i].proxy, *(LPVOID *)HookArray[i].original, &HookArray[i].length); 
	}
}

void UnhookAll()
{
	int i, NumEntries = sizeof(HookArray) / sizeof(HOOK_ARRAY);

	for(i = 0; i < NumEntries; i++)
		UnhookFunction(HookArray[i].dll, HookArray[i].name, *(LPVOID *)HookArray[i].original, HookArray[i].length); 

	VirtualFree(OriginalMemArea, 0, MEM_RELEASE);
}

int WINAPI NewMessageBoxA(HWND hWnd, LPCSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	printf("MessageBoxA called!\ntitle: %s\ntext: %s\n\n", lpCaption, lpText);
	return OldMessageBoxA(hWnd, lpText, lpCaption, uType);
}

int WINAPI NewMessageBoxW(HWND hWnd, LPWSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	printf("MessageBoxW called!\ntitle: %ws\ntext: %ws\n\n", lpCaption, lpText);
	return OldMessageBoxW(hWnd, lpText, lpCaption, uType);
}

//We need to copy 5 bytes, but we can only do 2, 4, 8 atomically
//Pad buffer to 8 bytes then use lock cmpxchg8b instruction
void SafeMemcpyPadded(LPVOID destination, LPVOID source, DWORD size)
{
	BYTE SourceBuffer[8];

	if(size > 8)
		return;

	//Pad the source buffer with bytes from destination
	memcpy(SourceBuffer, destination, 8);
	memcpy(SourceBuffer, source, size);

#ifndef NO_INLINE_ASM
	__asm 
	{
		lea esi, SourceBuffer;
		mov edi, destination;

		mov eax, [edi];
		mov edx, [edi+4];
		mov ebx, [esi];
		mov ecx, [esi+4];

		lock cmpxchg8b[edi];
	}
#else
	_InterlockedCompareExchange64((LONGLONG *)destination, *(LONGLONG *)SourceBuffer, *(LONGLONG *)destination);
#endif
}

BOOL HookFunction(CHAR *dll, CHAR *name, LPVOID proxy, LPVOID original, PDWORD length)
{
	LPVOID FunctionAddress;
	DWORD TrampolineLength = 0, OriginalProtection;
	hde32s disam;
	BYTE Jump[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};

	FunctionAddress = GetProcAddress(GetModuleHandleA(dll), name);
	if(!FunctionAddress)
		return FALSE;

	//disassemble length of each instruction, until we have 5 or more bytes worth
	while(TrampolineLength < 5)
	{
		LPVOID InstPointer = (LPVOID)((DWORD)FunctionAddress + TrampolineLength);
		TrampolineLength += hde32_disasm(InstPointer, &disam);
	}

	//Build the trampoline buffer
	memcpy(original, FunctionAddress, TrampolineLength);
	*(DWORD *)(Jump+1) = ((DWORD)FunctionAddress + TrampolineLength) - ((DWORD)original + TrampolineLength + 5);
	memcpy((LPVOID)((DWORD)original+TrampolineLength), Jump, 5);

	//Make sure the function is writable
	if(!VirtualProtect(FunctionAddress, TrampolineLength, PAGE_EXECUTE_READWRITE, &OriginalProtection))
		return FALSE;

	//Build and atomically write the hook
	*(DWORD *)(Jump+1) = (DWORD)proxy - (DWORD)FunctionAddress - 5;
	SafeMemcpyPadded(FunctionAddress, Jump, 5);

	//Restore the original page protection
	VirtualProtect(FunctionAddress, TrampolineLength, OriginalProtection, &OriginalProtection);

	//Clear CPU instruction cache
	FlushInstructionCache(GetCurrentProcess(), FunctionAddress, TrampolineLength);

	*length = TrampolineLength;
	return TRUE;
}

BOOL UnhookFunction(CHAR *dll, CHAR *name, LPVOID original, DWORD length)
{
	LPVOID FunctionAddress;
	DWORD OriginalProtection;

	FunctionAddress = GetProcAddress(GetModuleHandleA(dll), name);
	if(!FunctionAddress)
		return FALSE;

	if(!VirtualProtect(FunctionAddress, length, PAGE_EXECUTE_READWRITE, &OriginalProtection))
		return FALSE;

	SafeMemcpyPadded(FunctionAddress, original, length);

	VirtualProtect(FunctionAddress, length, PAGE_EXECUTE_READWRITE, &OriginalProtection);

	FlushInstructionCache(GetCurrentProcess(), FunctionAddress, length);

	return TRUE;
}

int main()
{
	HookAll();

	MessageBoxA(NULL, "Hello", "MsgBoxA Test", MB_OK);
	MessageBoxA(NULL, "World", "MsgBoxA Test", MB_OK);

	MessageBoxW(NULL, L"Hello", L"MsgBoxW Test", MB_OK);
	MessageBoxW(NULL, L"World", L"MsgBoxW Test", MB_OK);

	UnhookAll();
	getchar();
}

