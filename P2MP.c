#include <stdio.h>

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

void __cdecl appInit(void)
{
    MessageBoxA(NULL, "appInit called", "P2MP", MB_ICONINFORMATION);
    return;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;
    
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
	char text[256];
	sprintf(text, "Process %lu", GetCurrentProcessId());

	MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);
	
	HANDLE hProcess = GetCurrentProcess();
	if (hProcess == NULL)
	{
	    sprintf(text, "GetCurrentProcess (%d).", GetLastError());
	    MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);

	    return 1;
	}

	HMODULE hModule = GetModuleHandleA("Core.dll");
	if (hModule == NULL)
	{
	    sprintf(text, "GetModuleHandleA (%d).", GetLastError());
	    MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);

	    return 1;
	}
	
	MODULEINFO modInfo;
	if (!GetModuleInformation(hProcess, hModule, &modInfo, sizeof(modInfo)))
	{
	    sprintf(text, "GetModuleInformation (%d).", GetLastError());
	    MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);

	    return 1;
	}
	sprintf(text, "GetModuleInformation Success (%p).", modInfo.lpBaseOfDll);
	MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);
	
	LPVOID lpAddress = modInfo.lpBaseOfDll + 0x3f99; // core.appInit

	DWORD lpflOldProtect;
	if (!VirtualProtectEx(hProcess, lpAddress, sizeof(DWORD_PTR),
			      PAGE_EXECUTE_READWRITE, &lpflOldProtect))
	{
	    sprintf(text, "VirtualProtectEx (%d).", GetLastError());
	    MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);

	    return 1;
	}

	char lpBuffer[5];
	if (!ReadProcessMemory(hProcess, lpAddress, lpBuffer, sizeof(lpBuffer), NULL))
	{
	    sprintf(text, "ReadProcessMemory (%d).", GetLastError());
	    MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);

	    return 1;
	}
	sprintf(text, "ReadProcessMemory Success (%02X %02X %02X %02X %02X).", lpBuffer[0], lpBuffer[1], lpBuffer[2], lpBuffer[3], lpBuffer[4]);
	MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);
	
	lpBuffer[0] = 0xE9;

	DWORD offset = (DWORD)appInit - ((DWORD)lpAddress + 5);
	*(lpBuffer + 1) = offset;

	if (!WriteProcessMemory(hProcess, lpAddress, lpBuffer, sizeof(lpBuffer), NULL))
	{
	    sprintf(text, "WriteProcessMemory (%d).", GetLastError());
	    MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);

	    return 1;
	}
	sprintf(text, "WriteProcessMemory Success (%02X %02X %02X %02X %02X).", lpBuffer[0], lpBuffer[1], lpBuffer[2], lpBuffer[3], lpBuffer[4]);
	MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);

	if (!ReadProcessMemory(hProcess, lpAddress, lpBuffer, sizeof(lpBuffer), NULL))
	{
	    sprintf(text, "ReadProcessMemory (%d).", GetLastError());
	    MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);

	    return 1;
	}
	sprintf(text, "ReadProcessMemory Success (%02X %02X %02X %02X %02X).", lpBuffer[0], lpBuffer[1], lpBuffer[2], lpBuffer[3], lpBuffer[4]);
	MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);
	
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == NULL)
	{
	    sprintf(text, "CreateToolhelp32Snapshot (%d).", GetLastError());
	    MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);

	    return 1;
	}

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	
	DWORD processId = GetCurrentProcessId();
	HANDLE hMainThread = NULL;

	if (Thread32First(hSnapshot, &te32)) {
	    do {
		if (te32.th32OwnerProcessID == processId) {
		    hMainThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
		    break;
		}
	    } while (Thread32Next(hSnapshot, &te32));
	}

	if (ResumeThread(hMainThread) == -1)
	{
	    sprintf(text, "ResumeThread (%d).", GetLastError());
	    MessageBoxA(NULL, text, "P2MP", MB_ICONINFORMATION);

	    return 1;
	}

	CloseHandle(hProcess);
    }

    return 0;
}
