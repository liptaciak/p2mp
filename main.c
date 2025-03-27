#include <stdio.h>
#include <string.h>

#include <windows.h>

int main()
{
    LPWSTR lpApplicationName = L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\POSTAL2Complete\\System\\Postal2.exe";
    LPWSTR lpCurrentDirectory = L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\POSTAL2Complete\\System";

    LPCSTR lpLibFileName = "C:\\Users\\mateu\\Documents\\p2mp\\P2MP.dll";
    
    STARTUPINFOW lpStartupInfo = {0};
    PROCESS_INFORMATION lpProcessInformation = {0};

    if (!CreateProcessW(lpApplicationName, NULL, NULL, NULL, FALSE, 0, NULL,
			lpCurrentDirectory, &lpStartupInfo, &lpProcessInformation))
    {
	printf("CreateProcessW (%d).\n", GetLastError());
	return 1;
    }

    WaitForInputIdle(lpProcessInformation.hProcess, INFINITE);
    CloseHandle(lpProcessInformation.hProcess);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lpProcessInformation.dwProcessId);
    if (hProcess == NULL)
    {
	printf("OpenProcess (%d).\n", GetLastError());
	return 1;
    }
    
    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, strlen(lpLibFileName) + 1,
					  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (lpBaseAddress == NULL)
    {
	printf("VirtualAllocEx (%d).\n", GetLastError());
	CloseHandle(hProcess);

	return 1;
    }
 
    if (!WriteProcessMemory(hProcess, lpBaseAddress, lpLibFileName,
			    strlen(lpLibFileName) + 1, NULL))
    {
	printf("WriteProcessMemory (%d).\n", GetLastError());

	if (!VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE))
	{
	    printf("VirtualFreeEx (%d).\n", GetLastError());
	}

	CloseHandle(hProcess);
	return 1;
    }

    HMODULE hKernel32 = LoadLibrary("kernel32.dll");
    LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    if (lpStartAddress == NULL)
    {
	printf("GetProcAddress (%d).\n", GetLastError());

	if (!VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE))
	{
	    printf("VirtualFreeEx (%d).\n", GetLastError());
	}

	CloseHandle(hProcess);
	return 1;
    }
   	
    DWORD lpThreadId;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, lpStartAddress,
					lpBaseAddress, 0, &lpThreadId);
    if (hThread == NULL)
    {
	printf("CreateRemoteThread (%d).\n", GetLastError());

	if (!VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE))
	{
	    printf("VirtualFreeEx (%d).\n", GetLastError());
	}

	CloseHandle(hProcess);
	return 1;
    }
    printf("ThreadId (%d).\n", lpThreadId);
    
    if (!VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE))
    {
	printf("VirtualFreeEx (%d).\n", GetLastError());
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    printf("DLL Injected");
    return 0;
}
