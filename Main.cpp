#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

DWORD GetProcessID(const char* targetProcessName)
{
    DWORD targetProcessID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(processEntry);

        if (Process32First(hSnapshot, &processEntry))
        {
            do
            {
                if (!_stricmp(processEntry.szExeFile, targetProcessName))
                {
                    targetProcessID = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &processEntry));
        }
    }
    CloseHandle(hSnapshot);
    return targetProcessID;
}

int main()
{
    DWORD targetProcessID = 0;
    STARTUPINFOA startupInfo = { sizeof(startupInfo) };
    PROCESS_INFORMATION processInfo;

    // Get DLL path
    char dllFullPath[MAX_PATH];
    if (!GetFullPathNameA("Raji_BasicTrainer.dll", MAX_PATH, dllFullPath, nullptr))
    {
        std::cout << "Failed to get full DLL path.\n";
        return 1;
    }

    // Launch game exe
    if (!CreateProcessA("Raji.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo))
    {
        std::cout << "Failed to launch Raji.exe\n";
        return 1;
    }

    std::cout << "Launched Raji.exe, waiting for Raji-Win64-Shipping.exe...\n";

    //close Raji.exe process handle after opening Raji.exe above
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);

    // Wait for game-win64-shipping.exe
    while (!targetProcessID)
    {
        targetProcessID = GetProcessID("Raji-Win64-Shipping.exe");

        if (!targetProcessID)
        {
            std::cout << "Waiting for Raji-Win64-Shipping.exe...\n";
            Sleep(1000);
        }
    }

    std::cout << "Process found with ID: " << targetProcessID << "\n";

    // Open the target process
    HANDLE hTargetHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, targetProcessID);
    if (!hTargetHandle || hTargetHandle == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to open target process.\n";
        return 1;
    }

    // Allocate memory in target process
    void* location = VirtualAllocEx(hTargetHandle, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!location)
    {
        std::cout << "Failed to allocate memory in target process.\n";
        CloseHandle(hTargetHandle);
        return 1;
    }

    // Write DLL path
    if (!WriteProcessMemory(hTargetHandle, location, dllFullPath, strlen(dllFullPath) + 1, 0))
    {
        std::cout << "Failed to write DLL path.\n";
        VirtualFreeEx(hTargetHandle, location, 0, MEM_RELEASE);
        CloseHandle(hTargetHandle);
        return 1;
    }

    // LoadLibrary address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC loadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryA");

    // Create remote thread
    HANDLE hThread = CreateRemoteThread(hTargetHandle, 0, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, location, 0, 0);
    if (hThread)
    {
        std::cout << "Remote thread created successfully.\n";
        CloseHandle(hThread);
    }
    else
    {
        std::cout << "Failed to create remote thread.\n";
        VirtualFreeEx(hTargetHandle, location, 0, MEM_RELEASE);
        CloseHandle(hTargetHandle);
        return 1;
    }

    CloseHandle(hTargetHandle);

    std::cout << "Injection complete.\n";
    return 0;
}
