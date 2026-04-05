# Windows API Reference for Developers

## File System APIs

### File Operations
```c
// CreateFile
HANDLE CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

// ReadFile / WriteFile
BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

// DeleteFile, CopyFile, MoveFile
BOOL DeleteFileA(LPCSTR lpFileName);
BOOL CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);
BOOL MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName);

// GetFileAttributes, SetFileAttributes
DWORD GetFileAttributesA(LPCSTR lpFileName);
BOOL SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes);
```

### Directory Operations
```c
// CreateDirectory, RemoveDirectory
BOOL CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BOOL RemoveDirectoryA(LPCSTR lpPathName);

// FindFirstFile, FindNextFile
HANDLE FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
BOOL FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
BOOL FindClose(HANDLE hFindFile);
```

## Registry APIs

### Opening Keys
```c
LSTATUS RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, DWORD samDesired, PHKEY phkResult);
LSTATUS RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, DWORD samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
```

### Query/Set Values
```c
LSTATUS RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LSTATUS RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
LSTATUS RegDeleteValueA(HKEY hKey, LPCSTR lpValueName);
LSTATUS RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey);
```

### Common Registry Keys
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SYSTEM\CurrentControlSet\Services
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
```

## Process APIs

### Process Creation
```c
BOOL CreateProcessA(
    LPCSTR lpApplicationName,
    LPCSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);
```

### Process Information
```c
DWORD GetCurrentProcessId();
DWORD GetCurrentThreadId();
HANDLE GetCurrentProcess();
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode);
BOOL CloseHandle(HANDLE hObject);
```

### DLL Loading
```c
HMODULE LoadLibraryA(LPCSTR lpLibFileName);
FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
BOOL FreeLibrary(HMODULE hModule);
```

## Memory APIs

### Memory Allocation
```c
LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
```

### Memory Protection
```c
BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
```

## Networking APIs

### Winsock
```c
int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
SOCKET socket(int af, int type, int protocol);
int bind(SOCKET s, const struct sockaddr* name, int namelen);
int listen(SOCKET s, int backlog);
SOCKET accept(SOCKET s, struct sockaddr* addr, int* addrlen);
int connect(SOCKET s, const struct sockaddr* name, int namelen);
int send(SOCKET s, const char* buf, int len, int flags);
int recv(SOCKET s, char* buf, int len, int flags);
```

### WinHTTP
```c
HINTERNET WinHttpOpen(LPCWSTR pwszAgentW, DWORD dwAccessType, LPCWSTR pwszProxyW, LPCWSTR pwszProxyBypassW, DWORD dwFlags);
HINTERNET WinHttpConnect(HINTERNET hSession, LPCWSTR pszServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
HINTERNET WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags);
BOOL WinHttpSendRequest(HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
BOOL WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved);
```

## Service APIs

### Creating/Managing Services
```c
SC_HANDLE CreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword);
SC_HANDLE OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwAccess);
SC_HANDLE OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwAccess);
BOOL StartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR* lpServiceArgVectors);
BOOL ControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
BOOL DeleteService(SC_HANDLE hService);
```

## Event Log APIs

```c
HANDLE RegisterEventSourceA(LPCSTR lpSourceName);
BOOL ReportEventA(HANDLE hEventLog, WORD wType, WORD wCategory, DWORD dwEventID, PSID lpUserSid, WORD wNumStrings, DWORD dwDataSize, LPCSTR* lpStrings, LPVOID lpRawData);
BOOL DeregisterEventSource(HANDLE hEventLog);
```

## Windows Forensics Artifacts

| Artifact | Path | Tool |
|----------|------|------|
| Prefetch | C:\Windows\Prefetch\ | pecmd, win Prefetch parser |
| Jump Lists | C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations | jlecmd |
| Shellbags | NTUSER.DAT | Shellbags Explorer |
| MFT | $MFT | MFT parser |
| USN Journal | $Extend\$UsnJrnl | USN Parser |
| Restore Points | System Volume Information\ | restorepointinfo |
| Thumbnail Cache | C:\Users\*\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db | Thumbnail DB Parser |

## Common DLLs for DFIR

| DLL | Purpose |
|-----|---------|
| ntdll.dll | NT kernel interface |
| kernel32.dll | Core Windows API |
| advapi32.dll | Advanced API (registry, services) |
| user32.dll | User interface |
| gdi32.dll | Graphics |
| ws2_32.dll | Windows Sockets |
| netapi32.dll | Network API |
| secur32.dll | Security |
| crypt32.dll | Cryptography |
| wintrust.dll | Trust verification |
