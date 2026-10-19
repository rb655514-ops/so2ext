#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cwchar>

int main() {
    printf("--- BlueStacks processes ---\n");
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W p{}; p.dwSize = sizeof(p);
    if (Process32FirstW(s, &p)) do {
        if (wcsstr(p.szExeFile, L"HD-") || wcsstr(p.szExeFile, L"Bstk")) {
            printf("pid=%lu  %ls\n", p.th32ProcessID, p.szExeFile);
            HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p.th32ProcessID);
            if (!h) { printf("   open failed %lu\n", GetLastError()); continue; }
            unsigned long long a = 0;
            MEMORY_BASIC_INFORMATION m;
            while (a < 0x7FFFFFFFFFFFULL && VirtualQueryEx(h, (LPCVOID)a, &m, sizeof(m))) {
                if (m.State == MEM_COMMIT && m.RegionSize >= (64ull << 20))
                    printf("   base=%llX  size=%.0f MB\n", (unsigned long long)m.BaseAddress, m.RegionSize / 1048576.0);
                unsigned long long n = (unsigned long long)m.BaseAddress + m.RegionSize;
                if (n <= a) break;
                a = n;
            }
            CloseHandle(h);
        }
    } while (Process32NextW(s, &p));
    CloseHandle(s);
    printf("--- done ---\n");
    return 0;
}
