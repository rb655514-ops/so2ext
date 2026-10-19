// tools/recon.cpp — v2, под BlueStacks 5 #include <windows.h> #include <tlhelp32.h> #include <cstdio> #include <cwchar> #include <cwctype>
static void lower(wchar_t* s) { for (; *s; ++s) *s = (wchar_t)towlower(*s); }
static bool interesting(const wchar_t* name) { wchar_t b[260]; wcsncpy(b, name, 259); b[259] = 0; lower(b); return wcsstr(b, L"hd-") wcsstr(b, L"bstk") wcsstr(b, L"bluestacks"); }
struct Hit { DWORD pid; wchar_t name[260]; }; static Hit g_hits[64]; static int g_n = 0;
int main() { printf("=== SO2 external cheat / recon v2 (BlueStacks) ===\n\n");

C
HANDLE tok;
BOOL elev = FALSE;
if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
    TOKEN_ELEVATION te{}; DWORD sz = sizeof(te);
    if (GetTokenInformation(tok, TokenElevation, &te, sz, &sz)) elev = te.TokenIsElevated;
    CloseHandle(tok);
}
printf("elevated: %s\n\n", elev ? "YES" : "NO  <-- запусти от администратора");

HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
if (Process32FirstW(snap, &pe)) {
    do {
        if (interesting(pe.szExeFile) && g_n < 64) {
            g_hits[g_n].pid = pe.th32ProcessID;
            wcsncpy(g_hits[g_n].name, pe.szExeFile, 259);
            g_n++;
        }
    } while (Process32NextW(snap, &pe));
}
CloseHandle(snap);

if (!g_n) { printf("Процессы BlueStacks не найдены. Эмулятор запущен?\n"); return 1; }

printf("Найдено процессов BlueStacks: %d\n", g_n);
for (int i = 0; i < g_n; i++)
    printf("  pid=%6lu  %ls\n", g_hits[i].pid, g_hits[i].name);

for (int i = 0; i < g_n; i++) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, g_hits[i].pid);
    if (!h) {
        printf("\n[%ls] OpenProcess failed err=%lu\n", g_hits[i].name, GetLastError());
        continue;
    }

    printf("\n--- %ls (pid %lu): регионы >= 64 MB ---\n", g_hits[i].name, g_hits[i].pid);
    unsigned long long a = 0, totalBig = 0;
    MEMORY_BASIC_INFORMATION mbi;
    int cnt = 0;
    while (a < 0x00007FFFFFFFFFFFULL &&
           VirtualQueryEx(h, (LPCVOID)a, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize >= (64ull << 20)) {
            printf("   base=%016llX  size=%8.1f MB  protect=0x%lX  type=0x%lX\n",
                   (unsigned long long)mbi.BaseAddress,
                   mbi.RegionSize / 1048576.0, mbi.Protect, mbi.Type);
            totalBig += mbi.RegionSize;
            if (++cnt > 50) { printf("   ...\n"); break; }
        }
        unsigned long long nx = (unsigned long long)mbi.BaseAddress + mbi.RegionSize;
        if (nx <= a) break;
        a = nx;
    }
    printf("   итого крупных: %.1f MB\n", totalBig / 1048576.0);
    CloseHandle(h);
}

printf("\nГотово. Скопируй весь вывод.\n");
return 0;
}
