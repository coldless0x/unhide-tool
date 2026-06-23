#include "ProcessDkomCheck.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <set>
#include <map>
#include <cstdio>
#include <cstring>

#define XK 0x55

template<int N>
static void xr(char (&a)[N]) {
    for (int i = 0; i < N - 1; i++) a[i] ^= XK;
    a[N - 1] = 0;
}

struct Api {
    HANDLE (WINAPI* OpenProcess)(DWORD, BOOL, DWORD);
    BOOL (WINAPI* CloseHandle)(HANDLE);
    HANDLE (WINAPI* CreateToolhelp32Snapshot)(DWORD, DWORD);
    BOOL (WINAPI* Process32FirstW)(HANDLE, LPPROCESSENTRY32W);
    BOOL (WINAPI* Process32NextW)(HANDLE, LPPROCESSENTRY32W);
    int (WINAPI* WideCharToMultiByte)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCCH, LPBOOL);
    HMODULE (WINAPI* LoadLibraryW)(LPCWSTR);

    BOOL (WINAPI* EnumProcesses)(DWORD*, DWORD, DWORD*);
    BOOL (WINAPI* QueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);

    NTSTATUS (WINAPI* NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

    BOOL (WINAPI* EnumWindows)(WNDENUMPROC, LPARAM);
    DWORD (WINAPI* GetWindowThreadProcessId)(HWND, LPDWORD);
    BOOL (WINAPI* GetExitCodeProcess)(HANDLE, LPDWORD);
    DWORD (WINAPI* GetProcessId)(HANDLE);

    bool Init();
};

static Api A = {};
static bool g_initDone = false;

static const DWORD kPidMin = 8;
static const DWORD kPidMax = 65535;
static const DWORD kScanDelayMs = 150;

static void AnsiToWide(const char* ansi, WCHAR* wide, int wideChars) {
    if (!ansi || !wide || wideChars <= 0) return;
    int i = 0;
    for (; ansi[i] && i < wideChars - 1; i++)
        wide[i] = (WCHAR)(unsigned char)ansi[i];
    wide[i] = 0;
}

#define LD(mod, ptr, ...) do { \
    char _b[] = __VA_ARGS__; \
    xr(_b); \
    *(FARPROC*)&ptr = GetProcAddress(mod, _b); \
    if (!ptr) return false; \
} while(0)

#define LD_OPT(mod, ptr, ...) do { \
    char _b[] = __VA_ARGS__; \
    xr(_b); \
    *(FARPROC*)&ptr = GetProcAddress(mod, _b); \
} while(0)

bool Api::Init() {
    char kn[] = { 0x3E, 0x30, 0x27, 0x3B, 0x30, 0x39, 0x66, 0x67, 0x7B, 0x31, 0x39, 0x39, 0 };
    xr(kn);
    HMODULE hK = GetModuleHandleA(kn);
    if (!hK) return false;

    char la[] = { 0x19, 0x3A, 0x34, 0x31, 0x19, 0x3C, 0x37, 0x27, 0x34, 0x27, 0x2C, 0x02, 0 };
    xr(la);
    FARPROC fpLL = GetProcAddress(hK, la);
    if (!fpLL) return false;
    this->LoadLibraryW = (HMODULE(WINAPI*)(LPCWSTR))fpLL;

    LD(hK, OpenProcess,          { 0x1A, 0x25, 0x30, 0x3B, 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0 });
    LD(hK, CloseHandle,          { 0x16, 0x39, 0x3A, 0x26, 0x30, 0x1D, 0x34, 0x3B, 0x31, 0x39, 0x30, 0 });
    LD(hK, CreateToolhelp32Snapshot, { 0x16, 0x27, 0x30, 0x34, 0x21, 0x30, 0x01, 0x3A, 0x3A, 0x39, 0x3D, 0x30, 0x39, 0x25, 0x66, 0x67, 0x06, 0x3B, 0x34, 0x25, 0x26, 0x3D, 0x3A, 0x21, 0 });
    LD(hK, Process32FirstW,      { 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x66, 0x67, 0x13, 0x3C, 0x27, 0x26, 0x21, 0x02, 0 });
    LD(hK, Process32NextW,       { 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x66, 0x67, 0x1B, 0x30, 0x2D, 0x21, 0x02, 0 });
    LD(hK, WideCharToMultiByte,  { 0x02, 0x3C, 0x31, 0x30, 0x16, 0x3D, 0x34, 0x27, 0x01, 0x3A, 0x18, 0x20, 0x39, 0x21, 0x3C, 0x17, 0x2C, 0x21, 0x30, 0 });
    LD_OPT(hK, GetExitCodeProcess, { 0x12, 0x30, 0x21, 0x10, 0x2D, 0x3C, 0x21, 0x16, 0x3A, 0x31, 0x30, 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0 });
    LD(hK, GetProcessId,          { 0x12, 0x30, 0x21, 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x1C, 0x31, 0 });
    LD_OPT(hK, QueryFullProcessImageNameW, { 0x04, 0x20, 0x30, 0x27, 0x2C, 0x13, 0x20, 0x39, 0x39, 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x1C, 0x38, 0x34, 0x32, 0x30, 0x1B, 0x34, 0x38, 0x30, 0x02, 0 });

    char pn[] = { 0x25, 0x26, 0x34, 0x25, 0x3C, 0x7B, 0x31, 0x39, 0x39, 0 };
    xr(pn);
    HMODULE hP = GetModuleHandleA(pn);
    if (!hP) {
        WCHAR wp[16];
        AnsiToWide(pn, wp, 16);
        hP = this->LoadLibraryW(wp);
    }
    if (hP) {
        LD_OPT(hP, EnumProcesses, { 0x10, 0x3B, 0x20, 0x38, 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x30, 0x26, 0 });
        if (!this->QueryFullProcessImageNameW)
            LD_OPT(hP, QueryFullProcessImageNameW, { 0x04, 0x20, 0x30, 0x27, 0x2C, 0x13, 0x20, 0x39, 0x39, 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x1C, 0x38, 0x34, 0x32, 0x30, 0x1B, 0x34, 0x38, 0x30, 0x02, 0 });
    }

    char nn[] = { 0x3B, 0x21, 0x31, 0x39, 0x39, 0x7B, 0x31, 0x39, 0x39, 0 };
    xr(nn);
    HMODULE hN = GetModuleHandleA(nn);
    if (!hN) {
        WCHAR wn[16];
        AnsiToWide(nn, wn, 16);
        hN = this->LoadLibraryW(wn);
    }
    if (hN) {
        LD_OPT(hN, NtQuerySystemInformation, { 0x1B, 0x21, 0x04, 0x20, 0x30, 0x27, 0x2C, 0x06, 0x2C, 0x26, 0x21, 0x30, 0x38, 0x1C, 0x3B, 0x33, 0x3A, 0x27, 0x38, 0x34, 0x21, 0x3C, 0x3A, 0x3B, 0 });
    }

    char un[] = { 0x20, 0x26, 0x30, 0x27, 0x66, 0x67, 0x7B, 0x31, 0x39, 0x39, 0 };
    xr(un);
    HMODULE hU = GetModuleHandleA(un);
    if (!hU) {
        WCHAR wu[16];
        AnsiToWide(un, wu, 16);
        hU = this->LoadLibraryW(wu);
    }
    if (hU) {
        LD_OPT(hU, EnumWindows,             { 0x10, 0x3B, 0x20, 0x38, 0x02, 0x3C, 0x3B, 0x31, 0x3A, 0x22, 0x26, 0 });
        LD_OPT(hU, GetWindowThreadProcessId, { 0x12, 0x30, 0x21, 0x02, 0x3C, 0x3B, 0x31, 0x3A, 0x22, 0x01, 0x3D, 0x27, 0x30, 0x34, 0x31, 0x05, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x1C, 0x31, 0 });
    }

    return true;
}

typedef struct _SYSTEM_PROCESS_INFO_EX {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} SYSTEM_PROCESS_INFO_EX, *PSYSTEM_PROCESS_INFO_EX;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

#define NtQsiClass(x) ((SYSTEM_INFORMATION_CLASS)(x))
#define SystemExtendedHandleInformationClass NtQsiClass(64)

static bool ProcessExists(DWORD pid) {
    if (pid < kPidMin || pid > kPidMax) return false;

    HANDLE h = A.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;

    if (A.GetProcessId(h) != pid) {
        A.CloseHandle(h);
        return false;
    }

    DWORD exitCode = 0;
    bool alive = true;
    if (A.GetExitCodeProcess)
        alive = A.GetExitCodeProcess(h, &exitCode) && exitCode == STILL_ACTIVE;
    A.CloseHandle(h);
    return alive;
}


static void BuildAplUnion(const std::set<DWORD>& ep,
                          const std::set<DWORD>& tp,
                          const std::set<DWORD>& nq,
                          std::set<DWORD>& apl) {
    apl.clear();
    apl.insert(ep.begin(), ep.end());
    apl.insert(tp.begin(), tp.end());
    apl.insert(nq.begin(), nq.end());
}

static bool QueryViaEnumProcesses(std::set<DWORD>& outPids,
                                  std::map<DWORD, std::string>& outNames) {
    if (!A.EnumProcesses) return false;
    DWORD pids[4096];
    DWORD cbNeeded = 0;
    if (!A.EnumProcesses(pids, sizeof(pids), &cbNeeded)) return false;

    DWORD nProcs = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < nProcs; i++) {
        DWORD pid = pids[i];
        if (pid == 0) continue;
        outPids.insert(pid);

        HANDLE h = A.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (h) {
            WCHAR wname[260] = {0};
            DWORD wsize = 260;
            if (A.QueryFullProcessImageNameW &&
                A.QueryFullProcessImageNameW(h, 0, wname, &wsize)) {
                std::wstring wpath = wname;
                size_t slash = wpath.find_last_of(L'\\');
                std::wstring basename = (slash != std::wstring::npos)
                                          ? wpath.substr(slash + 1) : wpath;
                char ansi[260] = {0};
                A.WideCharToMultiByte(CP_UTF8, 0, basename.c_str(), -1,
                                     ansi, sizeof(ansi), nullptr, nullptr);
                outNames[pid] = ansi;
            }
            A.CloseHandle(h);
        }
    }
    return true;
}

static bool QueryViaToolhelp(std::set<DWORD>& outPids,
                              std::map<DWORD, std::string>& outNames) {
    HANDLE snap = A.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (A.Process32FirstW(snap, &pe)) {
        do {
            DWORD pid = pe.th32ProcessID;
            if (pid == 0) continue;
            outPids.insert(pid);

            char ansi[260] = {0};
            A.WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                 ansi, sizeof(ansi), nullptr, nullptr);
            outNames[pid] = ansi;
        } while (A.Process32NextW(snap, &pe));
    }
    A.CloseHandle(snap);
    return true;
}

static bool QueryViaNtQsi(std::set<DWORD>& outPids,
                           std::map<DWORD, std::string>& outNames) {
    if (!A.NtQuerySystemInformation) return false;
    ULONG bufferSize = 0;
    NTSTATUS status = A.NtQuerySystemInformation(NtQsiClass(5), nullptr, 0, &bufferSize);
    if (bufferSize == 0) return false;

    ULONG allocSize = bufferSize + 0x10000;
    PVOID buf = malloc(allocSize);
    if (!buf) return false;

    status = A.NtQuerySystemInformation(NtQsiClass(5), buf, allocSize, &bufferSize);
    if (status < 0) {
        free(buf);
        return false;
    }

    PSYSTEM_PROCESS_INFO_EX cur = (PSYSTEM_PROCESS_INFO_EX)buf;
    PBYTE bufEnd = (PBYTE)buf + allocSize;
    while (cur) {
        if ((PBYTE)cur + sizeof(SYSTEM_PROCESS_INFO_EX) > bufEnd) break;

        DWORD pid = (DWORD)(ULONG_PTR)cur->UniqueProcessId;
        if (pid != 0) {
            outPids.insert(pid);
            if (cur->ImageName.Buffer && cur->ImageName.Length > 0 &&
                cur->ImageName.Length < 520) {
                const WCHAR* nameBuf = cur->ImageName.Buffer;
                ULONG nameBytes = cur->ImageName.Length;
                if ((PBYTE)nameBuf >= (PBYTE)buf && (PBYTE)nameBuf + nameBytes <= bufEnd) {
                    char ansi[260] = {0};
                    A.WideCharToMultiByte(CP_UTF8, 0, nameBuf,
                                         nameBytes / sizeof(WCHAR),
                                         ansi, sizeof(ansi) - 1, nullptr, nullptr);
                    outNames[pid] = ansi;
                }
            }
        }
        ULONG next = cur->NextEntryOffset;
        if (next == 0) break;
        if ((PBYTE)cur + next > bufEnd || next < sizeof(ULONG)) break;
        cur = (PSYSTEM_PROCESS_INFO_EX)((PBYTE)cur + next);
    }
    free(buf);
    return true;
}

struct EnumWindowsCtx {
    std::set<DWORD>* pids;
};

static BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    EnumWindowsCtx* ctx = (EnumWindowsCtx*)lParam;
    DWORD pid = 0;
    if (A.GetWindowThreadProcessId) A.GetWindowThreadProcessId(hwnd, &pid);
    if (pid != 0) ctx->pids->insert(pid);
    return TRUE;
}

static bool QueryViaWindows(std::set<DWORD>& outPids) {
    if (!A.EnumWindows) return false;
    EnumWindowsCtx ctx = { &outPids };
    return A.EnumWindows(EnumWindowsCallback, (LPARAM)&ctx) != 0;
}

static bool QueryViaHandlesRaw(std::set<DWORD>& outPids) {
    if (!A.NtQuerySystemInformation) return false;

    ULONG bufferSize = 0;
    NTSTATUS status = A.NtQuerySystemInformation(
        SystemExtendedHandleInformationClass, nullptr, 0, &bufferSize);
    if (bufferSize == 0) return false;

    ULONG allocSize = bufferSize + 0x10000;
    PVOID buf = malloc(allocSize);
    if (!buf) return false;

    status = A.NtQuerySystemInformation(
        SystemExtendedHandleInformationClass, buf, allocSize, &bufferSize);
    if (status < 0) {
        free(buf);
        return false;
    }

    PSYSTEM_HANDLE_INFORMATION_EX info = (PSYSTEM_HANDLE_INFORMATION_EX)buf;
    PBYTE bufEnd = (PBYTE)buf + allocSize;
    ULONG_PTR count = info->NumberOfHandles;

    for (ULONG_PTR i = 0; i < count; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = &info->Handles[i];
        if ((PBYTE)(entry + 1) > bufEnd) break;

        DWORD pid = (DWORD)entry->UniqueProcessId;
        if (pid >= kPidMin && pid <= kPidMax)
            outPids.insert(pid);
    }

    free(buf);
    return true;
}


static std::string ResolveProcessName(DWORD pid,
                                      const std::map<DWORD, std::string>& n1,
                                      const std::map<DWORD, std::string>& n2) {
    auto it = n1.find(pid);
    if (it != n1.end() && !it->second.empty()) return it->second;
    it = n2.find(pid);
    if (it != n2.end() && !it->second.empty()) return it->second;

    HANDLE h = A.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h && A.GetProcessId(h) == pid) {
        WCHAR wname[260] = {0};
        DWORD wsize = 260;
        if (A.QueryFullProcessImageNameW &&
            A.QueryFullProcessImageNameW(h, 0, wname, &wsize)) {
            std::wstring wpath = wname;
            size_t slash = wpath.find_last_of(L'\\');
            std::wstring basename = (slash != std::wstring::npos)
                                      ? wpath.substr(slash + 1) : wpath;
            char ansi[260] = {0};
            A.WideCharToMultiByte(CP_UTF8, 0, basename.c_str(), -1,
                                 ansi, sizeof(ansi), nullptr, nullptr);
            A.CloseHandle(h);
            return ansi;
        }
        A.CloseHandle(h);
    } else if (h) {
        A.CloseHandle(h);
    }

    char noname[] = { 0x7D, 0x3B, 0x3A, 0x78, 0x3B, 0x34, 0x38, 0x30, 0x7C, 0 };
    xr(noname);
    return noname;
}

struct ScanSnapshot {
    std::set<DWORD> enumP, toolP, ntqP, aplUnion, live, hidden, handles, windows;
    std::map<DWORD, std::string> names;
    bool okEnum = false;
    bool okTool = false;
    bool okNtq = false;
    bool okWin = false;
    bool okHandles = false;
};

static void CollectAplSources(std::set<DWORD>& ep,
                              std::set<DWORD>& tp,
                              std::set<DWORD>& nq,
                              std::map<DWORD, std::string>& names,
                              bool& okEnum, bool& okTool, bool& okNtq) {
    ep.clear();
    tp.clear();
    nq.clear();
    okEnum = QueryViaEnumProcesses(ep, names);
    okTool = QueryViaToolhelp(tp, names);
    okNtq  = QueryViaNtQsi(nq, names);
}

static void CollectLivePids(std::set<DWORD>& live) {
    live.clear();
    for (DWORD pid = kPidMin; pid <= kPidMax; pid++) {
        if (ProcessExists(pid))
            live.insert(pid);
    }
}

static void TakeSnapshot(ScanSnapshot& s) {
    s.aplUnion.clear();
    s.live.clear();
    s.hidden.clear();
    s.handles.clear();
    s.windows.clear();
    s.names.clear();

    std::set<DWORD> aplStart, aplEnd;
    CollectAplSources(s.enumP, s.toolP, s.ntqP, s.names,
                      s.okEnum, s.okTool, s.okNtq);
    BuildAplUnion(s.enumP, s.toolP, s.ntqP, aplStart);

    CollectLivePids(s.live);

    std::set<DWORD> ep2, tp2, nq2;
    std::map<DWORD, std::string> names2;
    bool okE2 = false, okT2 = false, okN2 = false;
    CollectAplSources(ep2, tp2, nq2, names2, okE2, okT2, okN2);
    BuildAplUnion(ep2, tp2, nq2, aplEnd);

    s.aplUnion = aplStart;
    s.aplUnion.insert(aplEnd.begin(), aplEnd.end());
    for (const auto& kv : names2) {
        if (!kv.second.empty() && !s.names.count(kv.first))
            s.names[kv.first] = kv.second;
    }

    for (DWORD pid : s.live) {
        if (!s.aplUnion.count(pid))
            s.hidden.insert(pid);
    }

    std::set<DWORD> rawHandles;
    s.okHandles = QueryViaHandlesRaw(rawHandles);
    for (DWORD pid : rawHandles) {
        if (!s.aplUnion.count(pid) && s.live.count(pid))
            s.handles.insert(pid);
    }

    std::set<DWORD> rawWin;
    s.okWin = QueryViaWindows(rawWin);
    for (DWORD pid : rawWin) {
        if (!s.aplUnion.count(pid))
            s.windows.insert(pid);
    }
}

void ProcessDkomCheck::Run(std::vector<DkomProcessHit>& outHits) {
    if (!g_initDone) { g_initDone = A.Init(); }
    if (!g_initDone) {
        char f3[] = { 0x0E, 0x11, 0x1E, 0x1A, 0x18, 0x08, 0x75, 0x13, 0x14, 0x01, 0x14, 0x19, 0x6F, 0x75, 0x3B, 0x30, 0x3B, 0x3D, 0x20, 0x38, 0x34, 0x75, 0x33, 0x3A, 0x3B, 0x21, 0x30, 0x75, 0x27, 0x30, 0x21, 0x3A, 0x27, 0x3B, 0x3A, 0x20, 0 };
        xr(f3);
        printf(f3);
        return;
    }

    outHits.clear();
    m_hitsCount = 0;

    ScanSnapshot s1, s2;
    TakeSnapshot(s1);
    Sleep(kScanDelayMs);
    TakeSnapshot(s2);

    m_totalEnumProc = s1.enumP.size();
    m_totalToolhelp = s1.toolP.size();
    m_totalNtQsi = s1.ntqP.size();
    m_totalWindows = s1.windows.size();
    m_totalBruteforce = s1.live.size();

    if (!s1.okEnum && !s1.okTool && !s1.okNtq && !s1.okWin && s1.live.empty()) {
        char f3[] = { 0x0E, 0x11, 0x1E, 0x1A, 0x18, 0x08, 0x75, 0x13, 0x14, 0x01, 0x14, 0x19, 0x6F, 0x75, 0x3B, 0x30, 0x3B, 0x3D, 0x20, 0x38, 0x34, 0x75, 0x33, 0x3A, 0x3B, 0x21, 0x30, 0x75, 0x27, 0x30, 0x21, 0x3A, 0x27, 0x3B, 0x3A, 0x20, 0 };
        xr(f3);
        printf(f3);
        return;
    }

    std::set<DWORD> candidates;
    auto addCandidates = [&](const std::set<DWORD>& src) {
        for (DWORD pid : src) candidates.insert(pid);
    };
    addCandidates(s1.hidden);
    addCandidates(s2.hidden);
    addCandidates(s1.handles);
    addCandidates(s2.handles);
    addCandidates(s1.windows);
    addCandidates(s2.windows);

    for (DWORD pid : candidates) {
        if (s1.aplUnion.count(pid) || s2.aplUnion.count(pid)) continue;
        if (!ProcessExists(pid)) continue;

        bool hiddenStable = s1.hidden.count(pid) && s2.hidden.count(pid);
        bool handleStable = s1.handles.count(pid) && s2.handles.count(pid);
        bool winStable = s1.windows.count(pid) && s2.windows.count(pid);

        DkomHitReason reason = DkomHitReason::None;

        if (hiddenStable) {
            reason = DkomHitReason::HiddenBrute;
        } else if (handleStable) {
            reason = DkomHitReason::HiddenHandle;
        } else if (winStable) {
            reason = DkomHitReason::GhostWindow;
        } else {
            continue;
        }

        DkomProcessHit hit;
        hit.pid = pid;
        hit.visibleInEnumProc = s1.enumP.count(pid) || s2.enumP.count(pid);
        hit.visibleInToolhelp = s1.toolP.count(pid) || s2.toolP.count(pid);
        hit.visibleInNtQsi    = s1.ntqP.count(pid) || s2.ntqP.count(pid);
        hit.visibleInWindows  = winStable;
        hit.visibleInBruteforce = hiddenStable;
        hit.visibleInHandles = handleStable;
        hit.reason = reason;
        hit.name = ResolveProcessName(pid, s1.names, s2.names);

        outHits.push_back(hit);
        m_hitsCount++;
    }
}
