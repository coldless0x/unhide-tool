#include "ProcessDkomCheck.h"
#include <cstdio>
#include <chrono>

#define XK 0x55

template<int N>
static void xr(char (&a)[N]) {
    for (int i = 0; i < N - 1; i++) a[i] ^= XK;
    a[N - 1] = 0;
}

static const char* ReasonLabel(DkomHitReason r) {
    switch (r) {
    case DkomHitReason::HiddenBrute:  return "DKOM hidden (bruteforce)";
    case DkomHitReason::HiddenHandle: return "DKOM hidden (handles)";
    case DkomHitReason::GhostWindow:  return "ghost window";
    default: return "unknown";
    }
}

int main() {
    {
        char s[] = { 0x11, 0x1E, 0x1A, 0x18, 0x75, 0x06, 0x36, 0x34, 0x3B, 0x3B, 0x30, 0x27, 0 };
        xr(s);
        printf("\n[+] %s\n\n", s);
    }
    {
        char s[] = { 0x06, 0x36, 0x34, 0x3B, 0x3B, 0x3C, 0x3B, 0x32, 0x7B, 0x7B, 0x7B, 0 };
        xr(s);
        printf("[+] %s\n", s);
    }
    fflush(stdout);

    auto t1 = std::chrono::high_resolution_clock::now();

    ProcessDkomCheck checker;
    std::vector<DkomProcessHit> hits;
    checker.Run(hits);

    auto t2 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

    {
        char s[] = { 0x70, 0x2F, 0x20, 0x75, 0x25, 0x27, 0x3A, 0x36, 0x26, 0x75, 0x29, 0x75, 0x70, 0x2F, 0x20, 0x75, 0x22, 0x3C, 0x3B, 0x26, 0x75, 0x29, 0x75, 0x70, 0x39, 0x39, 0x31, 0x75, 0x38, 0x26, 0 };
        xr(s);
        printf("[+] ");
        printf(s, checker.TotalEnumProc(), checker.TotalWindows(), (long long)ms);
        printf("\n");
    }

    if (hits.empty()) {
        char s[] = { 0x1B, 0x3A, 0x75, 0x26, 0x20, 0x26, 0x25, 0x3C, 0x36, 0x3C, 0x3A, 0x20, 0x26, 0x75, 0x25, 0x27, 0x3A, 0x36, 0x30, 0x26, 0x26, 0x30, 0x26, 0x7B, 0 };
        xr(s);
        printf("[+] %s\n", s);
    } else {
        char s[] = { 0x06, 0x20, 0x26, 0x25, 0x3C, 0x36, 0x3C, 0x3A, 0x20, 0x26, 0x6F, 0x75, 0x70, 0x2F, 0x20, 0 };
        xr(s);
        printf("[+] ");
        printf(s, hits.size());
        printf("\n\n");

        for (const auto& h : hits) {
            printf("[+]   %-6u  %s\n", h.pid, h.name.c_str());
            printf("[+]          %s", ReasonLabel(h.reason));
            if (h.visibleInBruteforce) printf(" | brute");
            if (h.visibleInHandles) printf(" | handle");
            if (h.visibleInWindows) printf(" | win");
            printf("\n");
        }
        printf("\n");
    }

    {
        char s[] = { 0x05, 0x27, 0x30, 0x26, 0x26, 0x75, 0x34, 0x3B, 0x2C, 0x75, 0x3E, 0x30, 0x2C, 0x75, 0x21, 0x3A, 0x75, 0x30, 0x2D, 0x3C, 0x21, 0x7B, 0 };
        xr(s);
        printf("[+] %s\n", s);
    }
    getchar();

    return 0;
}
