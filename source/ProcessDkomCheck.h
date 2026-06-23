#pragma once
#include <windows.h>
#include <string>
#include <vector>

enum class DkomHitReason {
    None = 0,
    HiddenBrute,    // exists via OpenProcess 2x, absent from all APL 2x
    HiddenHandle,   // referenced in handle table 2x, absent from all APL 2x
    GhostWindow     // window 2x, absent from all APL 2x
};

struct DkomProcessHit {
    DWORD pid = 0;
    std::string name;
    bool visibleInEnumProc = false;
    bool visibleInToolhelp = false;
    bool visibleInNtQsi = false;
    bool visibleInWindows = false;
    bool visibleInBruteforce = false;
    bool visibleInHandles = false;
    DkomHitReason reason = DkomHitReason::None;
};

class ProcessDkomCheck {
public:
    void Run(std::vector<DkomProcessHit>& outHits);

    size_t TotalEnumProc() const { return m_totalEnumProc; }
    size_t TotalToolhelp() const { return m_totalToolhelp; }
    size_t TotalNtQsi() const { return m_totalNtQsi; }
    size_t TotalWindows() const { return m_totalWindows; }
    size_t TotalBruteforce() const { return m_totalBruteforce; }
    size_t HitsCount() const { return m_hitsCount; }

private:
    size_t m_totalEnumProc = 0;
    size_t m_totalToolhelp = 0;
    size_t m_totalNtQsi = 0;
    size_t m_totalWindows = 0;
    size_t m_totalBruteforce = 0;
    size_t m_hitsCount = 0;
};
