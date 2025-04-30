#include "dwarf_unwind.hpp"
#include <cstring>

// BEGIN CHANGED CODE – pull in libunwind **only** when requested
#if DWARF_UNWINDING
#   include <libunwind.h>
#   include <ucontext.h>
#endif
// END CHANGED CODE

bool UnwindRbpChain(const uint8_t* snap,
                    uint32_t       snapSz,
                    uint64_t       snapBase,
                    uint64_t       rbp,
                    std::vector<uint64_t>& frames,
                    bool&          truncated)
{
    truncated = false;
    constexpr int kMaxFrames = 128;

// BEGIN CHANGED CODE – try DWARF first, fall back to frame-pointer chain
#if DWARF_UNWINDING
    // -------- Attempt DWARF / CFI unwinding via libunwind ----------
    //  We synthesise a minimal ucontext_t containing RIP/RSP/RBP taken
    //  from the snapshot, then ask libunwind to walk using DWARF CFI.
    uint64_t rip0 = 0;
    if (snapSz >= 8)
        std::memcpy(&rip0, snap, sizeof(uint64_t));  // return-addr on stack

    ucontext_t uc{};                       // zero-initialised
#   if defined(__x86_64__)
    uc.uc_mcontext.gregs[REG_RIP] = rip0;
    uc.uc_mcontext.gregs[REG_RSP] = snapBase;
    uc.uc_mcontext.gregs[REG_RBP] = rbp;
#   else
    // (Other archs need their own register setup.)
#   endif

    unw_cursor_t cur;
    if (unw_init_local(&cur, &uc) == 0) {
        int frameCount = 0;
        while (frameCount < kMaxFrames && unw_step(&cur) > 0) {
            unw_word_t ip;
            if (unw_get_reg(&cur, UNW_REG_IP, &ip) < 0) break;
            frames.push_back(static_cast<uint64_t>(ip));
            ++frameCount;
        }
        if (frameCount == kMaxFrames) truncated = true;
        if (!frames.empty())        // success – we're done
            return true;
        // else: fall through and try the simple chain walker
    }
#endif
// END CHANGED CODE – DWARF attempt finished; fallback below

    auto inSnapshot = [&](uint64_t addr) {
        return addr >= snapBase && (addr + 8) < snapBase + snapSz;
    };

    int frameCount = 0;
    while (inSnapshot(rbp) && frameCount++ < kMaxFrames)
    {
        uint64_t off = rbp - snapBase;
        uint64_t nextRbp, retAddr;
        std::memcpy(&nextRbp, snap + off,        sizeof(uint64_t));
        std::memcpy(&retAddr, snap + off + 8,    sizeof(uint64_t));
        frames.push_back(retAddr);

        if (!nextRbp || nextRbp <= rbp) break;   // bogus or done
        if (!inSnapshot(nextRbp))
        {
            truncated = true;
            break;
        }
        rbp = nextRbp;
    }
    return !frames.empty();
} 