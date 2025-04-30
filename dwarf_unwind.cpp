#include "dwarf_unwind.hpp"
#include <cstring>

bool UnwindRbpChain(const uint8_t* snap,
                    uint32_t       snapSz,
                    uint64_t       snapBase,
                    uint64_t       rbp,
                    std::vector<uint64_t>& frames,
                    bool&          truncated)
{
    truncated = false;
    constexpr int kMaxFrames = 128;
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