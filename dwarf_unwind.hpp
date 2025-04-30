#pragma once
#include <cstdint>
#include <vector>

// Very small helper: walk an RBP-framed stack living in |snapshot|.
// - snapshotBase   == live RSP at sample time (same addr BPF copied from)
// - firstRbp       == ctx->regs->bp  captured by BPF
// - on exit |truncated| is true when we ran out of snapshot before chain ended
bool UnwindRbpChain(const uint8_t* snapshot,
                    uint32_t        snapshotSize,
                    uint64_t        snapshotBase,
                    uint64_t        firstRbp,
                    std::vector<uint64_t>& outFrames,
                    bool&           truncated); 