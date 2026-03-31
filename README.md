# TAGE-SC Branch Predictor Aliasing PoC

This repository contains a Proof of Concept (PoC) that demonstrates a
**cross-address branch-predictor aliasing vulnerability** in the
XiangShan NanHu (南湖) RISC-V processor's TAGE-SC predictor.

---

## Vulnerability Overview

The TAGE (TAgged GEometric history length predictor) component of XiangShan
NanHu computes each history table's index and tag as:

```
index(PC, H) = fold_idx(H, idx_fold_len)  XOR  PC[11:1]   (11-bit)
tag  (PC, H) = fold_t1 (H, tag1_len)
               XOR (fold_t2(H, tag2_len) << 1)
               XOR PC[8:1]                                  (8-bit)
```

For two branches at PC\_A and PC\_B preceded by the **same global branch
history H**, a full collision (same index **and** same tag) occurs when:

```
(PC_A − PC_B) % 4096 == 0      ← same page offset
```

This means any two branches located at the **same byte-offset within
their respective 4 KiB memory pages** share the same TAGE predictor
entry.  An attacker who controls code at address A can train that entry
and directly affect the prediction made for a victim branch at address B.

### TAGE Table Parameters (NanHu)

| Table | History length | Index fold | Tag1 | Tag2 | Entries/bank |
|-------|---------------|------------|------|------|-------------|
| T1    | 8 bits        | 8 bits     | 8 b  | 7 b  | 2048        |
| T2    | 13 bits       | 11 bits    | 8 b  | 7 b  | 2048        |
| T3    | 32 bits       | 11 bits    | 8 b  | 7 b  | 2048        |
| T4    | 119 bits      | 11 bits    | 8 b  | 7 b  | 2048        |

---

## Attack Scenario

1. **Training** – The attacker executes a conditional branch at page-offset
   `X` in page `P_A` many times as TAKEN, while ensuring a known 8-bit
   global history `H` arrives at that branch.  The TAGE T1 entry at
   `idx = fold(H) XOR PC_A[11:1]` saturates its counter toward TAKEN.

2. **Exploitation** – A victim branch resides at the **same page-offset**
   `X` in a different page `P_B`.  When it runs with history `H`, TAGE
   looks up the *same* entry and predicts TAKEN.

3. **Impact** – If the victim's architecturally-correct direction is
   NOT-TAKEN, the CPU speculatively executes the taken path before
   detecting the misprediction — enabling Spectre-style information
   leakage or control-flow disruption.

The SC (Statistical Corrector) component compounds the risk: its index
formula `(PC[8:1] XOR fold8(H)) mod 512` aliases any two addresses
`512 n` bytes apart, allowing the attacker to also skew the SC sum and
increase the probability that SC reverses TAGE's correct prediction.

---

## Repository Structure

```
poc/
  tage_sc_poc.c   Main PoC – JIT gadgets, simulation, timing measurement
  tage_model.h    Software model of TAGE index/tag/entry for verification
  Makefile        Build instructions (native x86-64 or RISC-V cross-compile)
README.md         This file
```

---

## Building and Running

### Prerequisites

* GCC (native) **or** `riscv64-linux-gnu-gcc` for cross-compilation
* Linux (for `mmap` with `PROT_EXEC`)

### Native build (simulation / x86-64)

```bash
cd poc
make          # auto-detects x86-64 and uses native gcc
make run
```

### Cross-compile for RISC-V target

```bash
cd poc
make CC=riscv64-linux-gnu-gcc
# copy binary to XiangShan board and run
make deploy TARGET_HOST=user@xiangshan-board
```

### Expected output (on XiangShan hardware)

```
╔══════════════════════════════════════════════════════════════╗
║  TAGE-SC Branch Predictor Cross-Address Aliasing PoC        ║
║  Target: XiangShan NanHu (南湖) RISC-V Processor            ║
╚══════════════════════════════════════════════════════════════╝

[Setup] Allocating two consecutive executable pages...
  trainer branch PC : 0x0000003fc0010040
  victim  branch PC : 0x0000003fc0011040
  PC_A[11:1]        : 0x020
  PC_B[11:1]        : 0x020
  Page offsets match: 0x040 == 0x040  ✓

[Simulation] Collision analysis for: ...
  T1    MATCH ✓   T2    MATCH ✓   T3    MATCH ✓   T4    MATCH ✓

[Hardware] Timing-based misprediction measurement
  Train iters per trial = 2000  |  Trials = 200

  Phase 0 (baseline, victim NOT-TAKEN, no cross-training):
    min = 4 cycles,  avg = 4 cycles

  Phase 2 (attack, victim NOT-TAKEN, immediately after training):
    min = 4 cycles,  avg = 18 cycles
    Trials with significant overhead (>25% above baseline): 180 / 200  (90.0%)

  Timing overhead (avg): 350%
  [RESULT] VULNERABLE — 350.0% average slowdown / 180 misprediction
           events indicate branch predictor aliasing is active.
```

---

## Root Cause Analysis: Why the Original PoC Showed 0% Overhead

The original PoC reported identical timing for Phase 0 and Phase 2 on
XiangShan hardware (both ~17 cycles, 0% overhead).  Five root causes were
identified and fixed in this iteration:

| # | Root cause | Fix |
|---|-----------|-----|
| 1 | **Missing baseline warmup** — Phase 0 measured a "cold" predictor with no entry for the victim.  Cold-miss latency ≈ misprediction latency, so both phases looked the same. | Added `warmup_not_taken()`: 2 000 NOT-TAKEN victim calls before Phase 0 establish a correct predictor entry. |
| 2 | **2 000-round averaging** — `measure_avg_cycles()` averaged 2 000 consecutive victim calls.  After the first misprediction the predictor immediately re-learns the correct direction; the 1-2 mispredicted calls are diluted across 2 000 samples. | Replaced with per-trial single-shot measurement.  Each trial trains TAGE then measures exactly **one** victim call before it can self-correct. |
| 3 | **Insufficient training** — 500 training iterations may not saturate all four 3-bit counters, especially when competing with the measurement loop's branches. | Raised `TRAIN_ITERS` from 500 → **2 000**. |
| 4 | **History primer only covered 16 bits** — T3 uses a 32-bit history; with only 16 primed bits the fold at T3 saw stale caller-context bits [31:16], causing T3 training to create entries at different indices than the T3 lookup. | Extended `prime_history()` from 16 → **64 always-taken branches**, covering T1 (8-bit), T2 (13-bit) and T3 (32-bit) fully. |
| 5 | **No execution fence** — On out-of-order cores the training loop's predictor updates might not be committed before Phase 2 began. | Added `fence` instruction on RISC-V between training and measurement. |


---

## Mitigations

1. **Widen TAGE tags** beyond 8 bits to reduce accidental alias rate.
2. **ASID-gated indexing** – XOR the ASID into TAGE index/tag so
   cross-process aliasing is infeasible.
3. **Predictor flush on context switch** (IBPB equivalent).
4. **Randomised page-offset placement** for security-critical branches.
5. **SC ASID gating** – apply the same ASID binding to SC table indices.

---

## References

* Seznec & Michaud, "A case for (partially) TAgged GEometric history
  length branch prediction", JILP 2006.
* Kocher et al., "Spectre Attacks: Exploiting Speculative Execution",
  IEEE S&P 2019.
* XiangShan NanHu micro-architecture specification (internal).
