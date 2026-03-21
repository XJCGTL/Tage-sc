/*
 * tage_model.h - Software model of XiangShan NanHu TAGE-SC predictor
 *
 * Models the index/tag computation and entry lookup for TAGE T1~T4.
 * Used to verify the cross-address aliasing collision analytically.
 */

#ifndef TAGE_MODEL_H
#define TAGE_MODEL_H

#include <stdint.h>
#include <stdbool.h>

/* =====================================================================
 * TAGE hardware parameters - XiangShan NanHu
 * ===================================================================== */

#define TAGE_NUM_TABLES   4          /* T1 ~ T4 tagged tables            */
#define TAGE_T0_SETS      2048       /* T0 base predictor sets           */
#define TAGE_T0_WAYS      2          /* T0 has 2 ways (2-bit ctr each)   */
#define TAGE_TAGGED_SETS  2048       /* T1~T4: 2048 entries per bank     */
#define TAGE_TAG_BITS     8          /* Tag width in bits                */
#define TAGE_CTR_BITS     3          /* Counter width in bits            */
#define TAGE_US_BITS      1          /* Usefulness counter width         */
#define TAGE_IDX_BITS     11         /* Index width: log2(2048)          */

/* Per-table configuration */
typedef struct {
    int hist_len;   /* Global history length used by this table          */
    int idx_fold;   /* Folded history length for index (bits)            */
    int tag1_len;   /* Folded history length for tag1 (bits)             */
    int tag2_len;   /* Folded history length for tag2 (bits)             */
} TageTableCfg;

/* T1..T4 parameters from the NanHu specification */
static const TageTableCfg TAGE_CFG[TAGE_NUM_TABLES] = {
    { .hist_len =   8, .idx_fold =  8, .tag1_len = 8, .tag2_len = 7 }, /* T1 */
    { .hist_len =  13, .idx_fold = 11, .tag1_len = 8, .tag2_len = 7 }, /* T2 */
    { .hist_len =  32, .idx_fold = 11, .tag1_len = 8, .tag2_len = 7 }, /* T3 */
    { .hist_len = 119, .idx_fold = 11, .tag1_len = 8, .tag2_len = 7 }, /* T4 */
};

/* =====================================================================
 * Folded-history computation
 *
 * "Fold" compresses a history of `hist_len` bits into `out_len` bits by
 * XOR-ing successive chunks of width `out_len`:
 *
 *   result = 0
 *   for each out_len-bit chunk c of history[hist_len-1:0]:
 *       result ^= c
 *
 * This is the standard TAGE compressed-history approach that lets hardware
 * maintain the fold register incrementally (shift + XOR new/old bit).
 * ===================================================================== */

static inline uint32_t fold_history(uint64_t history, int hist_len, int out_len)
{
    uint32_t result = 0;
    uint32_t mask   = (out_len < 32) ? ((1u << out_len) - 1u) : 0xffffffffu;
    int shift = 0;
    while (shift < hist_len) {
        int chunk = hist_len - shift;
        if (chunk > out_len) chunk = out_len;
        result ^= (uint32_t)((history >> shift) & mask);
        shift  += out_len;
    }
    return result & mask;
}

/* =====================================================================
 * Index and tag calculation
 *
 * index[TAGE_IDX_BITS-1:0] = fold_idx(H, cfg.idx_fold)  XOR  (PC >> 1)
 * tag  [TAGE_TAG_BITS-1:0] = fold_t1(H, cfg.tag1_len)
 *                           XOR (fold_t2(H, cfg.tag2_len) << 1)
 *                           XOR (PC >> 1)
 *
 * Both are truncated to TAGE_IDX_BITS / TAGE_TAG_BITS respectively.
 * ===================================================================== */

static inline uint32_t tage_index(uint64_t pc, uint64_t history,
                                  const TageTableCfg *cfg)
{
    uint32_t fold_idx = fold_history(history, cfg->hist_len, cfg->idx_fold);
    uint32_t pc_bits  = (uint32_t)(pc >> 1);
    uint32_t idx_mask = (1u << TAGE_IDX_BITS) - 1u;
    return (fold_idx ^ pc_bits) & idx_mask;
}

static inline uint32_t tage_tag(uint64_t pc, uint64_t history,
                                const TageTableCfg *cfg)
{
    uint32_t fold_t1 = fold_history(history, cfg->hist_len, cfg->tag1_len);
    uint32_t fold_t2 = fold_history(history, cfg->hist_len, cfg->tag2_len);
    uint32_t pc_bits = (uint32_t)(pc >> 1);
    uint32_t tag_mask = (1u << TAGE_TAG_BITS) - 1u;
    return (fold_t1 ^ (fold_t2 << 1) ^ pc_bits) & tag_mask;
}

/* =====================================================================
 * Entry structure for a single TAGE tagged-table slot
 * ===================================================================== */

typedef struct {
    bool     valid;
    uint32_t tag;                       /* TAGE_TAG_BITS wide             */
    int8_t   ctr;                       /* 3-bit signed saturating ctr    */
    uint8_t  us;                        /* 1-bit usefulness counter        */
} TageEntry;

/* Saturating counter helpers */
static inline int8_t ctr_inc(int8_t c, int bits) {
    int8_t max = (1 << (bits - 1)) - 1;
    return (c < max) ? c + 1 : c;
}
static inline int8_t ctr_dec(int8_t c, int bits) {
    int8_t min = -(1 << (bits - 1));
    return (c > min) ? c - 1 : c;
}

/* Prediction direction from 3-bit signed ctr (positive = taken) */
static inline bool ctr_pred(int8_t c) { return c >= 0; }

/* =====================================================================
 * Simplified TAGE table (one bank, no wrbypass for brevity)
 * ===================================================================== */

typedef struct {
    TageEntry entries[TAGE_TAGGED_SETS];
    TageTableCfg cfg;
    int table_id;
} TageTable;

static inline void tage_table_init(TageTable *t, int id)
{
    t->table_id = id;
    t->cfg      = TAGE_CFG[id];
    for (int i = 0; i < TAGE_TAGGED_SETS; i++) {
        t->entries[i].valid = false;
        t->entries[i].tag   = 0;
        t->entries[i].ctr   = 0;
        t->entries[i].us    = 0;
    }
}

static inline bool tage_table_lookup(TageTable *t, uint64_t pc,
                                     uint64_t history, TageEntry **out)
{
    uint32_t idx = tage_index(pc, history, &t->cfg);
    uint32_t tag = tage_tag (pc, history, &t->cfg);
    TageEntry *e = &t->entries[idx];
    if (e->valid && e->tag == tag) {
        if (out) *out = e;
        return true;
    }
    return false;
}

static inline void tage_table_update(TageTable *t, uint64_t pc,
                                     uint64_t history, bool taken)
{
    uint32_t idx = tage_index(pc, history, &t->cfg);
    uint32_t tag = tage_tag (pc, history, &t->cfg);
    TageEntry *e = &t->entries[idx];

    if (e->valid && e->tag == tag) {
        /* Update existing entry */
        e->ctr = taken ? ctr_inc(e->ctr, TAGE_CTR_BITS)
                       : ctr_dec(e->ctr, TAGE_CTR_BITS);
    } else {
        /* Allocate new entry */
        e->valid = true;
        e->tag   = tag;
        e->ctr   = taken ? 0 : -1;   /* Start near weak taken/not-taken */
        e->us    = 0;
    }
}

#endif /* TAGE_MODEL_H */
