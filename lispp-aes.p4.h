/*
 *   LISPP - Lightweight stateless network layer privacy protection system
 *   Copyright (C) 2023 Marko Micovic, Uros Radenkovic, Pavle Vuletic, 
 *                      University of Belgrade, School of Electrical Engineering
 *   Copyright (C) 2019 Xiaoqi Chen,
 *                      Princeton University
 * 
 *   This file is part of LISPP.
 *
 *   LISPP is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   LISPP is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the GNU Affero General Public License
 *   along with LISPP. If not, see <https://www.gnu.org/licenses/>.
 */

#define AES_INDEX_00 0x00
#define AES_INDEX_01 0x01
#define AES_INDEX_02 0x02
#define AES_INDEX_03 0x03
#define AES_INDEX_10 0x04
#define AES_INDEX_11 0x05
#define AES_INDEX_12 0x06
#define AES_INDEX_13 0x07
#define AES_INDEX_20 0x08
#define AES_INDEX_21 0x09
#define AES_INDEX_22 0x0A
#define AES_INDEX_23 0x0B
#define AES_INDEX_30 0x0C
#define AES_INDEX_31 0x0D
#define AES_INDEX_32 0x0E
#define AES_INDEX_33 0x0F

// macro for generating the mask_key action
#define GEN_ACTION_MASK_KEY() \
    action mask_key(bit<W_32> key_127_096, bit<W_32> key_095_064, bit<W_32> key_063_032, bit<W_32> key_031_000) { \
            meta.aes.r0 = meta.aes.t0 ^ key_127_096; \
            meta.aes.r1 = meta.aes.t1 ^ key_095_064; \
            meta.aes.r2 = meta.aes.t2 ^ key_063_032; \
            meta.aes.r3 = meta.aes.t3 ^ key_031_000; \
        }

// macro for generating key masking tables
#define GEN_TABLE_MASK_KEY(ROUND, SUBKEY_127_096, SUBKEY_095_064, SUBKEY_063_032, SUBKEY_031_000) \
    table mask_key_round##ROUND##_table { \
        actions = { mask_key; } \
        default_action = mask_key(SUBKEY_127_096, SUBKEY_095_064, SUBKEY_063_032, SUBKEY_031_000); \
    }

// macro for applying mask_key_round table
#define APPLY_MASK_KEY(ROUND) mask_key_round##ROUND##_table.apply();

// macro for generating the new_round action
#define GEN_ACTION_NEW_ROUND() \
    action new_round() { \
        meta.aes.t0 = 0; \
        meta.aes.t1 = 0; \
        meta.aes.t2 = 0; \
        meta.aes.t3 = 0; \
    }

// macro for generating the merge_to_tx_whole action
#define GEN_ACTION_MERGE_TO_TX_WHOLE() \
    action merge_to_tx_whole(bit<W_32> valueFromLut) { \
        if ((meta.aes.index & 0x0C) == 0x00) { /* AES_INDEX_00 || AES_INDEX_01 || AES_INDEX_02 || AES_INDEX_03 */ \
            meta.aes.t0 = meta.aes.t0 ^ valueFromLut; \
        } else if ((meta.aes.index & 0x0C) == 0x04) { /* AES_INDEX_10 || AES_INDEX_11 || AES_INDEX_12 || AES_INDEX_13 */ \
            meta.aes.t1 = meta.aes.t1 ^ valueFromLut; \
        } else if ((meta.aes.index & 0x0C) == 0x08) { /* AES_INDEX_20 || AES_INDEX_21 || AES_INDEX_22 || AES_INDEX_23 */ \
            meta.aes.t2 = meta.aes.t2 ^ valueFromLut; \
        } else if ((meta.aes.index & 0x0C) == 0x0C) { /* AES_INDEX_30 || AES_INDEX_31 || AES_INDEX_32 || AES_INDEX_33 */ \
            meta.aes.t3 = meta.aes.t3 ^ valueFromLut; \
        } \
    }

// macro for generating the merge_to_tx_slice action
#define GEN_ACTION_MERGE_TO_TX_SLICE() \
    action merge_to_tx_slice(bit<W_8> valueFromLut) { \
        if (meta.aes.index == AES_INDEX_00) { \
            meta.aes.t0[31:24] = meta.aes.t0[31:24] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_01) { \
            meta.aes.t0[23:16] = meta.aes.t0[23:16] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_02) { \
            meta.aes.t0[15: 8] = meta.aes.t0[15: 8] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_03) { \
            meta.aes.t0[ 7: 0] = meta.aes.t0[ 7: 0] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_10) { \
            meta.aes.t1[31:24] = meta.aes.t1[31:24] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_11) { \
            meta.aes.t1[23:16] = meta.aes.t1[23:16] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_12) { \
            meta.aes.t1[15: 8] = meta.aes.t1[15: 8] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_13) { \
            meta.aes.t1[ 7: 0] = meta.aes.t1[ 7: 0] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_20) { \
            meta.aes.t2[31:24] = meta.aes.t2[31:24] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_21) { \
            meta.aes.t2[23:16] = meta.aes.t2[23:16] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_22) { \
            meta.aes.t2[15: 8] = meta.aes.t2[15: 8] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_23) { \
            meta.aes.t2[ 7: 0] = meta.aes.t2[ 7: 0] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_30) { \
            meta.aes.t3[31:24] = meta.aes.t3[31:24] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_31) { \
            meta.aes.t3[23:16] = meta.aes.t3[23:16] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_32) { \
            meta.aes.t3[15: 8] = meta.aes.t3[15: 8] ^ valueFromLut; \
        } else if (meta.aes.index == AES_INDEX_33) { \
            meta.aes.t3[ 7: 0] = meta.aes.t3[ 7: 0] ^ valueFromLut; \
        } \
    }

// macro for generating lookup tables, which is match-action table that XOR the value into accumulator variable
#define GEN_TABLE_LUT(NAME, WRITE) \
    table NAME { \
        key = { meta.aes.matcher: exact; } \
        actions = { WRITE; } \
        size = 256; \
    }
