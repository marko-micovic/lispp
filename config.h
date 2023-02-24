#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <stdint.h>

// *****************************************************************************
// Configuration
// *****************************************************************************

#ifndef FORCE_INLINE
#define FUNCTION_MODIFIER
#else
#define FUNCTION_MODIFIER __forceinline
#endif

#define AES_ROUNDS 10

// https://www.cryptool.org/en/cto/aes-step-by-step
// 11 * 128bit expanded key
typedef struct
{
    uint32_t w0;
    uint32_t w1;
    uint32_t w2;
    uint32_t w3;
} uint128_t;

__declspec(local_mem shared) static uint128_t const aes_key_expanded[11] = {
    {0x01010101, 0x02020202, 0x03030303, 0x04040404},
    {0xf2f3f3f3, 0xf0f1f1f1, 0xf3f2f2f2, 0xf7f6f6f6},
    {0xb2b1b19b, 0x4240406a, 0xb1b2b298, 0x4644446e},
    {0xadaa2ec1, 0xefea6eab, 0x5e58dc33, 0x181c985d},
    {0x39ec626c, 0xd6060cc7, 0x885ed0f4, 0x904248a9},
    {0x05beb10c, 0xd3b8bdcb, 0x5be66d3f, 0xcba42596},
    {0x6c812113, 0xbf399cd8, 0xe4dff1e7, 0x2f7bd471},
    {0x0dc98206, 0xb2f01ede, 0x562fef39, 0x79543b48},
    {0xad2bd0b0, 0x1fdbce6e, 0x49f42157, 0x30a01a1f},
    {0x568910b4, 0x4952deda, 0x00a6ff8d, 0x3006e592},
    {0x0f505fb0, 0x4602816a, 0x46a47ee7, 0x76a29b75}};

#endif
