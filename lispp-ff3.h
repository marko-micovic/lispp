/*
 *   LISPP - Lightweight stateless network layer privacy protection system
 *   Copyright (C) 2023 Marko Micovic, Uros Radenkovic, Pavle Vuletic, 
 *                      University of Belgrade, School of Electrical Engineering
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

#ifndef _LISPP_FF3_H_
#define _LISPP_FF3_H_

#include <stdint.h>

#include "config.h"
#include "lispp-aes.h"

// *****************************************************************************
// FF3
// *****************************************************************************

FUNCTION_MODIFIER static uint128_t power_of_two_modulo(
    __declspec(gp_reg) uint128_t number,
    __declspec(gp_reg) uint32_t powerOfTwo)
{
    uint32_t spilled_bits = powerOfTwo % 32;
    uint32_t affected_words = powerOfTwo / 32 + (spilled_bits == 0 ? 0 : 1);

    uint32_t mask[4] = {
        affected_words > 4 ? 0xFFFFFFFF : 0x00000000,
        affected_words > 3 ? 0xFFFFFFFF : 0x00000000,
        affected_words > 2 ? 0xFFFFFFFF : 0x00000000,
        affected_words > 1 ? 0xFFFFFFFF : 0x00000000};

    mask[4 - affected_words] = spilled_bits == 0 ? 0xFFFFFFFF : (1 << spilled_bits) - 1;

    number.w0 &= mask[0];
    number.w1 &= mask[1];
    number.w2 &= mask[2];
    number.w3 &= mask[3];

    return number;
}

FUNCTION_MODIFIER static uint128_t add(
    __declspec(gp_reg) uint128_t a,
    __declspec(gp_reg) uint128_t b)
{
    __declspec(gp_reg) uint128_t result;
    __declspec(gp_reg) uint32_t carry = 0;
    result.w3 = a.w3 + b.w3 + carry;
    carry = carry ? result.w3 <= b.w3 : result.w3 < b.w3;
    result.w2 = a.w2 + b.w2 + carry;
    carry = carry ? result.w2 <= b.w2 : result.w2 < b.w2;
    result.w1 = a.w1 + b.w1 + carry;
    carry = carry ? result.w1 <= b.w1 : result.w1 < b.w1;
    result.w0 = a.w0 + b.w0 + carry;
    carry = carry ? result.w0 <= b.w0 : result.w0 < b.w0;
    return result;
}

FUNCTION_MODIFIER static uint128_t sub(
    __declspec(gp_reg) uint128_t a,
    __declspec(gp_reg) uint128_t b)
{
    __declspec(gp_reg) uint128_t result;
    __declspec(gp_reg) uint32_t borrow = 0;
    result.w3 = a.w3 - b.w3 - borrow;
    borrow = borrow ? result.w3 >= a.w3 : result.w3 > a.w3;
    result.w2 = a.w2 - b.w2 - borrow;
    borrow = borrow ? result.w2 >= a.w2 : result.w2 > a.w2;
    result.w1 = a.w1 - b.w1 - borrow;
    borrow = borrow ? result.w1 >= a.w1 : result.w1 > a.w1;
    result.w0 = a.w0 - b.w0 - borrow;
    borrow = borrow ? result.w0 >= a.w0 : result.w0 > a.w0;
    return result;
}

__declspec(cls shared) static uint32_t const reverser_lut[256] = {
    0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
    0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8, 0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
    0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4, 0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
    0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec, 0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
    0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2, 0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
    0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea, 0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
    0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6, 0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
    0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee, 0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
    0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1, 0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
    0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9, 0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
    0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5, 0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
    0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed, 0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
    0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3, 0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
    0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb, 0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
    0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7, 0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
    0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef, 0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff};

FUNCTION_MODIFIER static uint32_t reverse_bits_32(
    __declspec(gp_reg) uint32_t param)
{
    __declspec(gp_reg) uint32_t reverse_param = 0;
    reverse_param = reverser_lut[param & 0xFF] << 0x18 |
                    reverser_lut[(param >> 0x08) & 0xFF] << 0x10 |
                    reverser_lut[(param >> 0x10) & 0xFF] << 0x08 |
                    reverser_lut[(param >> 0x18) & 0xFF];
    return reverse_param;
}

FUNCTION_MODIFIER static uint128_t reverse_bits_lower_n(
    __declspec(gp_reg) uint128_t input,
    __declspec(gp_reg) uint32_t n)
{
    uint32_t spilled_bits = n % 32;
    uint32_t affected_words = n / 32 + (spilled_bits == 0 ? 0 : 1);
    uint32_t offset = 32 - spilled_bits;
    uint32_t mask = ~(~0 << offset);

    __declspec(gp_reg) uint128_t result = {0, 0, 0, 0};

    __declspec(gp_reg) uint128_t reversed;
    reversed.w0 = reverse_bits_32(input.w3);
    reversed.w1 = reverse_bits_32(input.w2);
    reversed.w2 = reverse_bits_32(input.w1);
    reversed.w3 = reverse_bits_32(input.w0);

    if (spilled_bits == 0)
    {
        if (affected_words == 1)
        {
            result.w3 = reversed.w0;
        }
        else if (affected_words == 2)
        {
            result.w3 = reversed.w1;
            result.w2 = reversed.w0;
        }
        else if (affected_words == 3)
        {
            result.w3 = reversed.w2;
            result.w2 = reversed.w1;
            result.w1 = reversed.w0;
        }
        else if (affected_words == 4)
        {
            result.w3 = reversed.w3;
            result.w2 = reversed.w2;
            result.w1 = reversed.w1;
            result.w0 = reversed.w0;
        }
    }
    else
    {
        if (affected_words == 1)
        {
            result.w3 |= reversed.w0 >> offset;
        }
        else if (affected_words == 2)
        {
            result.w3 |= reversed.w1 >> offset;
            result.w3 |= (reversed.w0 & mask) << spilled_bits;
            result.w2 |= reversed.w0 >> offset;
        }
        else if (affected_words == 3)
        {
            result.w3 |= reversed.w2 >> offset;
            result.w3 |= (reversed.w1 & mask) << spilled_bits;
            result.w2 |= reversed.w1 >> offset;
            result.w2 |= (reversed.w0 & mask) << spilled_bits;
            result.w1 |= reversed.w0 >> offset;
        }
        else if (affected_words == 4)
        {
            result.w3 |= reversed.w3 >> offset;
            result.w3 |= (reversed.w2 & mask) << spilled_bits;
            result.w2 |= reversed.w2 >> offset;
            result.w2 |= (reversed.w1 & mask) << spilled_bits;
            result.w1 |= reversed.w1 >> offset;
            result.w1 |= (reversed.w0 & mask) << spilled_bits;
            result.w0 |= reversed.w0 >> offset;
        }
    }

    return result;
}

FUNCTION_MODIFIER static uint32_t reverse_bytes_4(
    __declspec(gp_reg) uint32_t param)
{
    __declspec(gp_reg) uint32_t mask = 0xFFFF0000; // 0b11111111111111110000000000000000;
    param = (param & mask) >> 0x10 | (param & ~mask) << 0x10;
    mask = 0xFF00FF00; // 0b11111111000000001111111100000000;
    param = (param & mask) >> 0x08 | (param & ~mask) << 0x08;
    return param;
}

FUNCTION_MODIFIER static uint128_t reverse_bytes_16(
    __declspec(gp_reg) uint128_t param)
{
    __declspec(gp_reg) uint128_t result;
    result.w0 = reverse_bytes_4(param.w3);
    result.w1 = reverse_bytes_4(param.w2);
    result.w2 = reverse_bytes_4(param.w1);
    result.w3 = reverse_bytes_4(param.w0);
    return result;
}

FUNCTION_MODIFIER static uint128_t get_ff3_initial_b(
    __declspec(gp_reg) uint128_t ff3_input,
    __declspec(gp_reg) uint32_t v)
{
    uint32_t spilled_bits_v = v % 32;
    uint32_t affected_words_v = v / 32 + (spilled_bits_v == 0 ? 0 : 1);
    uint32_t mask = spilled_bits_v == 0 ? 0xFFFFFFFF : ~(~0 << spilled_bits_v);
    ff3_input.w0 &= affected_words_v > 4 ? 0xFFFFFFFF : (affected_words_v == 4 ? mask : 0x00000000);
    ff3_input.w1 &= affected_words_v > 3 ? 0xFFFFFFFF : (affected_words_v == 3 ? mask : 0x00000000);
    ff3_input.w2 &= affected_words_v > 2 ? 0xFFFFFFFF : (affected_words_v == 2 ? mask : 0x00000000);
    ff3_input.w3 &= affected_words_v > 1 ? 0xFFFFFFFF : (affected_words_v == 1 ? mask : 0x00000000);
    return ff3_input;
}

FUNCTION_MODIFIER static uint128_t get_ff3_initial_a(
    __declspec(gp_reg) uint128_t ff3_input,
    __declspec(gp_reg) uint32_t v,
    __declspec(gp_reg) uint32_t u)
{
    uint32_t spilled_bits_v = v % 32;
    uint32_t whole_words_v = v / 32;
    uint32_t offset = 32 - spilled_bits_v;
    uint32_t mask = ~(~0 << offset);

    uint32_t i;

    if (spilled_bits_v != 0)
    {
        ff3_input.w3 >>= spilled_bits_v;
        ff3_input.w3 &= mask;
        ff3_input.w3 |= ff3_input.w2 << offset;
        ff3_input.w2 >>= spilled_bits_v;
        ff3_input.w2 &= mask;
        ff3_input.w2 |= ff3_input.w1 << offset;
        ff3_input.w1 >>= spilled_bits_v;
        ff3_input.w1 &= mask;
        ff3_input.w1 |= ff3_input.w0 << offset;
        ff3_input.w0 >>= spilled_bits_v;
        ff3_input.w0 &= mask;
    }

    for (i = 0; i < whole_words_v; i++)
    {
        ff3_input.w3 = ff3_input.w2;
        ff3_input.w2 = ff3_input.w1;
        ff3_input.w1 = ff3_input.w0;
        ff3_input.w0 = 0;
    }

    return get_ff3_initial_b(ff3_input, u);
}

FUNCTION_MODIFIER static uint128_t get_ff3_output(
    __declspec(gp_reg) uint128_t a,
    __declspec(gp_reg) uint128_t b,
    __declspec(gp_reg) uint32_t u,
    __declspec(gp_reg) uint32_t v)
{
    uint32_t spilled_bits_v = v % 32;
    uint32_t whole_words_v = v / 32;
    uint32_t offset = 32 - spilled_bits_v;

    uint32_t i;

    if (spilled_bits_v != 0)
    {
        a.w0 <<= spilled_bits_v;
        a.w0 |= a.w1 >> offset;
        a.w1 <<= spilled_bits_v;
        a.w1 |= a.w2 >> offset;
        a.w2 <<= spilled_bits_v;
        a.w2 |= a.w3 >> offset;
        a.w3 <<= spilled_bits_v;
    }

    for (i = 0; i < whole_words_v; i++)
    {
        a.w0 = a.w1;
        a.w1 = a.w2;
        a.w2 = a.w3;
        a.w3 = 0;
    }

    b.w0 |= a.w0;
    b.w1 |= a.w1;
    b.w2 |= a.w2;
    b.w3 |= a.w3;

    return b;
}

static uint128_t ff3_encrypt(
    __declspec(gp_reg) uint128_t ff3_input)
{
    __declspec(gp_reg) int32_t iteration;

    // [FF3-1] - step (2) : Let A = X[1..u]; B = X[u + 1..n]
    __declspec(gp_reg) uint128_t a = get_ff3_initial_a(ff3_input, W_V, W_U);
    __declspec(gp_reg) uint128_t b = get_ff3_initial_b(ff3_input, W_V);

    // [FF3-1] encryption iteration goes from 0 to 7
    for (iteration = 0; iteration <= (FF3_ROUNDS - 1); iteration++)
    {
        __declspec(gp_reg) uint128_t t;

        // [FF3-1] - step (3) : Let Tl = T[0..27] || 0*4 and Tr = T[32..55] || T[28..31] || 0*4
        // [FF3-1] - step (4.i) : If i is even, let m = u and W = Tr, else let m = v and W = Tl
        __declspec(gp_reg) uint32_t m;
        __declspec(gp_reg) uint32_t l;
        __declspec(gp_reg) uint32_t w;
        if ((iteration & 1) == 0)
        {
            m = W_U;
            l = W_V;
            w = FF3_TWEAK_R;
        }
        else
        {
            m = W_V;
            l = W_U;
            w = FF3_TWEAK_L;
        }

        // [FF3-1] - step (4.ii) : Let P = W ^ ([i]*4) || [NUMradix(REV(B))]*12
        t = reverse_bits_lower_n(b, l); // t <= [NUMradix(REV(B))]*12
        t.w0 = w ^ iteration;           // t <= P

        // [FF3-1] - step (4.iii) : Let S = REVB(CIPHER(REVB(P)))
        t = reverse_bytes_16(t); // t <= REVB(P)
        t = aes_encrypt(t);      // t <= CIPHER(REVB(P))
        t = reverse_bytes_16(t); // t <= S

        // [FF3-1] - step (4.iv) : Let y = NUM(S)
        // [FF3-1] - step (4.v) : Let c = (NUMradix(REV(A)) + y) mod (radix^^m)
        t = add(reverse_bits_lower_n(a, m), t); // t <= (NUMradix(REV(A)) + y)
        t = power_of_two_modulo(t, m);          // t <= c

        // [FF3-1] - step (4.vi) : Let C = REV(STRradix^^m(c))
        t = reverse_bits_lower_n(t, m); // t <= C

        // [FF3-1] - step (4.vii) : Let A = B
        a = b; // A <= B

        // [FF3-1] - step (4.viii) : Let B = C
        b = t; // B <= C
    }

    return get_ff3_output(a, b, W_U, W_V);
}

static uint128_t ff3_decrypt(
    __declspec(gp_reg) uint128_t ff3_input)
{
    __declspec(gp_reg) int32_t iteration;

    // [FF3-1] - step (2) : Let A = X[1..u]; B = X[u + 1..n]
    __declspec(gp_reg) uint128_t a = get_ff3_initial_a(ff3_input, W_V, W_U);
    __declspec(gp_reg) uint128_t b = get_ff3_initial_b(ff3_input, W_V);

    // [FF3-1] decryption iteration goes from 7 down to 0
    for (iteration = (FF3_ROUNDS - 1); iteration >= 0; iteration--)
    {
        __declspec(gp_reg) uint128_t t;

        // [FF3-1] - step (3) : Let Tl = T[0..27] || 0*4 and Tr = T[32..55] || T[28..31] || 0*4
        // [FF3-1] - step (4.i) : If i is even, let m = u and W = Tr, else let m = v and W = Tl
        uint32_t m;
        uint32_t l;
        uint32_t w;
        if ((iteration & 1) == 0)
        {
            m = W_U;
            l = W_V;
            w = FF3_TWEAK_R;
        }
        else
        {
            m = W_V;
            l = W_U;
            w = FF3_TWEAK_L;
        }

        // [FF3-1] - step (4.ii) : Let P = W ^ ([i]*4) || [NUMradix(REV(A))]*12
        t = reverse_bits_lower_n(a, l); // t <= [NUMradix(REV(A))]*12
        t.w0 = w ^ iteration;           // t <= P

        // [FF3-1] - step (4.iii) : Let S = REVB(CIPHER(REVB(P)))
        t = reverse_bytes_16(t); // t <= REVB(P)
        t = aes_encrypt(t);      // t <= CIPHER(REVB(P))
        t = reverse_bytes_16(t); // t <= S

        // [FF3-1] - step (4.iv) : Let y = NUM(S)
        // [FF3-1] - step (4.v) : Let c = (NUMradix(REV(B)) - y) mod (radix^^m)
        t = sub(reverse_bits_lower_n(b, m), t); // t <= (NUMradix(REV(B)) - y)
        t = power_of_two_modulo(t, m);          // t <= c

        // [FF3-1] - step (4.vi) : Let C = REV(STRradix^^m(c))
        t = reverse_bits_lower_n(t, m); // t <= C

        // [FF3-1] - step (4.vii) : Let B = A
        b = a; // B <= A

        // [FF3-1] - step (4.viii) : Let A = C
        a = t; // A <= C
    }

    return get_ff3_output(a, b, W_U, W_V);
}

#endif
