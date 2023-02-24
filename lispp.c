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

#include <pif_plugin.h>
#include <stdint.h>

#include "lispp-ff3.h"

int pif_plugin_ff3_encrypt(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data)
{
    uint32_t i00 = pif_plugin_meta_get__help__ff3_i00(headers);
    uint32_t i01 = pif_plugin_meta_get__help__ff3_i01(headers);
    uint32_t i02 = pif_plugin_meta_get__help__ff3_i02(headers);
    uint32_t i03 = pif_plugin_meta_get__help__ff3_i03(headers);

    uint128_t ff3_input = {i00, i01, i02, i03};
    uint128_t ff3_output = ff3_encrypt(ff3_input);

    pif_plugin_meta_set__help__ff3_o00(headers, ff3_output.w0);
    pif_plugin_meta_set__help__ff3_o01(headers, ff3_output.w1);
    pif_plugin_meta_set__help__ff3_o02(headers, ff3_output.w2);
    pif_plugin_meta_set__help__ff3_o03(headers, ff3_output.w3);

    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_ff3_decrypt(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data)
{
    uint32_t i00 = pif_plugin_meta_get__help__ff3_i00(headers);
    uint32_t i01 = pif_plugin_meta_get__help__ff3_i01(headers);
    uint32_t i02 = pif_plugin_meta_get__help__ff3_i02(headers);
    uint32_t i03 = pif_plugin_meta_get__help__ff3_i03(headers);

    uint128_t ff3_input = {i00, i01, i02, i03};
    uint128_t ff3_output = ff3_decrypt(ff3_input);

    pif_plugin_meta_set__help__ff3_o00(headers, ff3_output.w0);
    pif_plugin_meta_set__help__ff3_o01(headers, ff3_output.w1);
    pif_plugin_meta_set__help__ff3_o02(headers, ff3_output.w2);
    pif_plugin_meta_set__help__ff3_o03(headers, ff3_output.w3);

    return PIF_PLUGIN_RETURN_FORWARD;
}