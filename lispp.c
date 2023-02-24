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

#include "lispp-aes.h"

int pif_plugin_aes_encrypt(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data)
{
    uint32_t r0 = pif_plugin_meta_get__aes__t0(headers);
    uint32_t r1 = pif_plugin_meta_get__aes__t1(headers);
    uint32_t r2 = pif_plugin_meta_get__aes__t2(headers);
    uint32_t r3 = pif_plugin_meta_get__aes__t3(headers);

    uint128_t aes_state = { r0, r1, r2, r3 };

    aes_state = aes_encrypt(aes_state);

    r0 = aes_state.w0;
    r1 = aes_state.w1;
    r2 = aes_state.w2;
    r3 = aes_state.w3;

    pif_plugin_meta_set__aes__r0(headers, r0);
    pif_plugin_meta_set__aes__r1(headers, r1);
    pif_plugin_meta_set__aes__r2(headers, r2);
    pif_plugin_meta_set__aes__r3(headers, r3);

    return PIF_PLUGIN_RETURN_FORWARD;
}
