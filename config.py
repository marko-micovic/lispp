"""
    LISPP - Lightweight stateless network layer privacy protection system
    Copyright (C) 2023 Marko Micovic, Uros Radenkovic, Pavle Vuletic, 
                       University of Belgrade, School of Electrical Engineering

    This file is part of LISPP.

    LISPP is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    LISPP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with LISPP. If not, see <https://www.gnu.org/licenses/>.
"""

import codecs
import binascii
import sys

from math import ceil

# pip install aeskeyschedule
from aeskeyschedule import key_schedule

# usage:
# python config.py <ip-version> <transport-protocol> <ff3-aes-key> <ff3-tweak> <ff3-input-length>
# python config.py 4 tcp 04040404030303030202020201010101 0000000FEDCBA9 24
# python config.py 6 tcp 04040404030303030202020201010101 0000000FEDCBA9 24

delimiter = "// *****************************************************************************"

ff3_config_p4 = []

ff3_config_p4.append(delimiter)
ff3_config_p4.append("// Configuration")
ff3_config_p4.append(delimiter)
ff3_config_p4.append("")

try:
    ip_version_target = int(sys.argv[1])
    if ip_version_target == 4 or ip_version_target == 6:
        ff3_config_p4.append(f"#define IP_VERSION {ip_version_target}")
    else:
        print("!!! Invalid IP version target !!!")
        sys.exit()
except:
    sys.exit()

try:
    transport_protocol_target = sys.argv[2]
    if transport_protocol_target == "tcp":
        ff3_config_p4.append(f"#define TRANSPORT_PROTOCOL 0x06")
    elif transport_protocol_target == "udp":
        ff3_config_p4.append(f"#define TRANSPORT_PROTOCOL 0x11")
    else:
        print("!!! Invalid transport protocol target !!!")
        sys.exit()
except:
    sys.exit()

ff3_config_p4.append("")

try:
    ff3_input_length_string = sys.argv[5]
    ff3_input_length = int(ff3_input_length_string)
    if 16 <= ff3_input_length <= 128:
        w_u = ceil(ff3_input_length / 2)
        w_v = ff3_input_length - w_u
        ff3_config_p4.append(f"// W_N = len(ff3_input)")
        ff3_config_p4.append(f"#define W_N {ff3_input_length}")
        ff3_config_p4.append(f"// W_U = ceil(W_N / 2)")
        ff3_config_p4.append(f"#define W_U {w_u}")
        ff3_config_p4.append(f"// W_V = W_N - W_U")
        ff3_config_p4.append(f"#define W_V {w_v}")
        ff3_config_p4.append("")
    else:
        print("!!! Invalid FF3-1 input length !!!")
        sys.exit()
except:
    print("!!! Invalid FF3-1 input format !!!")
    sys.exit()

ff3_config_p4.append("#define FF3_ROUNDS  8")
ff3_config_p4.append("#define AES_ROUNDS 10")
ff3_config_p4.append("")

try:
    ff3_tweak_string = sys.argv[4]
    if len(ff3_tweak_string) == 14:
        ff3_tweak = codecs.decode(ff3_tweak_string, "hex_codec")
        ff3_tweak_l = f"{ff3_tweak.hex()[0:7]}0"
        ff3_tweak_r = f"{ff3_tweak.hex()[8:14]}{ff3_tweak.hex()[7:8]}0"
        # tl = tweak[55:28] ++ 4w0
        ff3_config_p4.append(f"#define FF3_TWEAK_L 32w0x{ff3_tweak_l}")
        # tweak[23:0] ++ tweak[27:24] ++ 4w0
        ff3_config_p4.append(f"#define FF3_TWEAK_R 32w0x{ff3_tweak_r}")
        ff3_config_p4.append("")
    else:
        print("!!! Invalid FF3-1 tweak length !!!")
        sys.exit()
except:
    print("!!! Invalid FF3-1 tweak format !!!")
    sys.exit()

ff3_config_p4.append("// https://www.cryptool.org/en/cto/aes-step-by-step")

try:
    ff3_aes_key_string = sys.argv[3]
    if len(ff3_aes_key_string) == 32:
        ff3_aes_key = codecs.decode(ff3_aes_key_string, "hex_codec")
        # key has to be reversed because
        # FF3-1 in the step (4) part (iii) reverse AES key (REVB(K))
        # but P4 as a language is not best suited for such an operation
        # (FF3-1 does not change AES key, it reverses same key every time)
        ff3_aes_key_reversed = bytes(reversed(ff3_aes_key))
        ff3_aes_key_expanded = key_schedule(ff3_aes_key_reversed)
        ff3_aes_round = 0
        for ff3_aes_subkey in ff3_aes_key_expanded:
            for i in range(4):
                msb = f"{((4 - i) * 32 - 1):03d}"
                lsb = f"{((4 - i) * 32 - 32):03d}"
                subkey = f"{ff3_aes_subkey[i * 4: (i + 1) * 4].hex()}"
                macro = f"#define AES_KEY_{ff3_aes_round:02d}_{msb}_{lsb} 0x{subkey}"
                ff3_config_p4.append(macro)
            ff3_aes_round += 1
            if ff3_aes_round != 11:
                ff3_config_p4.append("")
    else:
        print("!!! Invalid FF3-1 AES key length !!!")
        sys.exit()
except binascii.Error:
    print("!!! Invalid FF3-1 AES key format !!!")
    sys.exit()

with open('config.p4.h', 'w') as f_p4:
    for line in ff3_config_p4:
        f_p4.write(line)
        f_p4.write('\n')
