// *****************************************************************************
// Configuration
// *****************************************************************************

#define IP_VERSION 4
#define TRANSPORT_PROTOCOL 0x11

// W_N = len(ff3_input)
#define W_N 24
// W_U = ceil(W_N / 2)
#define W_U 12
// W_V = W_N - W_U
#define W_V 12

#define FF3_ROUNDS  8
#define AES_ROUNDS 10

#define FF3_TWEAK_L 32w0x00000000
#define FF3_TWEAK_R 32w0xedcba9f0

// https://www.cryptool.org/en/cto/aes-step-by-step
#define AES_KEY_00_127_096 0x01010101
#define AES_KEY_00_095_064 0x02020202
#define AES_KEY_00_063_032 0x03030303
#define AES_KEY_00_031_000 0x04040404

#define AES_KEY_01_127_096 0xf2f3f3f3
#define AES_KEY_01_095_064 0xf0f1f1f1
#define AES_KEY_01_063_032 0xf3f2f2f2
#define AES_KEY_01_031_000 0xf7f6f6f6

#define AES_KEY_02_127_096 0xb2b1b19b
#define AES_KEY_02_095_064 0x4240406a
#define AES_KEY_02_063_032 0xb1b2b298
#define AES_KEY_02_031_000 0x4644446e

#define AES_KEY_03_127_096 0xadaa2ec1
#define AES_KEY_03_095_064 0xefea6eab
#define AES_KEY_03_063_032 0x5e58dc33
#define AES_KEY_03_031_000 0x181c985d

#define AES_KEY_04_127_096 0x39ec626c
#define AES_KEY_04_095_064 0xd6060cc7
#define AES_KEY_04_063_032 0x885ed0f4
#define AES_KEY_04_031_000 0x904248a9

#define AES_KEY_05_127_096 0x05beb10c
#define AES_KEY_05_095_064 0xd3b8bdcb
#define AES_KEY_05_063_032 0x5be66d3f
#define AES_KEY_05_031_000 0xcba42596

#define AES_KEY_06_127_096 0x6c812113
#define AES_KEY_06_095_064 0xbf399cd8
#define AES_KEY_06_063_032 0xe4dff1e7
#define AES_KEY_06_031_000 0x2f7bd471

#define AES_KEY_07_127_096 0x0dc98206
#define AES_KEY_07_095_064 0xb2f01ede
#define AES_KEY_07_063_032 0x562fef39
#define AES_KEY_07_031_000 0x79543b48

#define AES_KEY_08_127_096 0xad2bd0b0
#define AES_KEY_08_095_064 0x1fdbce6e
#define AES_KEY_08_063_032 0x49f42157
#define AES_KEY_08_031_000 0x30a01a1f

#define AES_KEY_09_127_096 0x568910b4
#define AES_KEY_09_095_064 0x4952deda
#define AES_KEY_09_063_032 0x00a6ff8d
#define AES_KEY_09_031_000 0x3006e592

#define AES_KEY_10_127_096 0x0f505fb0
#define AES_KEY_10_095_064 0x4602816a
#define AES_KEY_10_063_032 0x46a47ee7
#define AES_KEY_10_031_000 0x76a29b75
