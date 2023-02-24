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

#define FF3_ROUNDS 8

#define FF3_TWEAK_L 32w0x00000000
#define FF3_TWEAK_R 32w0xedcba9f0
