## Introduction

LISPP is a **LI**ghtweight **S**tateless **P**rivacy **P**rotection system that 
uses Format-Preserving Encryption (FPE) for network layer privacy protection. 
FPE enables the encryption of arbitrary-length fields in a manner that 
allows the replacement of a protocol field with its encrypted version of the same size. 
The difference between the FPE and classical block ciphers like AES is shown in Figure 1.

![figure1](https://github.com/marko-micovic/lispp/assets/126237332/9b0f1d2e-a30d-47b7-9007-afd45e790ace)

**Figure 1.** *(**a**) Block cipher encryption vs (**b**) Format-preserving encryption of plaintext of length l.*
<br>
<br>

LISPP uses the FF3-1 FPE algorithm, recently adopted by NIST 
([NIST SP 800-38G Rev. 1](https://csrc.nist.gov/pubs/sp/800/38/g/r1/ipd)), 
although other FPE algorithms can be used as well. 
LISPP processes packets at the network boundary. 
It encrypts the host part of the source IP address and source port in packets that exit the protected network and 
decrypts them in the opposite direction. 
In the egress direction, 
the host part of the original source IP address from the protected network (designated as P—plaintext in Figure 2) and 
source port are replaced with their encrypted values (designated as C—ciphertext and new port number). 
The network part of the IP address (Net) remains the same, ensuring proper packet routing back to the protected network. 
In the ingress direction, decryption using the same key is performed, 
restoring addresses and ports to their original values.

![figure2](https://github.com/marko-micovic/lispp/assets/126237332/610c3dbf-c74a-4c81-b688-cf985ed3a0cd)

**Figure 2.** *LISPP header field modification at the network boundary.*
<br>
<br>

This way, when the user from the protected network communicates with the external devices, 
external devices can only know the user’s location (network part of the IP address) 
but not the exact user’s original source IP address. 
The encrypted version of the plaintext changes in every session 
because the source port takes a new value in subsequent TCP or UDP sessions. 
Every time a client from the protected network accesses the same external server, 
the client will appear to have a different IP address with a high probability, 
which is ensured by using encryption algorithms. 

The encryption of the packet header elements using FPE in LISPP is depicted in Figure 3.
The host part of the source IP address and source port are concatenated and encrypted using a secret key. 
Since FPE is used, *n* bits of plaintext are encrypted into exactly *n* bits of the ciphertext 
regardless of the number of bits *n*. 
In that case, it is possible to obtain a reversible one-to-one mapping between 
the (src IP, src port) and (enc(src IP), enc(src port)) pairs 
regardless of the network mask size and IP version. 
It is possible to achieve fully transparent and stateless operation in both directions.

![figure3](https://github.com/marko-micovic/lispp/assets/126237332/cbcc9f85-3384-4737-af4b-693dc802f8bf)

**Figure 3.** *LISPP address and port encryption.*
<br>
<br>
 
LISPP is so far developed for 
[Netronome Agilio](https://www.netronome.com/products/agilio-cx/) 
[NFP-4000 series](https://www.netronome.com/static/app/img/products/silicon-solutions/WP_NFP4000_TOO.pdf) 
SmartNIC and is implemented in three versions:
1. Pure P4 Implementation
2. Packet Control and FF3-1 in P4 and AES in Micro-C Implementation
3. Only Packet Control in P4 and Entire FF3-1 in Micro-C implementation

You can find more details about LISPP operation and performance evaluation in our paper:
 
Mićović, M.; Radenković, U.; Vuletić, P. 
Network Layer Privacy Protection Using Format-Preserving Encryption. 
Electronics 2023, 12, 4800. 
[https://doi.org/10.3390/electronics12234800](https://doi.org/10.3390/electronics12234800)

If you use the LISPP code or principles of operation in your research, please cite this paper.
