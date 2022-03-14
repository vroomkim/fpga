/*
 * Copyright 2019 Xilinx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "secp256k1_kernel.hpp"

xf::security::ecdsaSecp256k1<256> processor;
    /**
     * @brief verifying function.
     * It will return true if verified, otherwise false.
     *
     * @param r part of signing pair {r, s}
     * @param s part of signing pair {r, s}
     * @param hash Digest value of message to be signed.
     * @param Px X coordinate of public key point P.
     * @param Py Y coordinate of public key point P.
     */
#define HashW 256
    bool verify(ap_uint<256> r, ap_uint<256> s, ap_uint<HashW> hash, ap_uint<256> Px, ap_uint<256> Py, int mode) {
#ifdef LOGIC_NUM_TEST
#endif
#ifdef SET_FUNC_LIMIT
#pragma HLS allocation function instances = processor.add limit = 1
#pragma HLS allocation function instances = processor.productMod_p limit = 1
#pragma HLS allocation function instances = processor.dotProductNAFPrecomputeJacobian limit = 1
#pragma HLS allocation function instances = processor.dotProductJacobian limit = 1
#endif
        if (r == 0 || r >= processor.n || s == 0 || s >= processor.n) {
            return false;
        } else {
            ap_uint<256> z;
            if (HashW >= 256) {
                z = hash.range(HashW - 1, HashW - 256);
            } else {
                z = hash;
            }
            if (z >= processor.n) {
                z -= processor.n;
            }

            ap_uint<256> t1x, t1y, t2x, t2y;
//	    if (mode == V_RECOVER) {
//		recover(r, s, z, Px, Py);
//	    }

//            ap_uint<256> sInv = xf::security::internal::modularInv<256>(s, processor.n);
            ap_uint<256> sInv = z;

//            ap_uint<256> u1 = productMod_n(sInv, z);
            ap_uint<256> u1 = r;
//            ap_uint<256> u2 = productMod_n(sInv, r);

//            this->dotProductNAFPrecomputeJacobian(u1, t1x, t1y);
//            this->dotProductJacobian(Px, Py, u2, t2x, t2y);


	    t2x = ap_uint<256>("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
	    t2y = t2x;
            ap_uint<256> x, y;
            processor.add(u1, u1, t2x, t2y, t1x, t1y); // for test
            processor.add(t1x, t1y, t2x, t2y, x, y);

            if (x == 0 && y == 0) {
                return false;
            } else {
                if (r == x) {
                    return true;
                } else {
                    return false;
                }
            }
        }
    }

extern "C" void Secp256K1Kernel_verify1(
//	int opcode,
   	ap_uint<256> inp[5],
       	ap_uint<256> outp[1])
{
#pragma HLS INTERFACE m_axi offset = slave latency = 32 num_write_outstanding = 1 num_read_outstanding = \
    32 max_write_burst_length = 2 max_read_burst_length = 16 bundle = gmem0 port = inp
#pragma HLS INTERFACE m_axi offset = slave latency = 32 num_write_outstanding = 32 num_read_outstanding = \
    1 max_write_burst_length = 16 max_read_burst_length = 2 bundle = gmem1 port = outp
//#pragma HLS INTERFACE s_axilite port = inp bundle = control
//#pragma HLS INTERFACE s_axilite port = outp bundle = control
//#pragma HLS INTERFACE s_axilite port = return bundle = control

	bool kV;
//	processor.init();
	ap_uint<256> h, k, p, r, s;
//	int opcode = inp[OPCODE];

	h = inp[IN_M];
	ap_uint<256> px, py;
	r = inp[IN_R];
	s = inp[IN_S];
	px = inp[IN_PX];
	py = inp[IN_PY];
	kV = verify(r, s, h, px, py, (inp[0] == OP_VERIFY) ? V_ONLY : V_RECOVER);
	outp[OUT_KV] = ap_uint<256> (kV);
}
