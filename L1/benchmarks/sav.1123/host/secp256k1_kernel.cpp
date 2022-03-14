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

extern "C" void Secp256K1Kernel(
   	ap_uint<256> inp[IN_LEN],
       	ap_uint<256> outp[OUT_LEN])
	{
#if 1
#pragma HLS INTERFACE m_axi offset = slave latency = 32 num_write_outstanding = 1 num_read_outstanding = \
    32 max_write_burst_length = 2 max_read_burst_length = 16 bundle = gmem0 port = inp
#pragma HLS INTERFACE m_axi offset = slave latency = 32 num_write_outstanding = 32 num_read_outstanding = \
    1 max_write_burst_length = 16 max_read_burst_length = 2 bundle = gmem1 port = outp
#else
#pragma HLS INTERFACE m_axi offset = slave latency = 32 1 num_read_outstanding = \
	32 max_read_burst_length = 16 bundle = gmem0 port = inp
#pragma HLS INTERFACE m_axi offset = slave latency = 32 num_write_outstanding = \
	32 max_write_burst_length = 16 bundle = gmem1 port = outp
#endif
#pragma HLS INTERFACE s_axilite port = inp bundle = control
#pragma HLS INTERFACE s_axilite port = outp bundle = control
#pragma HLS INTERFACE s_axilite port = return bundle = control

	xf::security::ecdsaSecp256k1<256> processor;
//	processor.init();
	bool kV;
	ap_uint<256> h, k, p, r, s;

	h = inp[IN_M];
	if (inp[OPCODE] == OP_SIGN) {
		k = inp[IN_K];
		p = inp[IN_PK];
		kV = processor.sign(h, k, p, r, s);
		outp[OUT_R] = r;
		outp[OUT_S] = s;
	} else if (inp[OPCODE] == OP_VERIFY) {
		ap_uint<256> px, py;
		r = inp[IN_R];
		s = inp[IN_S];
		px = inp[IN_PX];
		py = inp[IN_PY];
		kV = processor.verify(r, s, h, px, py);
	}
	else {
		kV = false;
	}
	outp[OUT_KV] = ap_uint<256> (kV);
}
