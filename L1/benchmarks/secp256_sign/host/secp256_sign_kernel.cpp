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

#include "secp256_sign_kernel.hpp"

extern "C" void Secp256SignKernel(
   	ap_uint<256> inp[3],	// hash, key, private key
       	ap_uint<256> outp[3]) 	// R, S, kValid
	{
#pragma HLS INTERFACE m_axi offset = slave latency = 32 num_write_outstanding = 1 num_read_outstanding = \
    32 max_write_burst_length = 2 max_read_burst_length = 16 bundle = gmem0 port = inp
#pragma HLS INTERFACE m_axi offset = slave latency = 32 num_write_outstanding = 32 num_read_outstanding = \
    1 max_write_burst_length = 16 max_read_burst_length = 2 bundle = gmem1 port = outp
#pragma HLS INTERFACE s_axilite port = inp bundle = control
#pragma HLS INTERFACE s_axilite port = outp bundle = control
#pragma HLS INTERFACE s_axilite port = return bundle = control

	xf::security::ecdsaSecp256k1<256> processor;
	processor.init();
	bool kV;
	ap_uint<256> h, k, p, r, s;

	h = inp[0];
	k = inp[1];
	p = inp[2];
	kV = processor.sign(h, k, p, r, s);
	kV = processor.verify(h, k, p, r, s);
	outp[0] = r;
	outp[1] = s;
	outp[2] = ap_uint<256> (kV);
}
