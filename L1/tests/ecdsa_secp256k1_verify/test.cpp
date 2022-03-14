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

#include "test.hpp"
#include "xf_security/ecdsa_secp256k1.hpp"

void test(ap_uint<256> hash, ap_uint<256> Qx, ap_uint<256> Qy, ap_uint<256> r, ap_uint<256> s, bool& ifValid) {
    xf::security::ecdsaSecp256k1<256> processor;
    processor.init();
    ifValid = processor.verify(r, s, hash, Qx, Qy);
}
