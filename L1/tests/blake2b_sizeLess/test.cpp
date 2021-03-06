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
#include "xf_security/blake2b.hpp"

void test(hls::stream<ap_uint<64> >& msg_strm,
          hls::stream<ap_uint<6> >& msg_len_strm,
          hls::stream<ap_uint<512> >& key_strm,
          hls::stream<ap_uint<8> >& key_len_strm,
          hls::stream<ap_uint<8> >& out_len_strm,
          hls::stream<ap_uint<512> >& digest_strm,
          hls::stream<bool>& end_digest_strm) {
    xf::security::blake2b(msg_strm, msg_len_strm, key_strm, key_len_strm, out_len_strm, digest_strm, end_digest_strm);
}
