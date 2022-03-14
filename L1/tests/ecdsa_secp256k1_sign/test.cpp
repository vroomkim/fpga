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

#define S_DEBUG
#include "xf_security/ecdsa_secp256k1.hpp"
//#include "math.h"
#ifndef __SYNTHESIS__
#include <iostream>
#endif

xf::security::ecdsaSecp256k1<256> processor;

void test(ap_uint<256> hash, ap_uint<256> k, ap_uint<256> privateKey, ap_uint<256>& r, ap_uint<256>& s, bool& kValid) {
    processor.init();
    kValid = processor.sign(hash, k, privateKey, r, s);
#ifndef __SYNTHESIS__
    std::cout << std::hex << "*** N ***\n" << processor.n << std::endl;
    std::cout << std::hex << "*** N/2 ***\n" << processor.n/2 << std::endl;
    std::cout << std::hex << "*** C(N) ***\n" << ~processor.n+1 << std::endl;
    std::cout << std::hex << "*** P - N ***\n" << processor.p - processor.n << std::endl;
    std::cout << std::hex << "*** FE (P - N) ***\n" << processor.p - processor.n << std::endl;
#endif
}

#if 0
/**
 * @brief Calculate square root of u/v.
 *
 * @param u Input u of u/v to calculate square root.
 * @param v Input u of u/v to calculate square root.
 * @param sqrt_a Square root of u/v.
 */
bool modularSqrt(ap_uint<256> base, int recid, ap_uint<256>& sqrt_a) {
    ap_uint<256> rMod = ap_uint<256>("0x01000007A2000E90A1");		// (1<<(2*L))%m, (1<<512)%p
    ap_uint<256> p_1_d4 = ap_uint<256>("0x03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C");

    sqrt_a = xf::security::internal::modularExp<256, 256>(base, p_1_d4, processor.p, rMod);

#ifndef __SYNTHESIS__
std::cout << std::hex << "SQ : " << sqrt_a << "\n";
#endif
    if ( (sqrt_a&1) ^ (recid&1)) {
	    sqrt_a = xf::security::internal::subMod<256>(0, sqrt_a, processor.p);
#ifndef __SYNTHESIS__
std::cout << std::hex << "NSQ: " << sqrt_a << "\n";
#endif
    }
#if 0
    ap_uint<256> uv = xf::security::internal::productMod<256>(u, v, p);
    ap_uint<256> v2 = xf::security::internal::productMod<256>(v, v, p);
    ap_uint<256> v4 = xf::security::internal::productMod<256>(v2, v2, p);
    ap_uint<256> uv3 = xf::security::internal::productMod<256>(uv, v2, p);
    ap_uint<256> uv7 = xf::security::internal::productMod<256>(uv3, v4, p);

    ap_uint<256> tmp = xf::security::internal::modularExp<256, 256>(base, p_5_d8, p, rMod);

    tmp = xf::security::internal::productMod<256>(uv3, tmp, p);
    ap_uint<256> tmp_2 = xf::security::internal::productMod<256>(tmp, tmp, p);
    tmp_2 = xf::security::internal::productMod<256>(tmp_2, v, p);
    if (tmp_2 == u) {
        sqrt_a = tmp;
        return true;
    } else if (xf::security::internal::addMod<256>(tmp_2, u, p) == 0) {
        sqrt_a = xf::security::internal::productMod<256>(tmp, sqrt_n1, p);
        return true;
    } else {
        return false;
    }
#endif
    return true;
}

/**
 * @brief Decompress a point (Px, Py) from its compressed representation.
 *
 * @param P compressed point representation.
 * @param Px X coordinate of the point.
 * @param Py Y coordinate of the point.
 */
bool decompress(ap_uint<256> sigr, int recid, ap_uint<256>& sqrt_y2) {
    ap_uint<256> p_minus_n = ap_uint<256>("0x014551231950B75FC4402DA1722FC9BAEE");

    if (recid & 2) {
	    if ( sigr >= p_minus_n)
		    return false;
	    sigr += processor.n;
    }

    ap_uint<256> tx1 = processor.productMod_p(sigr, sigr);
#ifndef __SYNTHESIS__
    std::cout << std::hex << "r^2: " << tx1 << "\n";
#endif
    tx1 = processor.productMod_p(tx1, sigr);
#ifndef __SYNTHESIS__
    std::cout << std::hex << "r^3: " << tx1 << "\n";
#endif

    ap_uint<256> tx2 = processor.productMod_p(sigr, processor.a);
    tx2 = xf::security::internal::addMod<256>(tx2, processor.b, processor.p);

    ap_uint<256> tx3 = xf::security::internal::addMod<256>(tx2, tx1, processor.p);
#ifndef __SYNTHESIS__
    std::cout << std::hex << "Y^2: " << tx3 << "\n";
#endif

    bool valid = modularSqrt(tx3, recid, sqrt_y2);
#ifndef __SYNTHESIS__
    std::cout << std::hex << "Y  : " << sqrt_y2 << "\n";
#endif

#if 0
    if (P[255] == sqrt_x[0]) {
        sigr = sqrt_x;
    } else {
        sigr = p - sqrt_x;
    }
#endif
    return valid;
}
#endif


#define OP_SIGN         0
#define OP_VERIFY       1
#define OP_RECOVER_VERIFY       2

#define IN_LEN  5
#define IN_V_LEN  5
//#define OPCODE        0
#define IN_M    0
#define IN_K    1
#define IN_PK   2

#define IN_R    1
#define IN_S    2
#define IN_PX   3
#define IN_PY   4

#define OUT_LEN 3
#define OUT_V_LEN 1
#define OUT_KV  0
#define OUT_R   1
#define OUT_S   2

bool Secp256K1Kernel_verify1(int opcode, ap_uint<256> *inp, ap_uint<256> *outp)
{
//	processor.init();
	bool kV;
	ap_uint<256> h, k, p, r, s;
//	int opcode = inp[OPCODE];
	ap_uint<256> px, py;

	h = inp[IN_M];

	r = inp[IN_R];
	s = inp[IN_S];
	px = inp[IN_PX];
	if (opcode  == OP_VERIFY)
		py = inp[IN_PY];
	kV = processor.verify(r, s, h, px, py, V_RECOVER);

#if 0
	/* for test */
	processor.recover(r, s, h, px, py);
	std::cout << std::hex << "rPx: " << px << "\n";
	std::cout << std::hex << "rPy: " << py << "\n";
#endif
	return kV;
}

#ifndef __SYNTHESIS__
int main() {
    ap_uint<256> m = ap_uint<256>("0x4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a");
    ap_uint<256> privateKey = ap_uint<256>("0xebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f");
    ap_uint<256> k = ap_uint<256>("0x49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a");
    ap_uint<256> gold_r = ap_uint<256>("0x241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795");
    ap_uint<256> gold_s = ap_uint<256>("0x021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e");
    ap_uint<256> Qx = ap_uint<256>("0x779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd");
    ap_uint<256> Qy = ap_uint<256>("0xe94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f");

    ap_uint<256> y0, y1, y2, y3;
    int recid = 0;
    int opcode;
    ap_uint<256> inp[IN_V_LEN], outp[OUT_V_LEN];
    bool kValid;

//    test(m, k, privateKey, r, s, kValid);

    processor.init();
#ifdef S_DEBUG
    std::cout << std::hex << processor.p << "\n" << (processor.p+1)/4 << "\n" ;

    std::cout << std::hex << "R:  " << gold_r << "\n";
    std::cout << std::hex << "Qx: " << Qx << "\n";
    std::cout << std::hex << "Qy: " << Qy << "\n";
#endif

    opcode = OP_RECOVER_VERIFY;
    inp[IN_M] = m;
    inp[IN_R] = gold_r;
    inp[IN_S] = gold_s;
    inp[IN_PX] = recid;

    kValid = Secp256K1Kernel_verify1(opcode, inp, outp);
    std::cout << std::hex << "kValid: " << kValid << "\n";
    outp[OUT_KV] = ap_uint<256> (kValid);

    std::cout << std::hex << "\n********  TEST AGAIN *******" << "\n";
#if 1
    if (processor.decompress(gold_r, y0, 0) == 0)
	    // return 0;
	    std::cout << "Y0 false\n";
    if (processor.decompress(gold_r, y1, 1) == 0)
	    // return 0;
	    std::cout << "Y1 false\n";
    if (processor.decompress(gold_r, y2, 2) == 0)
	    // return 0;
	    std::cout << "Y2 false\n";
    if (processor.decompress(gold_r, y3, 3) == 0)
	    // return 0;
	    std::cout << "Y3 false\n";

#ifdef S_DEBUG
    std::cout << std::hex << "Y0: " << y0 << "\n";
    std::cout << std::hex << "Y1: " << y1 << "\n";
    std::cout << std::hex << "Y2: " << y2 << "\n";
    std::cout << std::hex << "Y3: " << y3 << "\n";
    std::cout << std::hex << "Qx: " << Qx << "\n";
    std::cout << std::hex << "Qy: " << Qy << "\n";
#endif


    ap_uint<256> rInv = xf::security::internal::modularInv<256>(gold_r, processor.n);
#ifdef S_DEBUG
    std::cout << std::hex << "RN: " << rInv << "\n";
#endif

    ap_uint<256> tu1 = processor.productMod_n(rInv, m);
#ifdef S_DEBUG
    std::cout << std::hex << "m:  " << m << "\n";
    std::cout << std::hex << "U1: " << tu1 << "\n";
#endif

    ap_uint<256> u1 = xf::security::internal::subMod<256>(0, tu1, processor.n);
#ifdef S_DEBUG
    std::cout << std::hex << "NU1:" << u1 << "\n";
#endif

    ap_uint<256> u2 = processor.productMod_n(rInv, gold_s);
#ifdef S_DEBUG
    std::cout << std::hex << "U2: " << u2 << "\n";
#endif

    ap_uint<256> t1x, t1y, t2x, t2y, Px, Py;
    processor.dotProductNAFPrecomputeJacobian(u1, t1x, t1y);  // t1x, t1y = G*u1
    processor.dotProductJacobian(gold_r, y0, u2, t2x, t2y);  // t2x, t2y = [xj]*u2
    processor.add(t1x, t1y, t2x, t2y, Px, Py);
#ifdef S_DEBUG
    std::cout << std::hex << "Px: " << Px << "\n";
    std::cout << std::hex << "Py: " << Py << "\n";

    std::cout << std::hex << "\nPmN:" << processor.p - processor.n << "\n";
#endif
#endif

#if 0
    ap_uint<256> sqrtV, conv;
    double convD = (double) m;
    conv = (ap_uint<256>) convD;
    sqrtV = (ap_uint<256>) std::sqrt((double)m);
    std::cout << std::hex << m << "\n" << sqrtV << "\n" << sqrtV*sqrtV << std::endl;
    std::cout << std::hex << convD << "\n" << conv << "\n" ;
    ap_uint<256> p = ap_uint<256>("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED");
    std::cout << std::hex << p << "\n" << (p-5)/8 << "\n" ;
    p = ap_uint<256>("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    std::cout << std::hex << p << "\n" << (p-5)/8 << "\n" ;
    std::cout << std::hex << p << "\n" << (p+1)/4 << "\n" ;
    ap_uint<513> bigNum = ap_uint<513>("0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    std::cout << std::hex << "****\n" << bigNum << "\n" << bigNum % p << "\n" ;


    if (gold_r != r || gold_s != s) {
        std::cout << std::hex << "r:" << r << std::endl;
        std::cout << std::hex << "s:" << s << std::endl;
        return 1;
    } else {
	std::cout << std::dec << "kValid:" << kValid << std::endl;
        return 0;
    }
#endif
}
#endif
