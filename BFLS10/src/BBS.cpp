#include "../include/BBS.h"

csprng rng_BBS;
gmp_randstate_t state_BBS;
mpz_class q = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001_mpz;
vector<ECP> lists_A;

GSK_sig UKGen(mpz_class gamma) {
    initState(state_BBS);
    GSK_sig gskSig;
    gskSig.x = rand_mpz(state_BBS);
    ECP_generator(&gskSig.A);
    mpz_class exp = (gamma + gskSig.x) % q;
    exp = invert_mpz(exp, q);
    ECP_mul(gskSig.A, exp);
    lists_A.push_back(gskSig.A);
    return gskSig;
}

void GKGen(GMSK &gmsk, GPK &gpk, vector<ECP> PKs, mpz_class gamma) {
    ECP_generator(&gpk.g_1);
    ECP2_generator(&gpk.g_2);

    ECP2_copy(&gpk.w, &gpk.g_2);
    ECP2_mul(gpk.w, gamma);

    // Randomly choose h, ksi1, and ksi2; compute u = h^(1/ksi1), v = h^(1/ksi2).
    // This satisfies the BBS requirements for these parameters.
    gmsk.ksi_1 = rand_mpz(state_BBS);
    gmsk.ksi_2 = rand_mpz(state_BBS);
    mpz_class ksi1_inv = invert_mpz(gmsk.ksi_1, q);
    mpz_class ksi2_inv = invert_mpz(gmsk.ksi_2, q);
    gpk.h = randECP(rng_BBS);
    ECP_copy(&gpk.u, &gpk.h);
    ECP_copy(&gpk.v, &gpk.h);
    ECP_mul(gpk.u, ksi1_inv);  // u^xi1 = h
    ECP_mul(gpk.v, ksi2_inv);  // v^xi2 = h

    // 为vector<ECP> PKs 中的 公钥分别生成证书，由于BFLS10中实际上并未用到这些证书，这里不实现
}


mpz_class H(mpz_class M, ECP T1, ECP T2, ECP T3, ECP R1, ECP R2, FP12 R3, ECP R4, ECP R5) {
    octet hash = getOctet(49);
    // m
    octet oct_M = getOctet(49);
    oct_M = mpzToOctet(M);
    concatOctet(&hash, &oct_M);
    free(oct_M.val);
    // T1 , T2 , T3
    octet oct_T1 = getOctet(49);
    ECP_toOctet(&oct_T1, &T1, true);
    concatOctet(&hash, &oct_T1);
    free(oct_T1.val);
    octet oct_T2 = getOctet(49);
    ECP_toOctet(&oct_T2, &T2, true);
    concatOctet(&hash, &oct_T2);
    free(oct_T2.val);
    octet oct_T3 = getOctet(49);
    ECP_toOctet(&oct_T3, &T3, true);
    concatOctet(&hash, &oct_T3);
    free(oct_T3.val);
    // R1 , R2 , R3 , R4 , R5
    octet oct_R1 = getOctet(49);
    ECP_toOctet(&oct_R1, &R1, true);
    concatOctet(&hash, &oct_R1);
    free(oct_R1.val);
    octet oct_R2 = getOctet(49);
    ECP_toOctet(&oct_R2, &R2, true);
    concatOctet(&hash, &oct_R2);
    free(oct_R2.val);
    octet oct_fp12 = getOctet(576);
    FP12_toOctet(&oct_fp12, &R3);
    concatOctet(&hash, &oct_fp12);
    free(oct_fp12.val);
    octet oct_R4 = getOctet(49);
    ECP_toOctet(&oct_R4, &R4, true);
    concatOctet(&hash, &oct_R4);
    free(oct_R4.val);
    octet oct_R5 = getOctet(49);
    ECP_toOctet(&oct_R5, &R5, true);
    concatOctet(&hash, &oct_R5);
    free(oct_R5.val);
    BIG order, result;
    BIG_rcopy(order, CURVE_Order);
    hashZp256(result, &hash, order);
    free(hash.val);

    return BIG_to_mpz(result);
}

Sigma_BBS GSig(GSK_sig gskSig, mpz_class M,GPK gpk) {
    mpz_class alpha = rand_mpz(state_BBS);
    mpz_class beta = rand_mpz(state_BBS);
    ECP T1, T2, T3;
    ECP_copy(&T1, &gpk.u);
    ECP_copy(&T2, &gpk.v);
    ECP_copy(&T3, &gpk.h);
    ECP_mul(T1, alpha);
    ECP_mul(T2, beta);
    ECP_mul(T3, ((alpha + beta) % q));
    ECP_add(&T3, &gskSig.A);

    // compute R1,...,R5
    mpz_class r_alpha = rand_mpz(state_BBS);
    mpz_class r_beta = rand_mpz(state_BBS);
    mpz_class r_x = rand_mpz(state_BBS);
    mpz_class r_delta1 = rand_mpz(state_BBS);
    mpz_class r_delta2 = rand_mpz(state_BBS);

    ECP R1, R2, R4, R5, temp_u, temp_v;
    ECP_copy(&R1, &gpk.u);
    ECP_copy(&R2, &gpk.v);
    ECP_mul(R1, r_alpha);
    ECP_mul(R2, r_beta);

    ECP_copy(&R4, &T1);
    ECP_mul(R4, r_x);
    ECP_copy(&temp_u, &gpk.u);
    ECP_mul(temp_u, r_delta1);
    ECP_neg(&temp_u);
    ECP_add(&R4, &temp_u);

    ECP_copy(&R5, &T2);
    ECP_mul(R5, r_x);
    ECP_copy(&temp_v, &gpk.v);
    ECP_mul(temp_v, r_delta2);
    ECP_neg(&temp_v);
    ECP_add(&R5, &temp_v);

    mpz_class x = gskSig.x;
    mpz_class delta1 = (x * alpha) % q;
    mpz_class delta2 = (x * beta) % q;
    FP12 R3, temp1, temp2, temp3;
    // R3 = e(T3, g2)^r_x · e(h, w)^-(r_alpha + r_beta) · e(h, g2)^-(r_delta1 + r_delta2)
    R3 = e(T3, gpk.g_2);
    FP12_pow(R3, r_x);
    temp1 = e(gpk.h, gpk.w);
    mpz_class exp1 = (q - ((r_alpha + r_beta) % q)) % q;
    FP12_pow(temp1, exp1);
    mpz_class exp2 = (q - ((r_delta1 + r_delta2)) % q) % q;
    temp2 = e(gpk.h, gpk.g_2);
    FP12_pow(temp2, exp2);
    FP12_mul(&R3, &temp1);
    FP12_mul(&R3, &temp2);

    //
    mpz_class c = H(M, T1, T2, T3, R1, R2, R3, R4, R5);
    mpz_class s_alpha = (r_alpha + c * alpha) % q;
    mpz_class s_beta = (r_beta + c * beta) % q;
    mpz_class s_x = (r_x + c * x) % q;
    mpz_class s_delta1 = (r_delta1 + c * delta1) % q;
    mpz_class s_delta2 = (r_delta2 + c * delta2) % q;

    //
    Sigma_BBS bbsSig;
    ECP_copy(&bbsSig.T_1, &T1);
    ECP_copy(&bbsSig.T_2, &T2);
    ECP_copy(&bbsSig.T_3, &T3);
    bbsSig.c = c;
    bbsSig.s_alpha = s_alpha;
    bbsSig.s_beta = s_beta;
    bbsSig.s_x = s_x;
    bbsSig.s_delta1 = s_delta1;
    bbsSig.s_delta2 = s_delta2;

    return bbsSig;
}

bool GVf(GPK gpk, mpz_class M, Sigma_BBS sig) {
    // Unpack values from sig
    ECP T1 = sig.T_1;
    ECP T2 = sig.T_2;
    ECP T3 = sig.T_3;
    mpz_class c = sig.c;
    mpz_class s_alpha = sig.s_alpha;
    mpz_class s_beta = sig.s_beta;
    mpz_class s_x = sig.s_x;
    mpz_class s_delta1 = sig.s_delta1;
    mpz_class s_delta2 = sig.s_delta2;

    // 1. Compute R̃1 = u^sα * T1^{-c}
    ECP R1;
    ECP_copy(&R1, &gpk.u);
    ECP_mul(R1, s_alpha);
    ECP T1_c;
    ECP_copy(&T1_c, &T1);
    ECP_mul(T1_c, c);
    ECP_neg(&T1_c);
    ECP_add(&R1, &T1_c);

    // 2. Compute R̃2 = v^sβ * T2^{-c}
    ECP R2;
    ECP_copy(&R2, &gpk.v);
    ECP_mul(R2, s_beta);
    ECP T2_c;
    ECP_copy(&T2_c, &T2);
    ECP_mul(T2_c, c);
    ECP_neg(&T2_c);
    ECP_add(&R2, &T2_c);

    // 3. Compute R̃4 = T1^sx * u^{-sδ1}
    ECP R4;
    ECP_copy(&R4, &T1);
    ECP_mul(R4, s_x);
    ECP u_neg_delta1;
    ECP_copy(&u_neg_delta1, &gpk.u);
    ECP_mul(u_neg_delta1, s_delta1);
    ECP_neg(&u_neg_delta1);
    ECP_add(&R4, &u_neg_delta1);

    // 4. Compute R̃5 = T2^sx * v^{-sδ2}
    ECP R5;
    ECP_copy(&R5, &T2);
    ECP_mul(R5, s_x);
    ECP v_neg_delta2;
    ECP_copy(&v_neg_delta2, &gpk.v);
    ECP_mul(v_neg_delta2, s_delta2);
    ECP_neg(&v_neg_delta2);
    ECP_add(&R5, &v_neg_delta2);

    // 5. Compute R̃3
    FP12 e1 = e(T3, gpk.g_2);
    FP12_pow(e1, s_x);
    FP12 e2 = e(gpk.h, gpk.w);
    mpz_class exp1 = (q - ((s_alpha + s_beta) % q)) % q;
    FP12_pow(e2, exp1);
    FP12 e3 = e(gpk.h, gpk.g_2);
    mpz_class exp2 = (q - ((s_delta1 + s_delta2) % q)) % q;
    FP12_pow(e3, exp2);
    FP12 e4 = e(T3, gpk.w);
    FP12 e5 = e(gpk.g_1, gpk.g_2);
    FP12_inv(&e5, &e5);
    FP12_mul(&e4, &e5);
    FP12_pow(e4, c);
    FP12 R3;
    FP12_copy(&R3, &e1);
    FP12_mul(&R3, &e2);
    FP12_mul(&R3, &e3);
    FP12_mul(&R3, &e4);

    // 6. Recompute challenge
    mpz_class c_hat = H(M, T1, T2, T3, R1, R2, R3, R4, R5);

    return c_hat == c;
}


ECP Open(GPK gpk, GMSK gmsk, Sigma_BBS sig) {
    ECP A;
    ECP_copy(&A, &sig.T_3);
    ECP T1, T2;
    ECP_copy(&T1, &sig.T_1);
    ECP_copy(&T2, &sig.T_2);
    ECP_mul(T1, gmsk.ksi_1);
    ECP_mul(T2, gmsk.ksi_2);
    ECP_add(&T1, &T2);
    ECP_neg(&T1);
    ECP_add(&A, &T1);
    return A;
}

int GJudge(ECP A) {
    for (int i = 0; i < lists_A.size(); ++i) {
        if (ECP_equals(&A, &lists_A[i])) return i + 1;
    }
    return 0;
}


//int main() {
//    int groupMemCount = 8;
//    initRNG(&rng_BBS);
//    initState(state_BBS);
//    mpz_class gamma = rand_mpz(state_BBS);
//
//    ECP PK_san = randECP(rng_BBS);
//    vector<GSK_sig> gsk;
//    for (int i = 0; i < groupMemCount; ++i) {
//        GSK_sig gskSig = UKGen(gamma);
//        gsk.push_back(gskSig);
//    }
//
//    mpz_class m = 0x54545454_mpz;
//    GMSK gmsk;
//    GPK gpk;
//    vector<ECP> PKs;
//    GKGen(gmsk, gpk, PKs, gamma);
//
//    Sigma_BBS bbsSig = GSig( gsk[groupMemCount / 2], m,gpk);
//    bool res = GVf(gpk, m, bbsSig);
//    cout << "BBS verify pass ? : " << res << endl;
//
//    ECP A = Open(gpk,gmsk,bbsSig);
//    int id = GJudge(A);
//    cout << "Open group member id is : " << id << endl;
//    return 0;
//}