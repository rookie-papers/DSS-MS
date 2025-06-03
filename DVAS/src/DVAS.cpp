#include "../include/DVAS.h"
#include "benchmark/benchmark.h"

csprng rng_DVAS;
gmp_randstate_t state_DVAS;
mpz_class q_DVAS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001_mpz;

// Without loss of generality, assume the first ADM\_size messages are sensitive and allowed to be sanitized,
// while the remaining messages are not allowed to be sanitized.
void initOmega(Omega &omega, int ADM_size, int FIX_size) {
    omega.ADM.clear();
    omega.FIX.clear();
    for (int i = 0; i < ADM_size + FIX_size; ++i) {
        if (i < ADM_size) {
            omega.ADM.push_back(i);
        } else {
            omega.FIX.push_back(i);
        }
    }
}

mpz_class f_mod(mpz_class m) {
    return (m + 0x5201314_mpz) % q_DVAS;
}

mpz_class h_DVAS(mpz_class mi, Omega omega, FP12 fp12) {
    octet hash = getOctet(49);
    octet oct_m = mpzToOctet(mi);
    concatOctet(&hash, &oct_m);
    free(oct_m.val);
    octet oct_fp12 = getOctet(576);
    FP12_toOctet(&oct_fp12, &fp12);
    concatOctet(&hash, &oct_fp12);
    free(oct_fp12.val);
    BIG order, ret;
    BIG_rcopy(order, CURVE_Order);
    hashZp256(ret, &hash, order);
    free(hash.val);

    return BIG_to_mpz(ret);
}

mpz_class h_p_DVAS(mpz_class IDi, ECP2 Ri) {
    octet hash = getOctet(49);
    octet oct_m = mpzToOctet(IDi);
    concatOctet(&hash, &oct_m);
    free(oct_m.val);
    octet oct_Ri = getOctet(98);
    ECP2_toOctet(&oct_Ri, &Ri, true);
    concatOctet(&hash, &oct_Ri);
    free(oct_Ri.val);
    BIG order, ret;
    BIG_rcopy(order, CURVE_Order);
    hashZp256(ret, &hash, order);
    free(hash.val);
    return BIG_to_mpz(ret);
}

ECP H0_DVAS(mpz_class mi, ECP2 Vi, ECP fai) {
    // To differentiate between H0 and H1, use 0x10001\_mpz for H0 and 0x11111\_mpz for H1.
    octet hash = getOctet(49);
    octet oct_m = mpzToOctet((mi * 0x10001_mpz) % q_DVAS);
    concatOctet(&hash, &oct_m);
    free(oct_m.val);
    octet oct_Vi = getOctet(98);
    ECP2_toOctet(&oct_Vi, &Vi, true);
    concatOctet(&hash, &oct_Vi);
    free(oct_Vi.val);
    octet oct_Fai = getOctet(49);
    ECP_toOctet(&oct_Fai, &fai, true);
    concatOctet(&hash, &oct_Fai);
    free(oct_Fai.val);
    BIG order, ret;
    BIG_rcopy(order, CURVE_Order);
    hashZp256(ret, &hash, order);
    free(hash.val);
    ECP H;
    ECP_generator(&H);
    ECP_mul(H, BIG_to_mpz(ret));
    return H;
}

ECP H1_DVAS(mpz_class mi, ECP2 Vi, ECP fai) {
    octet hash = getOctet(49);
    octet oct_m = mpzToOctet((mi * 0x11111_mpz) % q_DVAS);
    concatOctet(&hash, &oct_m);
    free(oct_m.val);
    octet oct_Vi = getOctet(98);
    ECP2_toOctet(&oct_Vi, &Vi, true);
    concatOctet(&hash, &oct_Vi);
    free(oct_Vi.val);
    octet oct_Fai = getOctet(49);
    ECP_toOctet(&oct_Fai, &fai, true);
    concatOctet(&hash, &oct_Fai);
    free(oct_Fai.val);
    BIG order, ret;
    BIG_rcopy(order, CURVE_Order);
    hashZp256(ret, &hash, order);
    free(hash.val);
    ECP H;
    ECP_generator(&H);
    ECP_mul(H, BIG_to_mpz(ret));
    return H;
}


//mpz_class H2_DVAS(ECP R) {
//    octet hash = getOctet(49);
//    octet oct_R = getOctet(49);
//    ECP_toOctet(&oct_R, &R, true);
//    concatOctet(&hash, &oct_R);
//    free(oct_R.val);
//    BIG order, ret;
//    BIG_rcopy(order, CURVE_Order);
//    hashZp256(ret, &hash, order);
//    free(hash.val);
//    return BIG_to_mpz(ret);
//}

Params_DVAS SetUp_DVAS(KeyPair_DVAS &MC, KeyPair_DVAS &EN, KeyPairDN_DVAS &DN, vector<SN_DVAS> &SN, int n) {
    Params_DVAS pp;
    ECP_generator(&pp.P);

    MC.sk = rand_mpz(state_DVAS);
    ECP2_generator(&MC.PK);
    ECP2_mul(MC.PK, MC.sk);

    EN.sk = rand_mpz(state_DVAS);
    ECP2_generator(&EN.PK);
    ECP2_mul(EN.PK, EN.sk);

    DN.sk = rand_mpz(state_DVAS);
    ECP_generator(&DN.PK);
    ECP_mul(DN.PK, DN.sk);

    for (int i = 0; i < n; ++i) {
        SN_DVAS SNi;
        SNi.IDi = rand_mpz(state_DVAS);
        mpz_class ri = rand_mpz(state_DVAS);
        ECP2_generator(&SNi.Ri);
        ECP2_mul(SNi.Ri, ri);

        mpz_class ui = (ri + MC.sk * h_p_DVAS(SNi.IDi, SNi.Ri)) % q_DVAS;
        ECP2 Ui;
        ECP2_generator(&Ui);
        ECP2_mul(Ui, ui);

        ECP2 right;
        ECP2_copy(&right, &MC.PK);
        ECP2_mul(right, h_p_DVAS(SNi.IDi, SNi.Ri));
        ECP2_add(&right, &SNi.Ri);

        if (ECP2_equals(&Ui, &right)) {
//            cout << "In setup verify pass" << endl;
            SNi.keyPair.sk = ui;
            ECP2_copy(&SNi.keyPair.PK, &Ui);
            SN.push_back(SNi);
            pp.U.push_back(SNi.keyPair.PK);
        }
    }

    ECP2_copy(&pp.X, &EN.PK);
    ECP_copy(&pp.Y, &DN.PK);
    return pp;
}

void Joining_DVAS(SN_DVAS SNi, ECP2 S, Omega &omega) {
    mpz_class ci = h_p_DVAS(SNi.IDi, SNi.Ri);
    ECP2 right;
    ECP2_copy(&right, &S);
    ECP2_mul(right, ci);
    ECP2_add(&right, &SNi.Ri);

    if (ECP2_equals(&SNi.keyPair.PK, &right)) {
//        cout << "In Joining verify pass" << endl;
        int ADM_size = 1;
        int FIX_size = 1;
        initOmega(omega, ADM_size, FIX_size);
    }
}

vector<Sigma_i_DVAS> Signing_DVAS(SN_DVAS SN, Params_DVAS pp, vector<mpz_class> m, Omega omega) {
    vector<Sigma_i_DVAS> sigma;
    for (int i = 0; i < m.size(); ++i) {
        //
        mpz_class vi = rand_mpz(state_DVAS);
        ECP2 Vi;
        ECP2_generator(&Vi);
        ECP2_mul(Vi, vi);
        // e(Y,X)^ui
        FP12 fp12 = e(pp.Y, pp.X);
        FP12_pow(fp12, SN.keyPair.sk);
        // phi_i = ti * ui * Y
        mpz_class ti = h_DVAS(m[i], omega, fp12);
        ECP fai_i;
        ECP_copy(&fai_i, &pp.Y);
        ECP_mul(fai_i, (ti * SN.keyPair.sk) % q_DVAS);
        // Ti = ui * H0 + vi * H1
        ECP H0 = H0_DVAS(m[i], Vi, fai_i);
        ECP H1 = H1_DVAS(m[i], Vi, fai_i);
        ECP Ti;
        ECP_copy(&Ti, &H0);
        ECP_mul(Ti, SN.keyPair.sk);
        ECP temp;
        ECP_copy(&temp, &H1);
        ECP_mul(temp, vi);
        ECP_add(&Ti, &temp);

        Sigma_i_DVAS sigma_i;
        ECP_copy(&sigma_i.Ti, &Ti);
        ECP2_copy(&sigma_i.Vi, &Vi);
        ECP_copy(&sigma_i.fai_i, &fai_i);

        sigma.push_back(sigma_i);

    }
    return sigma;
}

vector<Sigma_i_DVAS> Sanitizing_DVAS(vector<mpz_class> m,vector<Sigma_i_DVAS> sigma_vec,Params_DVAS pp,SN_DVAS SNi,KeyPair_DVAS EN,Omega omega) {

    vector<Sigma_i_DVAS> sanitized_sigma;
    for (int i = 0; i < m.size(); ++i) {

        Sigma_i_DVAS sigma_i = sigma_vec[i];
        ECP H0i = H0_DVAS(m[i], sigma_vec[i].Vi, sigma_vec[i].fai_i);
        ECP H1i = H1_DVAS(m[i], sigma_vec[i].Vi, sigma_vec[i].fai_i);
        ECP2 P;
        ECP2_generator(&P);
        FP12 lhs = e(sigma_vec[i].Ti, P);
        FP12 rhs = e(H0i, SNi.keyPair.PK);
        FP12 e2 = e(H1i, sigma_vec[i].Vi);
        FP12_mul(&rhs, &e2);
//        cout << "Sanitizing verification passed : " << FP12_equals(&lhs, &rhs) << endl;
        if (i >= omega.ADM.size()) {
            sanitized_sigma.push_back(sigma_i);  // FIX jump
            continue;
        }
        // T'_i = xH0' + v_i' H1'
        mpz_class v_i_prime = rand_mpz(state_DVAS);
        ECP2 V_i_prime;
        ECP2_generator(&V_i_prime);
        ECP2_mul(V_i_prime, v_i_prime);
        mpz_class m_i_prime = f_mod(m[i]);
        FP12 e_ui_y = e(pp.Y, pp.U[i]);  // e(Ui, Y)
        FP12_pow(e_ui_y, EN.sk);               // ^x
        mpz_class t_i_prime = h_DVAS(m_i_prime, omega, e_ui_y);
        ECP Phi_i_prime;
        ECP_copy(&Phi_i_prime, &pp.Y);
        ECP_mul(Phi_i_prime, (t_i_prime * EN.sk) % q_DVAS);
        ECP H0_prime = H0_DVAS(m_i_prime, V_i_prime, Phi_i_prime);
        ECP H1_prime = H1_DVAS(m_i_prime, V_i_prime, Phi_i_prime);
        ECP T_i_prime;
        ECP_copy(&T_i_prime, &H0_prime);
        ECP_mul(T_i_prime, EN.sk);
        ECP_mul(H1_prime, v_i_prime);
        ECP_add(&T_i_prime, &H1_prime);
        // sanitized signature
        Sigma_i_DVAS sanitized;
        ECP_copy(&sanitized.Ti, &T_i_prime);
        ECP2_copy(&sanitized.Vi, &V_i_prime);
        ECP_copy(&sanitized.fai_i, &Phi_i_prime);
        sanitized_sigma.push_back(sanitized);
    }
    return sanitized_sigma;
}

bool Verify_DVAS(vector<mpz_class> m,vector<Sigma_i_DVAS> sigma_vec,SN_DVAS SN,Params_DVAS pp) {
    // Step 1: T_sum = sum_i T_i
    ECP T_sum;
    ECP_inf(&T_sum);
    for (auto sig: sigma_vec) {
        ECP_add(&T_sum, &sig.Ti);
    }
    // right
    FP12 rhs;
    FP12_one(&rhs);
    for (size_t i = 0; i < sigma_vec.size(); ++i) {
        ECP H0i = H0_DVAS(m[i], sigma_vec[i].Vi, sigma_vec[i].fai_i);
        ECP H1i = H1_DVAS(m[i], sigma_vec[i].Vi, sigma_vec[i].fai_i);
        FP12 e1 = e(H0i, SN.keyPair.PK);
        FP12 e2 = e(H1i, sigma_vec[i].Vi);
        FP12_mul(&rhs, &e1);  // rhs = rhs * e1
        FP12_mul(&rhs, &e2);   // rhs = rhs * e2
    }
    // left
    ECP2 P2;
    ECP2_generator(&P2);
    FP12 lhs = e(T_sum, P2);
    return FP12_equals(&lhs, &rhs);
}

void Detect_DVAS(mpz_class mi, vector<Sigma_i_DVAS> sigma, SN_DVAS SN, Omega omega, Params_DVAS pp, int flag) {
    int idx = 0;
    if (flag == 0) idx = omega.ADM.size() + omega.FIX.size() - 1;
    FP12 theta = e(pp.Y, pp.X);
    FP12_pow(theta, SN.keyPair.sk);
    mpz_class tk = h_DVAS(mi, omega, theta);
    ECP tkY;
    ECP_copy(&tkY, &pp.Y);
    ECP_mul(tkY, tk);
    ECP2 P2;
    ECP2_generator(&P2);
    FP12 left = e(sigma[idx].fai_i, P2);
    FP12 right = e(tkY, SN.keyPair.PK);
    int ok = FP12_equals(&left, &right);
//    cout << "Detect OK ?: " << ok << endl;
    // If it's ADM detection, an additional verification of m' == f\_mod(m) is required here, which is omitted.
}

//int main() {
//    initState(state_DVAS);
//    int n = 3; // The number of SN
//    Omega omega;
//    //
//    printLine("setup");
//    KeyPair_DVAS MC, EN;
//    KeyPairDN_DVAS DN;
//    vector<SN_DVAS> SNs;
//    Params_DVAS pp = SetUp_DVAS(MC, EN, DN, SNs, n);
//    //
//    printLine("joining");
//    for (int i = 0; i < n; ++i) {
//        Joining_DVAS(SNs[i], MC.PK, omega);
//    }
//    //
//    printLine("Signing");
//    vector<mpz_class> m;
//    for (int i = 0; i < omega.ADM.size() + omega.FIX.size(); ++i) {
//        m.push_back(rand_mpz(state_DVAS));
//    }
//    int signer_idx = n / 2;
//    vector<Sigma_i_DVAS> sigma = Signing_DVAS(SNs[signer_idx], pp, m, omega);
//    cout << "sigma.size = " << sigma.size() << endl;
//    //
//    printLine("Sanitizing");
//    vector<Sigma_i_DVAS> sigma_sanitized = Sanitizing_DVAS(m, sigma, pp, SNs[signer_idx], EN, omega);
//    //
//    printLine("Verify");
//    bool ok = Verify_DVAS(m, sigma, SNs[signer_idx], pp);
//    cout << "verification passed : " << ok << endl;
//    //
//    printLine("Detect");
//    int flag = 0; // Set to 0 for non-sensitive information, otherwise set to 1.
//    int idx = omega.ADM.size() + omega.FIX.size() - 1;
//    if (flag != 0) idx = 0;
//    Detect_DVAS(m[idx], sigma, SNs[signer_idx], omega, pp, flag);
//    return 0;
//}

static void BM_Setup(benchmark::State &state) {
    initState(state_DVAS);
    int n = 3; // The number of SN
    Omega omega;
    //
    KeyPair_DVAS MC, EN;
    KeyPairDN_DVAS DN;
    vector<SN_DVAS> SNs;
    for (auto _: state) {
        SetUp_DVAS(MC, EN, DN, SNs, n);
    }
}

static void BM_Join(benchmark::State &state) {
    initState(state_DVAS);
    int n = 3; // The number of SN
    Omega omega;
    //
    KeyPair_DVAS MC, EN;
    KeyPairDN_DVAS DN;
    vector<SN_DVAS> SNs;
    Params_DVAS pp = SetUp_DVAS(MC, EN, DN, SNs, n);

    for (auto _: state) {
        Joining_DVAS(SNs[0], MC.PK, omega);

    }
}

static void BM_Sign(benchmark::State &state) {
    initState(state_DVAS);
    int n = 3; // The number of SN
    Omega omega;
    //
    KeyPair_DVAS MC, EN;
    KeyPairDN_DVAS DN;
    vector<SN_DVAS> SNs;
    Params_DVAS pp = SetUp_DVAS(MC, EN, DN, SNs, n);
    //
    for (int i = 0; i < n; ++i) {
        Joining_DVAS(SNs[i], MC.PK, omega);
    }
    //
    vector<mpz_class> m;
    for (int i = 0; i < omega.ADM.size() + omega.FIX.size(); ++i) {
        m.push_back(rand_mpz(state_DVAS));
    }
    int signer_idx = n / 2;
    for (auto _: state) {
        vector<Sigma_i_DVAS> sigma = Signing_DVAS(SNs[signer_idx], pp, m, omega);

    }
}


static void BM_Sanitizing(benchmark::State &state) {
    initState(state_DVAS);
    int n = 3; // The number of SN
    Omega omega;
    //
    KeyPair_DVAS MC, EN;
    KeyPairDN_DVAS DN;
    vector<SN_DVAS> SNs;
    Params_DVAS pp = SetUp_DVAS(MC, EN, DN, SNs, n);
    //
    for (int i = 0; i < n; ++i) {
        Joining_DVAS(SNs[i], MC.PK, omega);
    }
    //
    vector<mpz_class> m;
    for (int i = 0; i < omega.ADM.size() + omega.FIX.size(); ++i) {
        m.push_back(rand_mpz(state_DVAS));
    }
    int signer_idx = n / 2;
    vector<Sigma_i_DVAS> sigma = Signing_DVAS(SNs[signer_idx], pp, m, omega);
    //
    for (auto _: state) {
        Sanitizing_DVAS(m, sigma, pp, SNs[signer_idx], EN, omega);
    }
}

static void BM_Verify(benchmark::State &state) {
    initState(state_DVAS);
    int n = 3; // The number of SN
    Omega omega;
    //
    KeyPair_DVAS MC, EN;
    KeyPairDN_DVAS DN;
    vector<SN_DVAS> SNs;
    Params_DVAS pp = SetUp_DVAS(MC, EN, DN, SNs, n);
    //
    for (int i = 0; i < n; ++i) {
        Joining_DVAS(SNs[i], MC.PK, omega);
    }
    //
    vector<mpz_class> m;
    for (int i = 0; i < omega.ADM.size() + omega.FIX.size(); ++i) {
        m.push_back(rand_mpz(state_DVAS));
    }
    int signer_idx = n / 2;
    vector<Sigma_i_DVAS> sigma = Signing_DVAS(SNs[signer_idx], pp, m, omega);
    //
    vector<Sigma_i_DVAS> sigma_sanitized = Sanitizing_DVAS(m, sigma, pp, SNs[signer_idx], EN, omega);
    //
    for (auto _: state) {
        Verify_DVAS(m, sigma, SNs[signer_idx], pp);
    }
}

void BM_Detect(benchmark::State &state) {
    initState(state_DVAS);
    int n = 3; // The number of SN
    Omega omega;
    //
    KeyPair_DVAS MC, EN;
    KeyPairDN_DVAS DN;
    vector<SN_DVAS> SNs;
    Params_DVAS pp = SetUp_DVAS(MC, EN, DN, SNs, n);
    //
    for (int i = 0; i < n; ++i) {
        Joining_DVAS(SNs[i], MC.PK, omega);
    }
    //
    vector<mpz_class> m;
    for (int i = 0; i < omega.ADM.size() + omega.FIX.size(); ++i) {
        m.push_back(rand_mpz(state_DVAS));
    }
    int signer_idx = n / 2;
    vector<Sigma_i_DVAS> sigma = Signing_DVAS(SNs[signer_idx], pp, m, omega);
    //
    vector<Sigma_i_DVAS> sigma_sanitized = Sanitizing_DVAS(m, sigma, pp, SNs[signer_idx], EN, omega);
    //
    bool ok = Verify_DVAS(m, sigma, SNs[signer_idx], pp);
    //
    int flag = 0; // Set to 0 for non-sensitive information, otherwise set to 1.
    int idx = omega.ADM.size() + omega.FIX.size() - 1;
    if (flag != 0) idx = 0;

    for (auto _: state) {
        Detect_DVAS(m[idx], sigma, SNs[signer_idx], omega, pp, flag);
    }
}

// register
BENCHMARK(BM_Setup);
BENCHMARK(BM_Join);
BENCHMARK(BM_Sign);
BENCHMARK(BM_Sanitizing);
BENCHMARK(BM_Verify);
BENCHMARK(BM_Detect);

// run benchmark
BENCHMARK_MAIN();