#include "../include/DSS.h"
#include "benchmark/benchmark.h"

csprng rng;
gmp_randstate_t state_DSS;
typedef struct {
    vector<mpz_class> sk;
    mpz_class M;
    mpz_class u;
} CRT;
CRT crt;

#define SAN 3000
#define BITS 256
#define N 10

// Determine whether a and b are coprime
bool are_coprime(const mpz_class &a, const mpz_class &b) {
    mpz_class g;
    mpz_gcd(g.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    return g == 1;
}


Params Setup() {
    Params pp;
    ECP_generator(&pp.P);
    BIG order;
    BIG_rcopy(order, CURVE_Order);
    pp.q = BIG_to_mpz(order);
    return pp;
}

vector<mpz_class> KeyGen(Params &pp, KeyPair &keyPair, int k, int bits) {
    vector<mpz_class> sks;
    mpz_class sk, M_batch = 1;
    int count = 0;
    while (count < k) {
        while (true) {
            mpz_urandomb(sk.get_mpz_t(), state_DSS, bits);
            if (mpz_sizeinbase(sk.get_mpz_t(), 2) >= bits - 5) break;
        }

        sk |= 1;
        if (gcd(sk, M_batch) == 1) {
            sks.push_back(sk);
            M_batch *= sk;
            ++count;
        }
    }

    // Generate private key and public key for sanitor
    mpz_urandomb(keyPair.sk.get_mpz_t(), state_DSS, bits - 5);
    ECP_generator(&keyPair.PK);
    ECP_mul(keyPair.PK, keyPair.sk);
    // compute M_i and y_i (M_i * y_i ≡ 1 mod sk[i])
    std::vector<mpz_class> M_i(k), y_i(k);
    for (int i = 0; i < k; ++i) {
        M_i[i] = M_batch / sks[i];
        y_i[i] = invert_mpz(M_i[i], sks[i]);
    }
    mpz_class u = 0;
    for (int i = 0; i < k; ++i) {
        u += y_i[i] * M_i[i];
    }
    crt.sk = sks;
    crt.M = M_batch;
    crt.u = u;
    pp.u_s = keyPair.sk * u;
    return sks;
}

mpz_class H_ch(mpz_class m, ECP T) {
    octet hash = getOctet(49);

    octet oct_m = getOctet(49);
    oct_m = mpzToOctet(m);
    concatOctet(&hash, &oct_m);

    octet oct_T = getOctet(49);
    ECP_toOctet(&oct_T, &T, true);
    concatOctet(&hash, &oct_T);

    BIG order, ret;
    BIG_rcopy(order, CURVE_Order);
    hashZp256(ret, &hash, order);

    free(hash.val);
    free(oct_m.val);
    free(oct_T.val);

    return BIG_to_mpz(ret);
}

mpz_class H(mpz_class m0, ECP R, ECP CH) {
    octet hash = getOctet(49);

    octet oct_m = mpzToOctet(m0);
    concatOctet(&hash, &oct_m);

    octet oct_R = getOctet(49);
    ECP_toOctet(&oct_R, &R, true);
    concatOctet(&hash, &oct_R);

    octet oct_ch = getOctet(49);
    ECP_toOctet(&oct_ch, &CH, true);
    concatOctet(&hash, &oct_ch);

    BIG order, ret;
    BIG_rcopy(order, CURVE_Order);
    hashZp256(ret, &hash, order);

    free(hash.val);
    free(oct_m.val);
    free(oct_R.val);
    free(oct_ch.val);

    return BIG_to_mpz(ret);
}


Sigma Sign(Params pp, mpz_class sk, ECP PK_s, mpz_class &t) {
    Sigma sigma;
    initRNG(&rng);

    mpz_class r = rand_mpz(state_DSS);
    mpz_class s = rand_mpz(state_DSS);
    t = rand_mpz(state_DSS);
    ECP T;
    ECP_generator(&T);
    ECP_mul(T, t);
    ECP R;
    ECP_generator(&R);
    ECP_mul(R, r);

    mpz_class m0 = rand_mpz(state_DSS);
    mpz_class m = rand_mpz(state_DSS);
    mpz_class e = H_ch(m, T);
    ECP CH, temp;
    ECP_copy(&temp, &pp.P);
    ECP_copy(&CH, &PK_s);
    ECP_mul(temp, s);
    ECP_mul(CH, e);
    ECP_add(&CH, &temp);
    ECP_add(&CH, &T);

    mpz_class c = H(m0, R, CH);
    mpz_class z = (r + sk * c) % pp.q;

    sigma.m0 = m0;
    sigma.m = m;
    sigma.R = R;
    sigma.z = z;
    sigma.s = s;
    sigma.T = T;

    return sigma;
}


Sigma Sanitizing(Params pp, Sigma sigma, mpz_class sk_i, ECP PK_s) {
    Sigma sigma_p;
    mpz_class sk_s = pp.u_s % sk_i;

    mpz_class e = H_ch(sigma.m, sigma.T);
    ECP CH, temp;
    ECP_copy(&temp, &pp.P);
    ECP_copy(&CH, &PK_s);
    ECP_mul(temp, sigma.s);
    ECP_mul(CH, e);
    ECP_add(&CH, &temp);
    ECP_add(&CH, &sigma.T);

    mpz_class m_p = rand_mpz(state_DSS);
    mpz_class k = rand_mpz(state_DSS);
    ECP T_p;
    ECP_copy(&T_p, &CH);
    ECP K;
    ECP_copy(&K, &pp.P);
    ECP_mul(K, k);
    ECP_neg(&K);
    ECP_add(&T_p, &K);

    mpz_class e_p = H_ch(m_p, T_p);
    mpz_class s_p = (e_p * sk_s) % pp.q;
    s_p = pp.q - s_p;
    s_p = (k + s_p) % pp.q;

    sigma_p.m0 = sigma.m0;
    sigma_p.m = m_p;
    sigma_p.R = sigma.R;
    sigma_p.z = sigma.z;
    sigma_p.s = s_p;
    sigma_p.T = T_p;

    return sigma_p;
}

int Verify(Params pp, Sigma sigma, ECP PK_s, ECP PK) {
    mpz_class e = H_ch(sigma.m, sigma.T);
    ECP CH, temp;
    ECP_copy(&temp, &pp.P);
    ECP_copy(&CH, &PK_s);
    ECP_mul(temp, sigma.s);
    ECP_mul(CH, e);
    ECP_add(&CH, &temp);
    ECP_add(&CH, &sigma.T);

    mpz_class c = H(sigma.m0, sigma.R, CH);
    ECP left;
    ECP_copy(&left, &pp.P);
    ECP_mul(left, sigma.z);
    ECP right;
    ECP_copy(&right, &PK);
    ECP_mul(right, c);
    ECP_add(&right, &sigma.R);

    return ECP_equals(&left, &right);
}

KeyPair Proof(Params pp, Sigma sigma, mpz_class t) {
    KeyPair pi;
    ECP_generator(&pi.PK);
    mpz_class r = rand_mpz(state_DSS);
    ECP_mul(pi.PK, r);
    mpz_class c = H(sigma.m, pi.PK, sigma.T);
    pi.sk = (r + c * t) % pp.q;
    return pi;
}

bool Judge(KeyPair pi, Sigma sigma) {
    ECP zP;
    ECP_generator(&zP);
    ECP_mul(zP, pi.sk);
    ECP right;
    ECP_copy(&right, &sigma.T);
    mpz_class c = H(sigma.m, pi.PK, sigma.T);
    ECP_mul(right, c);
    ECP_add(&right, &pi.PK);
    return ECP_equals(&zP, &right);
}

void Join(Params &pp, mpz_class sk_san, int bits,int n) {
    mpz_class M_batch = 1;
    mpz_class sk_star;
    int i = 0;
    while (i < n) {
        while (true) {
            mpz_urandomb(sk_star.get_mpz_t(), state_DSS, bits);
            if (mpz_sizeinbase(sk_star.get_mpz_t(), 2) >= (bits - 5)) break;
        }
        sk_star |= 1;
        if (gcd(sk_star, crt.M) == 1 && gcd(sk_star, M_batch) == 1) {
            crt.sk.push_back(sk_star);
            M_batch *= sk_star;
            i++;
        }
    }

    crt.M = 1;
    for (const auto &m: crt.sk) crt.M *= m;

    crt.u = 0;
    int len = crt.sk.size();
    for (int i = 0; i < len; ++i) {
        mpz_class Mi = crt.M / crt.sk[i];
        mpz_class yi = invert_mpz(Mi, crt.sk[i]);
        crt.u += Mi * yi;
    }
    pp.u_s = sk_san * crt.u;
}

void Revoke(Params &pp, mpz_class sk_san, const vector<mpz_class> &sk_star_list) {
    for (const auto &sk_star : sk_star_list) {
        auto it = std::find(crt.sk.begin(), crt.sk.end(), sk_star);
        if (it != crt.sk.end()) crt.sk.erase(it);
        mpz_class M_star = crt.M / sk_star;
        mpz_class y_star = invert_mpz(M_star, sk_star);
        crt.u -= M_star * y_star;
        crt.M = M_star;
    }
    pp.u_s = sk_san * crt.u;
}

void showParams(Params pp) {
    printLine("showParams");
    cout << "pp.P = ";
    ECP_output(&pp.P);
    cout << "pp.q = ";
    show_mpz(pp.q.get_mpz_t());
    cout << "pp.u_s = ";
    show_mpz(pp.u_s.get_mpz_t());
}

void showSigma(Sigma sigma) {
    printLine("showSigma");
    cout << "sigma.m0 = ";
    show_mpz(sigma.m0.get_mpz_t());
    cout << "sigma.m = ";
    show_mpz(sigma.m.get_mpz_t());
    cout << "sigma.R = ";
    ECP_output(&sigma.R);
    cout << "sigma.z = ";
    show_mpz(sigma.z.get_mpz_t());
    cout << "sigma.s = ";
    show_mpz(sigma.s.get_mpz_t());
    cout << "sigma.T = ";
    ECP_output(&sigma.T);
}


void testDSS() {
    initState(state_DSS);
    Params pp = Setup();

    KeyPair keyPair_san;
    vector<mpz_class> sk = KeyGen(pp, keyPair_san, SAN, BITS);
    showParams(pp);

    KeyPair keyPair_sign;
    keyPair_sign.sk = rand_mpz(state_DSS);
    ECP_copy(&keyPair_sign.PK, &pp.P);
    ECP_mul(keyPair_sign.PK, keyPair_sign.sk);
    mpz_class t;
    Sigma sigma = Sign(pp, keyPair_sign.sk, keyPair_san.PK, t);
    showSigma(sigma);

    int res = Verify(pp, sigma, keyPair_san.PK, keyPair_sign.PK);
    cout << res << endl;

    printLine("Sanitizing");
    for (int i = 0; i < SAN; i++) {
        Sigma sigma_p = Sanitizing(pp, sigma, sk[i], keyPair_san.PK);
        res = Verify(pp, sigma_p, keyPair_san.PK, keyPair_sign.PK);
        cout << res << endl;
    }

    printLine("Proof and Judge");
    KeyPair pi = Proof(pp, sigma, t);
    bool judge = Judge(pi, sigma);
    cout << (judge ? "sig" : "san") << endl;

    printLine("Join");
    cout << "Join before sk.size() = " << crt.sk.size() << endl;
    Join(pp, keyPair_san.sk, BITS,N);
    cout << "Join after sk.size() = " << crt.sk.size() << endl;
    for (int i = 0; i < crt.sk.size(); ++i) {
        mpz_class sk_san = pp.u_s % crt.sk[i];
        show_mpz(sk_san.get_mpz_t());
    }

    printLine("Revoke");
    cout << "Revoke before sk.size() = " << crt.sk.size() << endl;
    vector<mpz_class> sk_star_lists(sk.begin(), sk.begin() + N);
    Revoke(pp, keyPair_san.sk, sk_star_lists);
    cout << "Revoke after sk.size() = "<< crt.sk.size() << endl;
    for (int i = 0; i < crt.sk.size(); ++i) {
        mpz_class sk_san = pp.u_s % crt.sk[i];
        show_mpz(sk_san.get_mpz_t());
    }
}

//int main() {
//    testDSS();
//    return 0;
//}

static void DSS_Setup(benchmark::State &state) {
    initState(state_DSS);
    for (auto _: state) {
        Params pp = Setup();
    }
}

static void DSS_KeyGen(benchmark::State &state) {
    initState(state_DSS);
    Params pp = Setup();

    KeyPair keyPair_san;
    for (auto _: state) {
        vector<mpz_class> sk = KeyGen(pp, keyPair_san, SAN, BITS);
    }
}

static void DSS_Sign(benchmark::State &state) {
    initState(state_DSS);
    Params pp = Setup();

    KeyPair keyPair_san;
    vector<mpz_class> sk = KeyGen(pp, keyPair_san, SAN, BITS);

    KeyPair keyPair_sign;
    keyPair_sign.sk = rand_mpz(state_DSS);
    ECP_copy(&keyPair_sign.PK, &pp.P);
    ECP_mul(keyPair_sign.PK, keyPair_sign.sk);
    mpz_class t;

    for (auto _: state) {
        Sigma sigma = Sign(pp, keyPair_sign.sk, keyPair_san.PK, t);
    }
}

static void DSS_Sanitizing(benchmark::State &state) {
    initState(state_DSS);
    Params pp = Setup();

    KeyPair keyPair_san;
    vector<mpz_class> sk = KeyGen(pp, keyPair_san, SAN, BITS);

    KeyPair keyPair_sign;
    keyPair_sign.sk = rand_mpz(state_DSS);
    ECP_copy(&keyPair_sign.PK, &pp.P);
    ECP_mul(keyPair_sign.PK, keyPair_sign.sk);
    mpz_class t;
    Sigma sigma = Sign(pp, keyPair_sign.sk, keyPair_san.PK, t);
    for (auto _: state) {
        Sigma sigma_p = Sanitizing(pp, sigma, sk[0], keyPair_san.PK);
    }
}

static void DSS_Verify(benchmark::State &state) {
    initState(state_DSS);
    Params pp = Setup();

    KeyPair keyPair_san;
    vector<mpz_class> sk = KeyGen(pp, keyPair_san, SAN, BITS);

    KeyPair keyPair_sign;
    keyPair_sign.sk = rand_mpz(state_DSS);
    ECP_copy(&keyPair_sign.PK, &pp.P);
    ECP_mul(keyPair_sign.PK, keyPair_sign.sk);
    mpz_class t;
    Sigma sigma = Sign(pp, keyPair_sign.sk, keyPair_san.PK, t);
    Sigma sigma_p = Sanitizing(pp, sigma, sk[0], keyPair_san.PK);
    for (auto _: state) {
        Verify(pp, sigma_p, keyPair_san.PK, keyPair_sign.PK);
    }
}

void DSS_Proof(benchmark::State &state) {
    initState(state_DSS);
    Params pp = Setup();

    KeyPair keyPair_san;
    vector<mpz_class> sk = KeyGen(pp, keyPair_san, SAN, BITS);

    KeyPair keyPair_sign;
    keyPair_sign.sk = rand_mpz(state_DSS);
    ECP_copy(&keyPair_sign.PK, &pp.P);
    ECP_mul(keyPair_sign.PK, keyPair_sign.sk);
    mpz_class t;
    Sigma sigma = Sign(pp, keyPair_sign.sk, keyPair_san.PK, t);
    Sigma sigma_p = Sanitizing(pp, sigma, sk[0], keyPair_san.PK);
    for (auto _: state) {
        Proof(pp, sigma, t);
    }
}

void DSS_Judge(benchmark::State &state) {
    initState(state_DSS);
    Params pp = Setup();

    KeyPair keyPair_san;
    vector<mpz_class> sk = KeyGen(pp, keyPair_san, SAN, BITS);

    KeyPair keyPair_sign;
    keyPair_sign.sk = rand_mpz(state_DSS);
    ECP_copy(&keyPair_sign.PK, &pp.P);
    ECP_mul(keyPair_sign.PK, keyPair_sign.sk);
    mpz_class t;
    Sigma sigma = Sign(pp, keyPair_sign.sk, keyPair_san.PK, t);
    Sigma sigma_p = Sanitizing(pp, sigma, sk[0], keyPair_san.PK);
    KeyPair pi = Proof(pp, sigma, t);
    for (auto _: state) {
        Judge(pi, sigma);
    }
}

void DSS_Join(benchmark::State &state) {

    initState(state_DSS);
    Params pp = Setup();

    KeyPair keyPair_san;
    vector<mpz_class> sk = KeyGen(pp, keyPair_san, SAN, BITS);

    for (auto _: state) {
        Join(pp, keyPair_san.sk, BITS,N);
    }
}

void DSS_Revoke(benchmark::State &state) {

    initState(state_DSS);
    Params pp = Setup();

    KeyPair keyPair_san;
    vector<mpz_class> sk = KeyGen(pp, keyPair_san, SAN + N, BITS);
    vector<mpz_class> sk_star_lists(sk.begin(), sk.begin() + N);

    for (auto _: state) {
        Revoke(pp, keyPair_san.sk, sk_star_lists);
    }
}

// register
BENCHMARK(DSS_Setup);
BENCHMARK(DSS_KeyGen);
BENCHMARK(DSS_Sign);
BENCHMARK(DSS_Sanitizing);
BENCHMARK(DSS_Verify);
BENCHMARK(DSS_Proof);
BENCHMARK(DSS_Judge);
BENCHMARK(DSS_Join);
BENCHMARK(DSS_Revoke);

// run benchmark
BENCHMARK_MAIN();