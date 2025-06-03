#include "../include/DSS-websocket.h"

gmp_randstate_t state_websocket;

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
    initState(state_websocket);
    std::vector<mpz_class> sk;
    // Generate k large integers n_i such that 2^(bits-5) < n < 2^bits
    while ((int) sk.size() < k) {
        mpz_class n;
        while (true) {
            mpz_urandomb(n.get_mpz_t(), state_websocket, bits);
            if (mpz_sizeinbase(n.get_mpz_t(), 2) >= (bits - 5)) break;
        }
        n |= 1; // Force odd to avoid even common factors
        if (n == 0) continue;
        // Ensure n is coprime with all previously chosen numbers
        bool ok = true;
        for (const auto &m: sk) {
            if (!are_coprime(n, m)) {
                ok = false;
                break;
            }
        }
        if (ok) {
            sk.push_back(n);
        }
    }
    // Compute M = product of all n_i
    mpz_class M = 1;
    for (const auto &sk_i: sk) {
        M *= sk_i;
    }
    // Generate private key and public key for sanitor
    mpz_urandomb(keyPair.sk.get_mpz_t(), state_websocket, bits - 5);
    ECP_generator(&keyPair.PK);
    ECP_mul(keyPair.PK, keyPair.sk);
    // compute M_i and y_i (M_i * y_i ≡ 1 mod sk[i])
    std::vector<mpz_class> M_i(k), y_i(k);
    for (int i = 0; i < k; ++i) {
        M_i[i] = M / sk[i];
        y_i[i] = invert_mpz(M_i[i], sk[i]);
    }
    mpz_class u = 0;
    for (int i = 0; i < k; ++i) {
        u += y_i[i] * M_i[i];
    }
    pp.u_s = keyPair.sk * u;
    return sk;
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


Sigma Sign(Params pp, mpz_class sk, ECP PK_s ,mpz_class& t) {
    Sigma sigma;
    initState(state_websocket);

    mpz_class r = rand_mpz(state_websocket);
    mpz_class s = rand_mpz(state_websocket);
    t = rand_mpz(state_websocket);
    ECP T;
    ECP_generator(&T);
    ECP_mul(T, t);
    ECP R;
    ECP_generator(&R);
    ECP_mul(R, r);

    mpz_class m0 = rand_mpz(state_websocket);
    mpz_class m = rand_mpz(state_websocket);
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


Sigma Sanitizing(Params pp, Sigma sigma, mpz_class sk_i, ECP PK_s, gmp_randstate_t& randState) {
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

    mpz_class m_p = rand_mpz(randState);
    mpz_class k = rand_mpz(randState);

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

KeyPair Proof(Params pp,Sigma sigma,mpz_class t){
    KeyPair pi;
    ECP_generator(&pi.PK);
    mpz_class r = rand_mpz(state_websocket);
    ECP_mul(pi.PK,r);
    mpz_class c = H(sigma.m,pi.PK,sigma.T);
    pi.sk = (r + c * t ) % pp.q;
    return pi;
}

bool Judge(KeyPair pi,Sigma sigma){
    ECP zP;
    ECP_generator(&zP);
    ECP_mul(zP, pi.sk);
    ECP right;
    ECP_copy(&right,&sigma.T);
    mpz_class c = H(sigma.m,pi.PK,sigma.T);
    ECP_mul(right,c);
    ECP_add(&right,&pi.PK);
    return ECP_equals(&zP,&right);
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


mpz_class initAndGetMpz(){
    return rand_mpz(state_websocket);
}


void testDSS(){
    int k = 5;// The number of sanitizor
    int bits = 256;
    initState(state_websocket);
    Params pp = Setup();

    KeyPair keyPair_san;
    vector<mpz_class> sk = KeyGen(pp, keyPair_san, k, bits);
    showParams(pp);

    KeyPair keyPair_sign;
    keyPair_sign.sk = rand_mpz(state_websocket);
    ECP_copy(&keyPair_sign.PK, &pp.P);
    ECP_mul(keyPair_sign.PK, keyPair_sign.sk);
    mpz_class t;
    Sigma sigma = Sign(pp, keyPair_sign.sk, keyPair_san.PK,t);
    showSigma(sigma);

    int res = Verify(pp, sigma, keyPair_san.PK, keyPair_sign.PK);
    cout << res << endl;

    printLine("Sanitizing");
    for (int i = 0; i < k; i++) {
        Sigma sigma_p = Sanitizing(pp, sigma, sk[i], keyPair_san.PK,state_websocket);
        res = Verify(pp, sigma_p, keyPair_san.PK, keyPair_sign.PK);
        cout << res << endl;
    }

    printLine("Proof and Judge");
    KeyPair pi = Proof(pp,sigma,t);
    bool judge = Judge(pi,sigma);
    cout << (judge ? "sig" : "san") << endl;
}

//int main() {
//    testDSS();
//    return 0;
//}
