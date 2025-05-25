#include "../include/Schnorr.h"

gmp_randstate_t state_schnorr;

mpz_class H(mpz_class m0, ECP R, ECP PK) {
    octet hash = getOctet(49);
    octet oct_m = mpzToOctet(m0);
    concatOctet(&hash, &oct_m);
    octet oct_R = getOctet(49);
    ECP_toOctet(&oct_R, &R, true);
    concatOctet(&hash, &oct_R);
    BIG order, ret;
    BIG_rcopy(order, CURVE_Order);
    hashZp256(ret, &hash, order);
    octet oct_pk = getOctet(49);
    ECP_toOctet(&oct_pk, &PK, true);
    concatOctet(&hash, &oct_pk);
    free(hash.val);
    free(oct_m.val);
    free(oct_R.val);
    free(oct_pk.val);
    return BIG_to_mpz(ret);
}

Params_schnorr Setup_schnorr() {
    Params_schnorr pp;
    BIG order;
    BIG_rcopy(order, CURVE_Order);
    pp.q = BIG_to_mpz(order);
    ECP_generator(&pp.P);
    return pp;
}

KeyPair_schnorr SKGen(Params_schnorr pp) {
    KeyPair_schnorr keyPair;
    initState(state_schnorr);
    keyPair.sk = rand_mpz(state_schnorr); // rand_mpz 已经自动 mod q了
    ECP_copy(&keyPair.PK, &pp.P);
    ECP_mul(keyPair.PK, keyPair.sk);
    return keyPair;
}

Sigma_schnorr SSign(KeyPair_schnorr keyPair, mpz_class m,Params_schnorr pp) {
    Sigma_schnorr sig;
    initState(state_schnorr);
    mpz_class r = rand_mpz(state_schnorr);
    ECP R;
    ECP_copy(&R, &pp.P);
    ECP_mul(R, r);

    mpz_class c = H(m, R, keyPair.PK);
    mpz_class z = (r + c * keyPair.sk) % pp.q;
    sig.z = z;
    sig.R = R;
    return sig;
}

int SVf(Params_schnorr pp, ECP PK, Sigma_schnorr sig, mpz_class m) {
    ECP left;
    ECP_copy(&left, &pp.P);
    ECP_mul(left, sig.z);
    mpz_class c = H(m, sig.R, PK);
    ECP right;
    ECP_copy(&right, &PK);
    ECP_mul(right, c);
    ECP_add(&right, &sig.R);
    return ECP_equals(&left, &right);
}

//int main() {
//    initState(state_schnorr);
//    mpz_class m = rand_mpz(state_schnorr);
//    printLine("schnorr message m");
//    show_mpz(m.get_mpz_t());
//    Params_schnorr pp = Setup_schnorr();
//    printLine("pp");
//    show_mpz(pp.q.get_mpz_t());
//    ECP_output(&pp.P);
//    KeyPair_schnorr keyPair = SKGen(pp);
//    printLine("keyPair");
//    show_mpz(keyPair.sk.get_mpz_t());
//    ECP_output(&keyPair.PK);
//    Sigma_schnorr sigma = SSign(keyPair, m , pp);
//    printLine("sigma");
//    show_mpz(sigma.z.get_mpz_t());
//    ECP_output(&sigma.R);
//    int res = SVf(pp, keyPair.PK, sigma, m);
//    printLine("verify");
//    cout << "verify pass? : " << res << endl;
//    return 0;
//}