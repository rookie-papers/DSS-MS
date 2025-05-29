#include "../include/SSig.h"

gmp_randstate_t state_SSig;

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

Params_SSig Setup_SSig() {
    Params_SSig pp;
    BIG order;
    BIG_rcopy(order, CURVE_Order);
    pp.q = BIG_to_mpz(order);
    ECP_generator(&pp.P);
    return pp;
}

KeyPair_SSig SKGen(Params_SSig pp) {
    KeyPair_SSig keyPair;
    initState(state_SSig);
    keyPair.sk = rand_mpz(state_SSig); // rand_mpz 已经自动 mod q了
    ECP_copy(&keyPair.PK, &pp.P);
    ECP_mul(keyPair.PK, keyPair.sk);
    return keyPair;
}

Sigma_SSig SSign(KeyPair_SSig keyPair, mpz_class m,Params_SSig pp) {
    Sigma_SSig sig;
    initState(state_SSig);
    mpz_class r = rand_mpz(state_SSig);
    ECP R;
    ECP_copy(&R, &pp.P);
    ECP_mul(R, r);

    mpz_class c = H(m, R, keyPair.PK);
    mpz_class z = (r + c * keyPair.sk) % pp.q;
    sig.z = z;
    sig.R = R;
    return sig;
}

int SVf(Params_SSig pp, ECP PK, Sigma_SSig sig, mpz_class m) {
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