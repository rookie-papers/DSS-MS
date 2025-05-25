#include "../include/BFLS10.h"

csprng rng_BFLS10;
gmp_randstate_t state_BFLS10;
mpz_class q_BFLS10 = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001_mpz;
GMSK gmsk_BFLS10;

mpz_class ComDigest_FIX(mpz_class m_FIX, mpz_class ADM, ECP PK_san, GPK gpk) {
    return m_FIX;
}

mpz_class ComDigest_FULL(mpz_class m, ECP PK_sig) {
    return m;
}

void KeyGeneration(KeyPair_schnorr &keyPair_Schnorr, GSK_sig &keyPair_BBS, Params_schnorr pp_S, mpz_class gamma) {
    keyPair_Schnorr = SKGen(pp_S);
    keyPair_BBS = UKGen(gamma);
}

Sigma_BFLS10 Signing(KeyPair_schnorr KP_Schnorr_sig, mpz_class m_FIX, Params_schnorr pp_S,
                     GSK_sig KP_BBS_sig, mpz_class m, ECP PK_san,
                     mpz_class ADM, mpz_class gamma) {

    Sigma_BFLS10 sigma;
    // Key generation. PKs denote: the set of public keys to be certified, i.e., gpk_sig and pk_san. Assigned here for use in Judge
    GMSK gmsk;
    vector<ECP> PKs;
    GKGen(gmsk, sigma.gpk, PKs, gamma);
    gmsk_BFLS10 = gmsk;
    // Schnorr signature on the fixed part of the message
    mpz_class msgDigest_FIX = ComDigest_FIX(m_FIX, ADM, PK_san, sigma.gpk);
    sigma.sigma_FIX = SSign(KP_Schnorr_sig, msgDigest_FIX, pp_S); // Represents m_FIX || ADM || pk_san || gpk
    // BBS signature on the sanitizable part of the message
    mpz_class msgDigest_FULL = ComDigest_FULL(m_FIX, PK_san);
    sigma.sigma_FULL = GSig(KP_BBS_sig, m, sigma.gpk);
    sigma.ADM = ADM;
    ECP_copy(&sigma.PK_san, &PK_san);
    return sigma;

}

Sigma_BFLS10 Sanitizing(Params_schnorr pp_S, ECP PK_sig, Sigma_BFLS10 sigma, mpz_class msgDigest_FIX,
                        GSK_sig KP_BBS_san, mpz_class &m_p) {

    int pass = SVf(pp_S, PK_sig, sigma.sigma_FIX, msgDigest_FIX);
    if (pass) {
        cout << "In Saniting : SVf = 1 " << endl;
        Sigma_BFLS10 sigma_p = sigma;
        m_p = rand_mpz(state_BFLS10);
        mpz_class msgDigest_FULL = ComDigest_FULL(m_p, PK_sig);
        sigma_p.sigma_FULL = GSig(KP_BBS_san, msgDigest_FULL, sigma.gpk);
        return sigma_p;
    } else {
        cout << "In Saniting : SVf = 0 " << endl;
        return sigma;
    }
}

int Verification(Params_schnorr pp_S, ECP PK_sig, mpz_class msgDigest_FIX,
                 mpz_class msgDigest_FULL, Sigma_BFLS10 sigma) {
    return SVf(pp_S, PK_sig, sigma.sigma_FIX, msgDigest_FIX) && GVf(sigma.gpk, msgDigest_FULL, sigma.sigma_FULL);
}

mpz_class H_NIZK(ECP T1, ECP T2, ECP T3, ECP A, ECP R) {

    octet hash = getOctet(49);
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
    // A,R
    octet oct_A = getOctet(49);
    ECP_toOctet(&oct_A, &A, true);
    concatOctet(&hash, &oct_A);
    free(oct_A.val);
    octet oct_R = getOctet(49);
    ECP_toOctet(&oct_R, &R, true);
    concatOctet(&hash, &oct_R);
    free(oct_R.val);
    BIG order, result;
    BIG_rcopy(order, CURVE_Order);
    hashZp256(result, &hash, order);
    free(hash.val);

    return BIG_to_mpz(result);
}

PI NIZK_proof(mpz_class x1, mpz_class x2, ECP T1, ECP T2, ECP T3, ECP A) {
    PI pi;
    mpz_class r1 = rand_mpz(state_BFLS10);
    mpz_class r2 = rand_mpz(state_BFLS10);
    ECP R, S;
    ECP_copy(&R, &T1);
    ECP_mul(R, r1);
    ECP_copy(&S, &T2);
    ECP_mul(S, r2);
    ECP_add(&R, &S);

    pi.c = H_NIZK(T1, T2, T3, A, R);
    pi.s1 = (r1 + pi.c * x1) % q_BFLS10;
    pi.s2 = (r2 + pi.c * x2) % q_BFLS10;
    return pi;
}

bool NIZK_verify(PI pi, ECP T1, ECP T2, ECP T3, ECP A) {
    ECP R1, R2, R3, A_neg, neg_c_term;
    // R' = T1^s1 + T2^s2 + (-c * (T3/A))
    ECP_copy(&R1, &T1);
    ECP_mul(R1, pi.s1);
    ECP_copy(&R2, &T2);
    ECP_mul(R2, pi.s2);
    ECP_copy(&R3, &T3);
    ECP_copy(&A_neg, &A);
    ECP_neg(&A_neg);
    ECP_add(&R3, &A_neg);
    ECP_copy(&neg_c_term, &R3);
    ECP_mul(neg_c_term, pi.c);
    ECP_neg(&neg_c_term);
    ECP_add(&R1, &R2);
    ECP_add(&R1, &neg_c_term);

    return (H_NIZK(T1, T2, T3, A, R1) == pi.c);
}

Evidence Proof(Params_schnorr pp_S, ECP PK_sig, Sigma_BFLS10 sigma, mpz_class msgDigest_FIX, GPK gpk) {

    Evidence evidence;
    // The signer possesses the PRF key k, and can therefore run GKen using k to generate the group secret key gmsk.
    // For simplicity, we directly assign the group secret key to the signer.
    GMSK gmsk_temp;
    GPK gpk_temp;
    vector<ECP> PKs;
    mpz_class gamma = rand_mpz(state_BFLS10);
    GKGen(gmsk_temp, gpk_temp, PKs, gamma);
    //
    int pass = SVf(pp_S, PK_sig, sigma.sigma_FIX, msgDigest_FIX);
    if (pass != 1) {
        cout << "In Proof, SVf defeat" << endl;
        return evidence;
    }
    evidence.A = Open(gpk, gmsk_BFLS10, sigma.sigma_FULL);
    // generate NIZK
    evidence.pi = NIZK_proof(gmsk_BFLS10.ksi_1, gmsk_BFLS10.ksi_2, sigma.sigma_FULL.T_1, sigma.sigma_FULL.T_2,
                             sigma.sigma_FULL.T_3, evidence.A);
    return evidence;
}

int Judge(Evidence evidence, Sigma_BFLS10 sigma) {
    int idx = GJudge(evidence.A);
    bool pass = NIZK_verify(evidence.pi, sigma.sigma_FULL.T_1, sigma.sigma_FULL.T_2, sigma.sigma_FULL.T_3, evidence.A);
    if (pass) return idx;
    return 1;
}

int main() {
    initRNG(&rng_BFLS10);
    initState(state_BFLS10);
    mpz_class gamma = rand_mpz(state_BFLS10);
    // Setup
    Params_schnorr pp_S = Setup_schnorr();
    KeyPair_schnorr KP_schnorr_sig, KP_schnorr_san;
    GSK_sig KP_BBS_sig, KP_BBS_san;
    KeyGeneration(KP_schnorr_sig, KP_BBS_sig, pp_S, gamma);
    KeyGeneration(KP_schnorr_san, KP_BBS_san, pp_S, gamma);
    mpz_class m_FIX = rand_mpz(state_BFLS10);
    mpz_class m = rand_mpz(state_BFLS10);
    mpz_class ADM = rand_mpz(state_BFLS10);
    ECP PK_san; //
    ECP_copy(&PK_san, &KP_BBS_san.A);
    // Sign
    Sigma_BFLS10 sigma = Signing(KP_schnorr_sig, m_FIX, pp_S, KP_BBS_sig, m, PK_san, ADM, gamma);
    mpz_class msgDigest_FIX = ComDigest_FIX(m_FIX, ADM, PK_san, sigma.gpk);
    // Saniting
    mpz_class m_p;
    Sigma_BFLS10 sigma_p = Sanitizing(pp_S, KP_schnorr_sig.PK, sigma, msgDigest_FIX, KP_BBS_san, m_p);
    // Verify the validity of the signatures before and after sanitization separately
    mpz_class msgDigest_FULL = ComDigest_FULL(m, PK_san);
    int res = Verification(pp_S, KP_schnorr_sig.PK, msgDigest_FIX, msgDigest_FULL, sigma);
    cout << "verify sigma : " << res << endl;
    mpz_class msgDigest_FULL_p = ComDigest_FULL(m_p, PK_san);
    res = Verification(pp_S, KP_schnorr_sig.PK, msgDigest_FIX, msgDigest_FULL_p, sigma_p);
    cout << "verify sigma_p : " << res << endl;
    // Three scenarios for accountability
    printLine("Proof and Judge");
    Evidence evidence = Proof(pp_S, KP_schnorr_sig.PK, sigma, msgDigest_FIX, sigma.gpk);
    int idx = Judge(evidence, sigma);
    cout << "sigma was generated by : " << idx << endl;
    evidence = Proof(pp_S, KP_schnorr_sig.PK, sigma_p, msgDigest_FIX, sigma_p.gpk);
    idx = Judge(evidence, sigma_p);
    cout << "sigma was generated by : " << idx << endl;
    // Modify part of the BBS signature to make it invalid; in this case, Judge should return 0
    ECP_generator(&sigma_p.sigma_FULL.T_1);
    evidence = Proof(pp_S, KP_schnorr_sig.PK, sigma_p, msgDigest_FIX, sigma_p.gpk);
    idx = Judge(evidence, sigma_p);
    cout << "sigma was generated by : " << idx << endl;

    return 0;
}