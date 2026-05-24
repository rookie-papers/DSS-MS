#include "../include/PF_CLSS_DV.h"

namespace PF_CLSS_DV {

    // Instantiate global random number states
    csprng rng;
    gmp_randstate_t state_gmp;

    // =====================================================================
    // Setup: generate system parameters and master key
    // =====================================================================
    tuple<Params, MasterKey> Setup() {
        mpz_class q = getCurveOrder();

        ECP P;
        ECP_generator(&P);

        mpz_class s = rand_mpz(state_gmp) % q;

        ECP Q_pub;
        ECP_copy(&Q_pub, &P);
        ECP_mul(Q_pub, s);

        Params pp{q, P, Q_pub};
        MasterKey msk{s};
        return make_tuple(pp, msk);
    }

    // =====================================================================
    // VerKeyGen: generate verifier key pair
    // =====================================================================
    VerifierKey VerKeyGen(Params pp) {
        mpz_class x_V = rand_mpz(state_gmp) % pp.q;

        ECP PK_V;
        ECP_copy(&PK_V, &pp.P);
        ECP_mul(PK_V, x_V);

        return VerifierKey{x_V, PK_V};
    }

    // =====================================================================
    // PartialKeyGen: KGC generates partial key for signer ID_O
    // =====================================================================
    PartialKey PartialKeyGen(Params pp, MasterKey msk, string ID_O) {
        mpz_class r = rand_mpz(state_gmp) % pp.q;

        ECP R;
        ECP_copy(&R, &pp.P);
        ECP_mul(R, r);

        mpz_class h1 = HashToZp(ID_O, R);

        // d = (r + s * h1) mod q
        mpz_class d = (r + (msk.s * h1) % pp.q) % pp.q;

        return PartialKey{R, d};
    }

    // =====================================================================
    // SinKeyGen: signer generates full key pair from partial key
    // =====================================================================
    tuple<SignerPubKey, SignerPrivKey> SinKeyGen(Params pp, string ID_O, PartialKey pak) {
        mpz_class x_O = rand_mpz(state_gmp) % pp.q;

        ECP X_O;
        ECP_copy(&X_O, &pp.P);
        ECP_mul(X_O, x_O);

        SignerPubKey PK_O{pak.R, X_O};
        SignerPrivKey SK_O{pak.d, x_O};

        return make_tuple(PK_O, SK_O);
    }

    // =====================================================================
    // Sign: produce a signature and authentication token
    // =====================================================================
    tuple<Signature, AuthToken> Sign(
        Params pp, string ID_O, SignerPrivKey SK_O, Message M, ECP PK_V)
    {
        mpz_class q = pp.q;
        mpz_class x_O = SK_O.x_O;
        mpz_class d   = SK_O.d;

        // 1. Random blinding factors
        mpz_class t1 = rand_mpz(state_gmp) % q;
        mpz_class t2 = rand_mpz(state_gmp) % q;

        // 2. T1 = t1 * P, T2 = t2 * P
        ECP T1, T2;
        ECP_copy(&T1, &pp.P);
        ECP_mul(T1, t1);
        ECP_copy(&T2, &pp.P);
        ECP_mul(T2, t2);

        // 3. Hash message components
        mpz_class h21 = HashToZp(M.m1, ID_O);
        mpz_class h22 = HashToZp(M.m2, ID_O);

        // 4. ECDH shared point = x_O * PK_V
        ECP shared_point;
        ECP_copy(&shared_point, &PK_V);
        ECP_mul(shared_point, x_O);

        // 5. Hash shared secret
        mpz_class h3 = HashToZp(ID_O, shared_point);

        // 6. Modular inverses of t1, t2
        mpz_class inv_t1 = invert_mpz(t1, q);
        mpz_class inv_t2 = invert_mpz(t2, q);

        // 7. u1 = inv_t1 * (h21 * h3 * x_O + d) mod q
        mpz_class core1 = (h21 * h3) % q;
        core1 = (core1 * x_O) % q;
        core1 = (core1 + d) % q;
        mpz_class u1 = (inv_t1 * core1) % q;

        // 8. u2 = inv_t2 * (h22 * h3 * x_O + d) mod q
        mpz_class core2 = (h22 * h3) % q;
        core2 = (core2 * x_O) % q;
        core2 = (core2 + d) % q;
        mpz_class u2 = (inv_t2 * core2) % q;

        // 9. AT1 = inv_t1 * (h3 * x_O) mod q
        mpz_class core_AT = (h3 * x_O) % q;
        mpz_class AT1 = (inv_t1 * core_AT) % q;

        Signature sig{u1, u2, T1, T2};
        AuthToken at{AT1};
        return make_tuple(sig, at);
    }

    // =====================================================================
    // Sanitize: sanitizer replaces m1 with m1' and adjusts signature
    // =====================================================================
    tuple<Message, Signature> Sanitize(
        Params pp, string ID_O, Message M, Signature sig, AuthToken at, string m1_prime)
    {
        mpz_class q = pp.q;

        mpz_class h21    = HashToZp(M.m1, ID_O);
        mpz_class h21_prime = HashToZp(m1_prime, ID_O);

        // diff = h21' - h21  (mod q, non-negative)
        mpz_class diff = mod_sub(h21_prime, h21, q);

        // u1' = u1 + AT1 * diff  (mod q)
        mpz_class delta_u = (at.AT1 * diff) % q;
        mpz_class u1_prime = (sig.u1 + delta_u) % q;

        mpz_class u2_prime = sig.u2;

        Message M_prime{m1_prime, M.m2};
        Signature sig_prime{u1_prime, u2_prime, sig.T1, sig.T2};

        return make_tuple(M_prime, sig_prime);
    }

    // =====================================================================
    // Verify: check signature validity
    // =====================================================================
    bool Verify(
        Params pp, string ID_O, SignerPubKey PK_O, VerifierKey VK_V,
        Message M_star, Signature sig_star)
    {
        mpz_class q = pp.q;

        // 1. h1 = H(ID_O, R)
        mpz_class h1 = HashToZp(ID_O, PK_O.R);

        // 2. Hash sanitized message components
        mpz_class h21_star = HashToZp(M_star.m1, ID_O);
        mpz_class h22_star = HashToZp(M_star.m2, ID_O);

        // 3. ECDH shared point = VK_V.SK_V * PK_O.X_O
        ECP shared_point;
        ECP_copy(&shared_point, &PK_O.X_O);
        ECP_mul(shared_point, VK_V.SK_V);

        // 4. h3 = H(ID_O, shared_point)
        mpz_class h3 = HashToZp(ID_O, shared_point);

        // 5. base_offset = R + h1 * Q_pub
        ECP h1_Q;
        ECP_copy(&h1_Q, &pp.Q_pub);
        ECP_mul(h1_Q, h1);

        ECP base_offset;
        ECP_copy(&base_offset, &PK_O.R);
        ECP_add(&base_offset, &h1_Q);

        // 6. RHS1 = (1/u1) * (h21*h3 * X_O + base_offset)
        mpz_class scalar1 = (h21_star * h3) % q;
        ECP InnerP1;
        ECP_copy(&InnerP1, &PK_O.X_O);
        ECP_mul(InnerP1, scalar1);
        ECP_add(&InnerP1, &base_offset);

        mpz_class inv_u1 = invert_mpz(sig_star.u1, q);
        ECP RHS1;
        ECP_copy(&RHS1, &InnerP1);
        ECP_mul(RHS1, inv_u1);

        // 7. RHS2 = (1/u2) * (h22*h3 * X_O + base_offset)
        mpz_class scalar2 = (h22_star * h3) % q;
        ECP InnerP2;
        ECP_copy(&InnerP2, &PK_O.X_O);
        ECP_mul(InnerP2, scalar2);
        ECP_add(&InnerP2, &base_offset);

        mpz_class inv_u2 = invert_mpz(sig_star.u2, q);
        ECP RHS2;
        ECP_copy(&RHS2, &InnerP2);
        ECP_mul(RHS2, inv_u2);

        // 8. RHS_Total = RHS1 + RHS2
        ECP RHS_Total;
        ECP_copy(&RHS_Total, &RHS1);
        ECP_add(&RHS_Total, &RHS2);

        // 9. LHS_Total = T1 + T2
        ECP LHS_Total;
        ECP_copy(&LHS_Total, &sig_star.T1);
        ECP_add(&LHS_Total, &sig_star.T2);

        // 10. Compare
        return ECP_equals(&LHS_Total, &RHS_Total) == 1;
    }

} // namespace PF_CLSS_DV
