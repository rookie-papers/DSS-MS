#include "../include/iut_k_san.h"

namespace IUT
{

    csprng rng;
    gmp_randstate_t state_gmp;

    // ============================================================
    // Serialization helpers
    // ============================================================

    string Serialize(VRS::VRS_PublicKey pk_SP, vector<string> &m_ext,
                     vector<IUT_SanitizerKey> &PKZ, IUT_SigmaSS &sigma_SS)
    {
        // Hash all components into a single scalar to avoid building an extremely long string
        // that could overflow internal octet buffers (1024-byte limit in appendToOctet for strings).
        mpz_class h = HashToZp(pk_SP.pk, m_ext, sigma_SS.mu, sigma_SS.eta,
                               sigma_SS.X_j, sigma_SS.Y_j, sigma_SS.sigma_j);
        return h.get_str(16);
    }

    // ============================================================
    // Setup
    // ============================================================
    Params Setup(size_t n, size_t k)
    {
        Params pp;
        pp.q = getCurveOrder();
        ECP_generator(&pp.g1);
        ECP2_generator(&pp.g2);
        pp.vrs_pp = VRS::V_Init();
        pp.eqs_pp = EQS::PPGen();
        return pp;
    }

    // ============================================================
    // KGen_S
    // ============================================================
    IUT_SignerKey KGen_S(Params pp, size_t expected_N)
    {
        IUT_SignerKey skS;

        size_t l = expected_N;
        auto [pk_eqs, sk_eqs] = EQS::KeyGen(pp.eqs_pp, l);
        skS.sk_EQS = sk_eqs;
        skS.pk_EQS = pk_eqs;

        auto [pk_sp, sk_sp] = VRS::V_Gen(pp.vrs_pp);
        skS.sk_SP = sk_sp;
        skS.pk_SP = pk_sp;

        return skS;
    }

    // ============================================================
    // KGen_Z
    // ============================================================
    IUT_SanitizerKey KGen_Z(Params pp)
    {
        IUT_SanitizerKey skZ;

        PKE::KGenPKE_full(2048, skZ.pk_ZE, skZ.sk_ZE);

        auto [pk_zp, sk_zp] = VRS::V_Gen(pp.vrs_pp);
        skZ.sk_ZP = sk_zp;
        skZ.pk_ZP = pk_zp;

        return skZ;
    }

    // ============================================================
    // Sign
    // ============================================================
    IUT_Signature Sign(Params pp, IUT_SignerKey skS, vector<IUT_SanitizerKey> &PKZ,
                       vector<string> &m, vector<vector<int>> &A)
    {
        mpz_class q = pp.q;
        size_t n = m.size();
        size_t k = PKZ.size();
        size_t N = n + k;

        // 1. Build extended message m_ext
        vector<string> m_ext = m;
        for (size_t i = 0; i < k; i++)
        {
            m_ext.push_back(PKE::SerializePK(PKZ[i].pk_ZE));
        }

        // 2. Build extended matrix A_ext
        vector<vector<int>> A_ext(k, vector<int>(N, 0));
        for (size_t i = 0; i < k; i++)
        {
            for (size_t j = 0; j < n; j++)
            {
                A_ext[i][j] = A[i][j];
            }
        }

        // 3. Init vectors
        vector<ECP> X(N), Y(N);
        vector<ECP2> sigma(N);
        vector<vector<PKE::PKE_Ciphertext>> SKZ(k, vector<PKE::PKE_Ciphertext>(N));
        vector<mpz_class> y_scalars(N);

        // 4. For j=0..N-1
        for (size_t j = 0; j < N; j++)
        {
            mpz_class x_j = rand_mpz(state_gmp);
            mpz_class y_j = rand_mpz(state_gmp);
            y_scalars[j] = y_j;

            // X[j] = x_j * g1
            ECP_copy(&X[j], &pp.g1);
            ECP_mul(X[j], x_j);

            // Y[j] = y_j * X[j]
            ECP_copy(&Y[j], &X[j]);
            ECP_mul(Y[j], y_j);

            // H_j = HashToG2(j, m_ext[j])
            ECP2 H_j;
            HashToG2(H_j, to_string(j), m_ext[j]);

            // sigma[j] = y_j * H_j
            ECP2_copy(&sigma[j], &H_j);
            ECP2_mul(sigma[j], y_j);
        }

        // 6. mu = EQS::Sign(skS.sk_EQS, X)
        EQS::Merc_Signature mu = EQS::Sign(pp.eqs_pp, skS.sk_EQS, X);

        // 7. eta = EQS::Sign(skS.sk_EQS, Y)
        EQS::Merc_Signature eta = EQS::Sign(pp.eqs_pp, skS.sk_EQS, Y);

        // 8. Build SKZ ciphertext matrix
        for (size_t i = 0; i < k; i++)
        {
            for (size_t j = 0; j < N; j++)
            {
                mpz_class payload;
                if (A_ext[i][j] == 1)
                {
                    payload = y_scalars[j];
                }
                else
                {
                    payload = mpz_class(0);
                }
                SKZ[i][j] = PKE::EncryptPKE(PKZ[i].pk_ZE, payload);
            }
        }

        // 9. Assemble sigma_SS
        IUT_SigmaSS sigma_SS;
        sigma_SS.mu = mu;
        sigma_SS.eta = eta;
        sigma_SS.sigma_j = sigma;
        sigma_SS.X_j = X;
        sigma_SS.Y_j = Y;
        sigma_SS.SKZ = SKZ;

        // 10. Build ring L
        vector<ECP> L;
        L.push_back(skS.pk_SP.pk);
        for (size_t i = 0; i < k; i++)
        {
            L.push_back(PKZ[i].pk_ZP.pk);
        }

        // 11. t = Serialize(pk_SP, m_ext, PKZ, sigma_SS)
        string t = Serialize(skS.pk_SP, m_ext, PKZ, sigma_SS);

        // 12. sigma_VRS = VRS::Sig(L, t, skS.sk_SP, 0)
        VRS::VRS_Signature sigma_VRS = VRS::V_Sig(pp.vrs_pp, L, t, skS.sk_SP, 0);

        // 13. Return
        IUT_Signature sig;
        sig.sigma_SS = sigma_SS;
        sig.sigma_VRS = sigma_VRS;
        return sig;
    }

    // ============================================================
    // Sanitize
    // ============================================================
    IUT_Signature Sanitize(Params pp, IUT_SanitizerKey &skZ, IUT_SignerKey &pkS,
                           vector<IUT_SanitizerKey> &PKZ, vector<string> &m,
                           vector<int> &MOD_indices, vector<string> &m_prime,
                           IUT_Signature &sig)
    {
        mpz_class q = pp.q;
        size_t n = m.size();
        size_t k = PKZ.size();
        size_t N = n + k;

        // 1. Find i_prime = index of skZ in PKZ
        int i_prime = -1;
        for (size_t i = 0; i < k; i++)
        {
            if (PKZ[i].pk_ZE.n == skZ.pk_ZE.n)
            {
                i_prime = (int)i;
                break;
            }
        }
        if (i_prime == -1)
            throw runtime_error("Sanitizer key not found in PKZ");

        // 2. Build m_ext_prime
        vector<string> m_ext_prime = m_prime;
        for (size_t i = 0; i < k; i++)
        {
            m_ext_prime.push_back(PKE::SerializePK(PKZ[i].pk_ZE));
        }

        // 3. Random r, s. rs = (r*s)%q
        mpz_class r = rand_mpz(state_gmp);
        mpz_class s = rand_mpz(state_gmp);
        mpz_class rs = (r * s) % q;

        // 4. sigma_prime(N)
        vector<ECP2> sigma_prime(N);

        // 5. [X_prime, mu_prime] = EQS::ChangeRep
        auto [X_prime, mu_prime] = EQS::ChangeRep(pp.eqs_pp, pkS.pk_EQS,
                                                  sig.sigma_SS.X_j, sig.sigma_SS.mu, r);

        // 6. [Y_prime, eta_prime] = EQS::ChangeRep
        auto [Y_prime, eta_prime] = EQS::ChangeRep(pp.eqs_pp, pkS.pk_EQS,
                                                   sig.sigma_SS.Y_j, sig.sigma_SS.eta, rs);

        // 7. For j=0..N-1
        for (size_t j = 0; j < N; j++)
        {
            bool in_mod = false;
            for (auto idx : MOD_indices)
            {
                if ((size_t)idx == j)
                {
                    in_mod = true;
                    break;
                }
            }

            if (in_mod)
            {
                // i. zeta_raw = Decrypt
                mpz_class zeta_raw = PKE::DecryptPKE(skZ.pk_ZE, skZ.sk_ZE,
                                                     sig.sigma_SS.SKZ[i_prime][j]);
                // ii. zeta = zeta_raw % q
                mpz_class zeta = zeta_raw % q;
                // iii. if zeta==0: unauthorized
                if (zeta == mpz_class(0))
                {
                    throw runtime_error("Unauthorized sanitization: zeta is zero");
                }
                // iv. new_scalar = (zeta * s) % q
                mpz_class new_scalar = (zeta * s) % q;

                // v. H_prime = HashToG2(j, m_ext_prime[j])
                ECP2 H_prime;
                HashToG2(H_prime, to_string(j), m_ext_prime[j]);

                // vi. sigma_prime[j] = new_scalar * H_prime
                ECP2_copy(&sigma_prime[j], &H_prime);
                ECP2_mul(sigma_prime[j], new_scalar);
            }
            else
            {
                // sigma_prime[j] = s * sig.sigma_SS.sigma_j[j]
                ECP2_copy(&sigma_prime[j], &sig.sigma_SS.sigma_j[j]);
                ECP2_mul(sigma_prime[j], s);
            }
        }

        // 8. SKZ_prime
        vector<vector<PKE::PKE_Ciphertext>> SKZ_prime(k, vector<PKE::PKE_Ciphertext>(N));
        for (size_t i = 0; i < k; i++)
        {
            for (size_t j = 0; j < N; j++)
            {
                SKZ_prime[i][j] = PKE::MultiplyPKE(PKZ[i].pk_ZE, sig.sigma_SS.SKZ[i][j], s);
            }
        }

        // 9. sigma_SS_prime
        IUT_SigmaSS sigma_SS_prime;
        sigma_SS_prime.mu = mu_prime;
        sigma_SS_prime.eta = eta_prime;
        sigma_SS_prime.sigma_j = sigma_prime;
        sigma_SS_prime.X_j = X_prime;
        sigma_SS_prime.Y_j = Y_prime;
        sigma_SS_prime.SKZ = SKZ_prime;

        // 10. Build ring L. my_index = i_prime + 1
        vector<ECP> L;
        L.push_back(pkS.pk_SP.pk);
        for (size_t i = 0; i < k; i++)
        {
            L.push_back(PKZ[i].pk_ZP.pk);
        }
        size_t my_index = (size_t)i_prime + 1;

        // 11. t_prime = Serialize
        string t_prime = Serialize(pkS.pk_SP, m_ext_prime, PKZ, sigma_SS_prime);

        // 12. sigma_VRS_prime
        VRS::VRS_Signature sigma_VRS_prime = VRS::V_Sig(pp.vrs_pp, L, t_prime, skZ.sk_ZP, my_index);

        // 13. Return
        IUT_Signature sig_prime;
        sig_prime.sigma_SS = sigma_SS_prime;
        sig_prime.sigma_VRS = sigma_VRS_prime;
        return sig_prime;
    }

    // ============================================================
    // Verify
    // ============================================================
    bool Verify(Params pp, IUT_SignerKey &pkS, vector<IUT_SanitizerKey> &PKZ,
                vector<string> &m, IUT_Signature &sig)
    {
        size_t n = m.size();
        size_t k = PKZ.size();
        size_t N = n + k;

        // 1. Build m_ext
        vector<string> m_ext = m;
        for (size_t i = 0; i < k; i++)
        {
            m_ext.push_back(PKE::SerializePK(PKZ[i].pk_ZE));
        }

        // 2. Build ring L
        vector<ECP> L;
        L.push_back(pkS.pk_SP.pk);
        for (size_t i = 0; i < k; i++)
        {
            L.push_back(PKZ[i].pk_ZP.pk);
        }

        // t = Serialize
        string t = Serialize(pkS.pk_SP, m_ext, PKZ, sig.sigma_SS);

        // b1 = VRS::Ver
        bool b1 = VRS::V_Ver(pp.vrs_pp, L, t, sig.sigma_VRS);
        if (!b1)
            return false;

        // 3. Check Y_j not infinity
        for (size_t j = 0; j < N; j++)
        {
            ECP inf_pt;
            ECP_inf(&inf_pt);
            if (ECP_equals(&sig.sigma_SS.Y_j[j], &inf_pt))
                return false;
        }

        // 4. Verify EQS signatures
        bool b3 = EQS::Verify(pp.eqs_pp, pkS.pk_EQS, sig.sigma_SS.X_j, sig.sigma_SS.mu);
        if (!b3)
            return false;

        bool b4 = EQS::Verify(pp.eqs_pp, pkS.pk_EQS, sig.sigma_SS.Y_j, sig.sigma_SS.eta);
        if (!b4)
            return false;

        // 5. Pairing checks
        for (size_t j = 0; j < N; j++)
        {
            ECP2 H_j;
            HashToG2(H_j, to_string(j), m_ext[j]);

            FP12 lhs = e(sig.sigma_SS.X_j[j], sig.sigma_SS.sigma_j[j]);
            FP12 rhs = e(sig.sigma_SS.Y_j[j], H_j);

            if (!FP12_equals(&lhs, &rhs))
                return false;
        }

        return true;
    }

    // ============================================================
    // Prove
    // ============================================================
    VRS::VRS_Proof_Judge Prove(IUT_SignerKey &skS, vector<IUT_SanitizerKey> &PKZ,
                               vector<string> &m, IUT_Signature &sig)
    {
        size_t k = PKZ.size();

        // Build m_ext
        vector<string> m_ext = m;
        for (size_t i = 0; i < k; i++)
        {
            m_ext.push_back(PKE::SerializePK(PKZ[i].pk_ZE));
        }

        // Build ring L
        vector<ECP> L;
        L.push_back(skS.pk_SP.pk);
        for (size_t i = 0; i < k; i++)
        {
            L.push_back(PKZ[i].pk_ZP.pk);
        }

        // t = Serialize
        string t = Serialize(skS.pk_SP, m_ext, PKZ, sig.sigma_SS);

        // pi = VRS::Proof
        VRS::VRS_Proof_Judge pi = VRS::V_Proof(VRS::V_Init(), L, t, sig.sigma_VRS,
                                               skS.pk_SP, skS.sk_SP);
        return pi;
    }

    // ============================================================
    // Judge
    // ============================================================
    int Judge(IUT_SignerKey &pkS, vector<IUT_SanitizerKey> &PKZ,
              vector<string> &m, IUT_Signature &sig, VRS::VRS_Proof_Judge pi)
    {
        // 1. Verify signature
        Params pp;
        pp.q = getCurveOrder();
        pp.vrs_pp = VRS::V_Init();
        pp.eqs_pp = EQS::PPGen();

        IUT_SignerKey pkS_pub;
        pkS_pub.pk_EQS = pkS.pk_EQS;
        pkS_pub.pk_SP = pkS.pk_SP;

        bool ok = Verify(pp, pkS_pub, PKZ, m, sig);
        if (!ok)
            return -1;

        // 2. Build m_ext
        size_t k = PKZ.size();
        vector<string> m_ext = m;
        for (size_t i = 0; i < k; i++)
        {
            m_ext.push_back(PKE::SerializePK(PKZ[i].pk_ZE));
        }

        // 3. Build ring L
        vector<ECP> L;
        L.push_back(pkS.pk_SP.pk);
        for (size_t i = 0; i < k; i++)
        {
            L.push_back(PKZ[i].pk_ZP.pk);
        }

        // 4. t = Serialize
        string t = Serialize(pkS.pk_SP, m_ext, PKZ, sig.sigma_SS);

        // 5. b = VRS::Judge
        int b = VRS::V_Judge(pp.vrs_pp, L, t, sig.sigma_VRS, pkS.pk_SP, pi);

        return b;
    }

} // namespace IUT
