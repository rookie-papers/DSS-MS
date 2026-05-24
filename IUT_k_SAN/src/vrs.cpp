#include "../include/iut_k_san.h"

namespace VRS
{

    csprng rng;
    gmp_randstate_t state_gmp;

    // ---------- Internal: LEprove_n ----------
    // 这里针对本方案进行了优化
    static LogEq_Proof LEprove_n(VRS_Params pp, vector<ECP> &L, ECP h, ECP z, mpz_class x, size_t j)
    {
        mpz_class p = pp.p;
        size_t n = L.size();

        vector<ECP> R(n), S(n);
        vector<mpz_class> c(n), gamma(n);

        // For real signer j: random r_j
        mpz_class r_j = rand_mpz(state_gmp);

        // R[j] = r_j * G, S[j] = r_j * h
        ECP_copy(&R[j], &pp.G);
        ECP_mul(R[j], r_j);
        ECP_copy(&S[j], &h);
        ECP_mul(S[j], r_j);

        // For i != j: random c_i, gamma_i
        mpz_class prod_c("1");
        for (size_t i = 0; i < n; i++)
        {
            if (i == j)
                continue;
            c[i] = rand_mpz(state_gmp);
            gamma[i] = rand_mpz(state_gmp);
            prod_c = (prod_c * c[i]) % p;

            mpz_class neg_c_i = (p - c[i]) % p;

            // R[i] = gamma_i * G + neg_c_i * L[i]
            ECP tmp1, tmp2;
            ECP_copy(&tmp1, &pp.G);
            ECP_mul(tmp1, gamma[i]);
            ECP_copy(&tmp2, &L[i]);
            ECP_mul(tmp2, neg_c_i);
            ECP_add(&tmp1, &tmp2);
            ECP_copy(&R[i], &tmp1);

            // S[i] = gamma_i * h + neg_c_i * z
            ECP tmp3, tmp4;
            ECP_copy(&tmp3, &h);
            ECP_mul(tmp3, gamma[i]);
            ECP_copy(&tmp4, &z);
            ECP_mul(tmp4, neg_c_i);
            ECP_add(&tmp3, &tmp4);
            ECP_copy(&S[i], &tmp3);
        }

        // c_hash = HashToZp(R[0]||S[0]||...||R[n-1]||S[n-1]) % p
        vector<ECP> all_points;
        for (size_t i = 0; i < n; i++)
        {
            all_points.push_back(R[i]);
            all_points.push_back(S[i]);
        }
        mpz_class c_hash = HashToZp(all_points) % p;

        // inv_prod = prod_c^{-1} mod p
        mpz_class inv_prod = invert_mpz(prod_c, p);

        // c[j] = c_hash * inv_prod mod p
        c[j] = (c_hash * inv_prod) % p;

        // gamma[j] = r_j + c[j]*x mod p
        gamma[j] = (r_j + (c[j] * x) % p) % p;

        LogEq_Proof proof;
        proof.R = R;
        proof.S = S;
        proof.c = c;
        proof.gamma = gamma;
        return proof;
    }

    // ---------- Internal: LEverif_n ----------
    static bool LEverif_n(VRS_Params pp, vector<ECP> &L, ECP h, ECP z, LogEq_Proof P)
    {
        mpz_class p = pp.p;
        size_t n = L.size();

        // c_hash = HashToZp(R[0]||S[0]||...||R[n-1]||S[n-1]) % p
        vector<ECP> all_points;
        for (size_t i = 0; i < n; i++)
        {
            all_points.push_back(P.R[i]);
            all_points.push_back(P.S[i]);
        }
        mpz_class c_hash = HashToZp(all_points) % p;

        // prod_c = product of all c[i] mod p
        mpz_class prod_c("1");
        for (size_t i = 0; i < n; i++)
        {
            prod_c = (prod_c * P.c[i]) % p;
        }
        if (prod_c != c_hash)
            return false;

        // For each i: gamma[i]*G == R[i] + c[i]*L[i]  AND  gamma[i]*h == S[i] + c[i]*z
        for (size_t i = 0; i < n; i++)
        {
            // gamma[i]*G == R[i] + c[i]*L[i]
            ECP lhs1, rhs1;
            ECP_copy(&lhs1, &pp.G);
            ECP_mul(lhs1, P.gamma[i]);

            ECP_copy(&rhs1, &L[i]);
            ECP_mul(rhs1, P.c[i]);
            ECP_add(&rhs1, &P.R[i]);

            if (!ECP_equals(&lhs1, &rhs1))
                return false;

            // gamma[i]*h == S[i] + c[i]*z
            ECP lhs2, rhs2;
            ECP_copy(&lhs2, &h);
            ECP_mul(lhs2, P.gamma[i]);

            ECP_copy(&rhs2, &z);
            ECP_mul(rhs2, P.c[i]);
            ECP_add(&rhs2, &P.S[i]);

            if (!ECP_equals(&lhs2, &rhs2))
                return false;
        }

        return true;
    }

    // ---------- VRS Algorithms ----------

    VRS_Params V_Init()
    {
        VRS_Params pp;
        pp.p = getCurveOrder();
        ECP_generator(&pp.G);
        return pp;
    }

    pair<VRS_PublicKey, VRS_SecretKey> V_Gen(VRS_Params pp)
    {
        VRS_SecretKey sk;
        sk.sk = rand_mpz(state_gmp);
        VRS_PublicKey pk;
        ECP_copy(&pk.pk, &pp.G);
        ECP_mul(pk.pk, sk.sk);
        return {pk, sk};
    }

    VRS_Signature V_Sig(VRS_Params pp, vector<ECP> &L, string m, VRS_SecretKey sk, size_t my_index)
    {
        mpz_class p = pp.p;

        // Random r
        mpz_class r = rand_mpz(state_gmp);

        // h = HashToG1(m || r)
        ECP h;
        HashToG1(h, m, r);

        // z = sk * h
        ECP z;
        ECP_copy(&z, &h);
        ECP_mul(z, sk.sk);

        // P = LEprove_n(L, h, z, sk, my_index)
        LogEq_Proof P = LEprove_n(pp, L, h, z, sk.sk, my_index);

        VRS_Signature sig;
        sig.r = r;
        ECP_copy(&sig.z, &z);
        sig.P = P;
        return sig;
    }

    bool V_Ver(VRS_Params pp, vector<ECP> &L, string m, VRS_Signature sig)
    {
        // h = HashToG1(m || r)
        ECP h;
        HashToG1(h, m, sig.r);

        return LEverif_n(pp, L, h, sig.z, sig.P);
    }

    VRS_Proof_Judge V_Proof(VRS_Params pp, vector<ECP> &L, string m, VRS_Signature sig,
                            VRS_PublicKey my_pk, VRS_SecretKey my_sk)
    {
        // h = HashToG1(m || r)
        ECP h;
        HashToG1(h, m, sig.r);

        // z_bar = my_sk * h
        ECP z_bar;
        ECP_copy(&z_bar, &h);
        ECP_mul(z_bar, my_sk.sk);

        // L_single = {my_pk.pk}
        vector<ECP> L_single;
        L_single.push_back(my_pk.pk);

        // P_bar = LEprove_n(L_single, h, z_bar, my_sk, 0)
        LogEq_Proof P_bar = LEprove_n(pp, L_single, h, z_bar, my_sk.sk, 0);

        VRS_Proof_Judge pi;
        ECP_copy(&pi.z_bar, &z_bar);
        pi.P_bar = P_bar;
        return pi;
    }

    int V_Judge(VRS_Params pp, vector<ECP> &L, string m, VRS_Signature sig,
                VRS_PublicKey target_pk, VRS_Proof_Judge pi)
    {
        // h = HashToG1(m || r)
        ECP h;
        HashToG1(h, m, sig.r);

        // L_single = {target_pk.pk}
        vector<ECP> L_single;
        L_single.push_back(target_pk.pk);

        // b = LEverif_n(L_single, h, pi.z_bar, pi.P_bar)
        bool b = LEverif_n(pp, L_single, h, pi.z_bar, pi.P_bar);
        if (!b)
            return -1;

        // if sig.z == pi.z_bar return 1 else return 0
        if (ECP_equals(&sig.z, &pi.z_bar))
            return 1;
        return 0;
    }

} // namespace VRS
