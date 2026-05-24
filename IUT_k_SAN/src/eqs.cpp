#include "../include/iut_k_san.h"

namespace EQS
{

    csprng rng;
    gmp_randstate_t state_gmp;

    Merc_Params PPGen()
    {
        Merc_Params pp;
        pp.p = getCurveOrder();
        ECP_generator(&pp.P);
        ECP2_generator(&pp.P_hat);
        return pp;
    }

    pair<Merc_PublicKey, Merc_SecretKey> KeyGen(Merc_Params pp, size_t l)
    {
        Merc_SecretKey sk;
        Merc_PublicKey pk;
        sk.x.resize(l);
        pk.X_hat.resize(l);
        for (size_t i = 0; i < l; i++)
        {
            sk.x[i] = rand_mpz(state_gmp);
            ECP2_copy(&pk.X_hat[i], &pp.P_hat);
            ECP2_mul(pk.X_hat[i], sk.x[i]);
        }
        return {pk, sk};
    }

    Merc_Signature Sign(Merc_Params pp, Merc_SecretKey sk, vector<ECP> &M)
    {
        mpz_class p = pp.p;
        size_t l = sk.x.size();

        // Random y
        mpz_class y = rand_mpz(state_gmp);
        mpz_class inv_y = invert_mpz(y, p);

        // Y = inv_y * P
        ECP Y;
        ECP_copy(&Y, &pp.P);
        ECP_mul(Y, inv_y);

        // Y_hat = inv_y * P_hat
        ECP2 Y_hat;
        ECP2_copy(&Y_hat, &pp.P_hat);
        ECP2_mul(Y_hat, inv_y);

        // Z_base = sum(x[i] * M[i])
        ECP Z_base;
        ECP_inf(&Z_base);
        for (size_t i = 0; i < l; i++)
        {
            ECP tmp;
            ECP_copy(&tmp, &M[i]);
            ECP_mul(tmp, sk.x[i]);
            ECP_add(&Z_base, &tmp);
        }

        // Z = y * Z_base
        ECP Z;
        ECP_copy(&Z, &Z_base);
        ECP_mul(Z, y);

        Merc_Signature sig;
        ECP_copy(&sig.Z, &Z);
        ECP_copy(&sig.Y, &Y);
        ECP2_copy(&sig.Y_hat, &Y_hat);
        return sig;
    }

    bool Verify(Merc_Params pp, Merc_PublicKey pk, vector<ECP> &M, Merc_Signature sig)
    {
        size_t l = pk.X_hat.size();

        // Check 1: product e(M[i], X_hat[i]) == e(Z, Y_hat)
        FP12 lhs1;
        FP12_one(&lhs1);
        for (size_t i = 0; i < l; i++)
        {
            FP12 ei = e(M[i], pk.X_hat[i]);
            FP12_mulMy(lhs1, ei);
        }
        FP12 rhs1 = e(sig.Z, sig.Y_hat);
        if (!FP12_equals(&lhs1, &rhs1))
            return false;

        // Check 2: e(Y, P_hat) == e(P, Y_hat)
        FP12 lhs2 = e(sig.Y, pp.P_hat);
        FP12 rhs2 = e(pp.P, sig.Y_hat);
        if (!FP12_equals(&lhs2, &rhs2))
            return false;

        return true;
    }

    Merc_SecretKey ConvertSK(Merc_Params pp, Merc_SecretKey sk, mpz_class rho)
    {
        mpz_class p = pp.p;
        Merc_SecretKey sk_new;
        sk_new.x.resize(sk.x.size());
        for (size_t i = 0; i < sk.x.size(); i++)
        {
            sk_new.x[i] = (sk.x[i] * rho) % p;
        }
        return sk_new;
    }

    Merc_PublicKey ConvertPK(Merc_PublicKey pk, mpz_class rho)
    {
        Merc_PublicKey pk_new;
        pk_new.X_hat.resize(pk.X_hat.size());
        for (size_t i = 0; i < pk.X_hat.size(); i++)
        {
            ECP2_copy(&pk_new.X_hat[i], &pk.X_hat[i]);
            ECP2_mul(pk_new.X_hat[i], rho);
        }
        return pk_new;
    }

    Merc_Signature ConvertSig(Merc_Params pp, Merc_PublicKey pk, vector<ECP> &M,
                              Merc_Signature sig, mpz_class rho)
    {
        mpz_class p = pp.p;

        // Random psi
        mpz_class psi = rand_mpz(state_gmp);
        mpz_class inv_psi = invert_mpz(psi, p);

        // scalar_z = psi * rho mod p
        mpz_class scalar_z = (psi * rho) % p;

        // Z' = scalar_z * Z
        ECP Zp;
        ECP_copy(&Zp, &sig.Z);
        ECP_mul(Zp, scalar_z);

        // Y' = inv_psi * Y
        ECP Yp;
        ECP_copy(&Yp, &sig.Y);
        ECP_mul(Yp, inv_psi);

        // Y_hat' = inv_psi * Y_hat
        ECP2 Y_hatp;
        ECP2_copy(&Y_hatp, &sig.Y_hat);
        ECP2_mul(Y_hatp, inv_psi);

        Merc_Signature sig_new;
        ECP_copy(&sig_new.Z, &Zp);
        ECP_copy(&sig_new.Y, &Yp);
        ECP2_copy(&sig_new.Y_hat, &Y_hatp);
        return sig_new;
    }

    pair<vector<ECP>, Merc_Signature> ChangeRep(Merc_Params pp, Merc_PublicKey pk,
                                                vector<ECP> &M, Merc_Signature sig, mpz_class mu)
    {
        mpz_class p = pp.p;

        // Random psi
        mpz_class psi = rand_mpz(state_gmp);
        mpz_class inv_psi = invert_mpz(psi, p);

        // M'[i] = mu * M[i]
        vector<ECP> Mp(M.size());
        for (size_t i = 0; i < M.size(); i++)
        {
            ECP_copy(&Mp[i], &M[i]);
            ECP_mul(Mp[i], mu);
        }

        // scalar_z = psi * mu mod p
        mpz_class scalar_z = (psi * mu) % p;

        // Z' = scalar_z * Z
        ECP Zp;
        ECP_copy(&Zp, &sig.Z);
        ECP_mul(Zp, scalar_z);

        // Y' = inv_psi * Y
        ECP Yp;
        ECP_copy(&Yp, &sig.Y);
        ECP_mul(Yp, inv_psi);

        // Y_hat' = inv_psi * Y_hat
        ECP2 Y_hatp;
        ECP2_copy(&Y_hatp, &sig.Y_hat);
        ECP2_mul(Y_hatp, inv_psi);

        Merc_Signature sig_new;
        ECP_copy(&sig_new.Z, &Zp);
        ECP_copy(&sig_new.Y, &Yp);
        ECP2_copy(&sig_new.Y_hat, &Y_hatp);
        return {Mp, sig_new};
    }

} // namespace EQS
