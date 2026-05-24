#include "../include/iut_k_san.h"
#include <gmpxx.h>

namespace PKE
{

    csprng rng;
    gmp_randstate_t state_gmp;

    // ---------- Internal helpers ----------
    static mpz_class random_prime_bits(int bits, gmp_randstate_t &state)
    {
        mpz_class p;
        mpz_urandomb(p.get_mpz_t(), state, bits);
        mpz_nextprime(p.get_mpz_t(), p.get_mpz_t());
        return p;
    }

    static mpz_class lcm(mpz_class a, mpz_class b)
    {
        mpz_class g;
        mpz_gcd(g.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
        return (a / g) * b;
    }

    static mpz_class L_func(mpz_class x, mpz_class n)
    {
        return (x - mpz_class(1)) / n;
    }

    // ---------- Paillier Algorithms ----------

    PKE_PublicKey KGenPKE(int lambda_bits)
    {
        int half = lambda_bits / 2;

        mpz_class p = random_prime_bits(half, state_gmp);
        mpz_class q = random_prime_bits(half, state_gmp);
        while (p == q)
        {
            q = random_prime_bits(half, state_gmp);
        }

        mpz_class n = p * q;
        mpz_class n_sq = n * n;
        mpz_class lambda_val = lcm(p - mpz_class(1), q - mpz_class(1));
        mpz_class g = n + mpz_class(1);

        mpz_class u = pow_mpz(g, lambda_val, n_sq);
        mpz_class L_u = L_func(u, n);
        mpz_class mu_val = invert_mpz(L_u, n);

        PKE_PublicKey pk;
        pk.n = n;
        pk.g = g;
        pk.n_sq = n_sq;

        static PKE_SecretKey last_sk;
        last_sk.lambda = lambda_val;
        last_sk.mu = mu_val;

        return pk;
    }

    void KGenPKE_full(int lambda_bits, PKE_PublicKey &pk, PKE_SecretKey &sk)
    {
        int half = lambda_bits / 2;

        mpz_class p = random_prime_bits(half, state_gmp);
        mpz_class q = random_prime_bits(half, state_gmp);
        while (p == q)
        {
            q = random_prime_bits(half, state_gmp);
        }

        mpz_class n = p * q;
        mpz_class n_sq = n * n;
        mpz_class lambda_val = lcm(p - mpz_class(1), q - mpz_class(1));
        mpz_class g = n + mpz_class(1);

        mpz_class u = pow_mpz(g, lambda_val, n_sq);
        mpz_class L_u = L_func(u, n);
        mpz_class mu_val = invert_mpz(L_u, n);

        pk.n = n;
        pk.g = g;
        pk.n_sq = n_sq;
        sk.lambda = lambda_val;
        sk.mu = mu_val;
    }

    PKE_Ciphertext EncryptPKE(PKE_PublicKey pk, mpz_class m)
    {
        assert(m < pk.n);

        // Random r with 0 < r < n and gcd(r, n) == 1
        mpz_class r, gcd_val;
        do
        {
            mpz_urandomm(r.get_mpz_t(), state_gmp, pk.n.get_mpz_t());
            mpz_gcd(gcd_val.get_mpz_t(), r.get_mpz_t(), pk.n.get_mpz_t());
        } while (r == mpz_class(0) || gcd_val != mpz_class(1));

        // c = g^m * r^n mod n^2
        mpz_class gm, rn;
        mpz_powm(gm.get_mpz_t(), pk.g.get_mpz_t(), m.get_mpz_t(), pk.n_sq.get_mpz_t());
        mpz_powm(rn.get_mpz_t(), r.get_mpz_t(), pk.n.get_mpz_t(), pk.n_sq.get_mpz_t());
        mpz_class c = (gm * rn) % pk.n_sq;

        PKE_Ciphertext ctx;
        ctx.c = c;
        return ctx;
    }

    mpz_class DecryptPKE(PKE_PublicKey pk, PKE_SecretKey sk, PKE_Ciphertext ctx)
    {
        assert(ctx.c < pk.n_sq);

        // u = c^lambda mod n^2
        mpz_class u;
        mpz_powm(u.get_mpz_t(), ctx.c.get_mpz_t(), sk.lambda.get_mpz_t(), pk.n_sq.get_mpz_t());

        // L(u) = (u - 1) / n
        mpz_class L_u = L_func(u, pk.n);

        // m = L(u) * mu mod n
        mpz_class m = (L_u * sk.mu) % pk.n;
        return m;
    }

    PKE_Ciphertext MultiplyPKE(PKE_PublicKey pk, PKE_Ciphertext ctx, mpz_class s)
    {
        // c' = c^s mod n^2
        mpz_class cp;
        mpz_powm(cp.get_mpz_t(), ctx.c.get_mpz_t(), s.get_mpz_t(), pk.n_sq.get_mpz_t());
        PKE_Ciphertext result;
        result.c = cp;
        return result;
    }

} // namespace PKE
