#include "../include/IBSDIA.h"
#include "benchmark/benchmark.h"

csprng rng_DIA;
gmp_randstate_t state_DIA;
mpz_class p_DIA = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001_mpz;

int l_DIA = 256; // the length of ID is l-bit

Params_DIA Setup_DIA(ECP &msk) {
    Params_DIA pp;
    ECP2_generator(&pp.g);
    mpz_class x = rand_mpz(state_DIA);
    ECP2_copy(&pp.g1,&pp.g);
    ECP2_mul(pp.g1, x);
    ECP_generator(&pp.g2);
    ECP_copy(&msk,&pp.g2);
    ECP_mul(msk, x);
    pp.u = randECP(rng_DIA);
    for (int i = 0; i < l_DIA; ++i) {
        ECP miui = randECP(rng_DIA);
        pp.miu.push_back(miui);
    }
    return pp;
}

vector<int> getBits(mpz_class ID) {
    std::vector<int> ID_bits;
    for (int i = l_DIA - 1; i >= 0; --i) {
        ID_bits.push_back(mpz_tstbit(ID.get_mpz_t(), i));
    }
    return ID_bits;
}

ECP prodMiu(vector<ECP> mius, vector<int> ID_bits) {
    ECP mu_ID;
    ECP_copy(&mu_ID, &mius[0]);  // μ'
    ECP tmp;  // μ_{j+1}
    for (int j = 1; j < l_DIA; ++j) {
        if (ID_bits[j] == 0) continue;
        ECP_copy(&tmp, &mius[j]);
        ECP_add(&mu_ID, &tmp);     // μ_ID += μ_{j+1}
    }
    return mu_ID;
}

KeyPair_DIA Extract_DIA(Params_DIA pp, mpz_class ID, ECP msk) {
    KeyPair_DIA keyPair;
    mpz_class r_ID = rand_mpz(state_DIA);
    std::vector<int> ID_bits = getBits(ID);
    ECP mu_ID = prodMiu(pp.miu, ID_bits);
    ECP_copy(&keyPair.sk_IDp, &mu_ID);
    ECP_mul(keyPair.sk_IDp, r_ID);
    ECP_add(&keyPair.sk_IDp, &msk);
    ECP2_copy(&keyPair.sk_IDpp, &pp.g);
    ECP2_mul(keyPair.sk_IDpp, r_ID);
    keyPair.ID = ID;
    return keyPair;  // 返回 (sk'_ID, sk''_ID)
}

bool Extract_verify(KeyPair_DIA keyPair, Params_DIA pp) {
    // Verify: e(σ_i, g) = e(g1, g2) · e(μ_ID, sk''_{ID}) · e(H(name, i) · u^{m*}, g^r)
    FP12 lhs = e(keyPair.sk_IDp, pp.g);
    std::vector<int> ID_bits = getBits(keyPair.ID);
    ECP mu_ID = prodMiu(pp.miu, ID_bits);
    FP12 e1 = e(pp.g2, pp.g1);
    FP12 e2 = e(mu_ID, keyPair.sk_IDpp);
    FP12 rhs;
    FP12_copy(&rhs, &e1);
    FP12_mul(&rhs, &e2);
    return FP12_equals(&lhs, &rhs);
}


void initIndex(Index_DIA &index, vector<int> K1, vector<int> K2) {
    index.K1 = K1;
    index.K2 = K2;
}

mpz_class f_k(gmp_randstate_t &k1, int i, mpz_class name) {
    return (rand_mpz(k1) * (i + 1) * name) % p_DIA;
}

ECP H_DIA(mpz_class name, int i) {
    octet hash = getOctet(49);
    mpz_class input = name + i + 1;
    octet oct_m = mpzToOctet(input);
    concatOctet(&hash, &oct_m);
    free(oct_m.val);
    BIG order, ret;
    BIG_rcopy(order, CURVE_Order);
    hashZp256(ret, &hash, order);
    free(hash.val);
    mpz_class scalar = BIG_to_mpz(ret) % p_DIA;
    ECP H;
    ECP_generator(&H);
    ECP_mul(H, scalar);
    return H;
}



mpz_class getTauDigest(Tau_0 tau0){
    return tau0.name;
}

Sigma_SSig SSig(KeyPair_SSig keyPair, Tau_0 tau0,Params_SSig pp){
    return SSign(keyPair, getTauDigest(tau0),pp);
}

Sigma_DIA SignGen_DIA(vector<mpz_class> m, Index_DIA idx, ECP msk, mpz_class ID, KeyPair_DIA keyPair,Params_DIA pp,
                 KeyPair_SSig ssk,Params_SSig pp_S) {

    Sigma_DIA sigma;
    Tau_0 tau0;
    // g^r
    mpz_class r = rand_mpz(state_DIA);
    ECP2_generator(&tau0.gr);
    ECP2_mul(tau0.gr,r);
    // compute phi = {sigma_i}
    gmp_randstate_t k_1;
    initState(k_1);
    tau0.name = rand_mpz(k_1);
    sigma.m_star = m;
    for (int i = 0; i < m.size(); ++i) {
        if (i < idx.K1.size()){
            mpz_class alpha_i = f_k(k_1, idx.K1[i], tau0.name);
            sigma.m_star[i] = (sigma.m_star[i] + alpha_i) % p_DIA;
        }
        ECP H = H_DIA(tau0.name, i);
        ECP tmp_u;
        ECP_copy(&tmp_u,&pp.u);
        ECP_mul(tmp_u,sigma.m_star[i]);
        ECP_add(&H,&tmp_u);
        ECP_mul(H,r);

        ECP sigma_i;
        ECP_copy(&sigma_i, &keyPair.sk_IDp);
        ECP_add(&sigma_i,&H);
        sigma.phi.push_back(sigma_i);
    }
    // generator signature
    ECP2_copy(&tau0.grid,&keyPair.sk_IDpp);
    sigma.SSign = SSig(ssk,tau0,pp_S);
    sigma.tau0 = tau0;
    ECP_copy(&sigma.PK_s ,&ssk.PK);
    ECP_copy(&sigma.beta,&pp.u);
    ECP_mul(sigma.beta,r);
    return sigma;
}

Sigma_DIA Sanitization_DIA(Sigma_DIA sigma,Params_DIA pp,Params_SSig pp_S,mpz_class ID,KeyPair_DIA keyPair,Index_DIA idx) {
    // verify SSig_ssk(tau0)
    int ok = SVf(pp_S,sigma.PK_s,sigma.SSign,sigma.tau0.name);
    if (!ok) {
        cout << "Sanitizing : SSign SVf defeat" << endl;
        return sigma;
    }
    // verify e(sigma_i,g) = e(g1, g2) * e(μ_ID, g^rID) * e( H(name,i)·u^m*,g^r )
    FP12 tmp = e(pp.g2,pp.g1);
    vector<int> IDBits = getBits(ID);
    ECP prod = prodMiu(pp.miu,IDBits);
    FP12 tmp2 = e(prod,sigma.tau0.grid);
    FP12_mul(&tmp,&tmp2);
    for (int i = 0; i < sigma.phi.size(); ++i) {
        ECP H = H_DIA(sigma.tau0.name,i);
        ECP tmp_u;
        ECP_copy(&tmp_u,&pp.u);
        ECP_mul(tmp_u,sigma.m_star[i]);
        ECP_add(&H,&tmp_u);
        FP12 right = e(H,sigma.tau0.gr);
        FP12_mul(&right,&tmp);
        FP12 left = e(sigma.phi[i],pp.g);
        ok = ok && FP12_equals(&left,&right);
        // if (ok) cout << "Sanitizing success" << endl;
    }
    // e(u,g^r) =? e(β,g)
    ECP temp_u;
    ECP_copy(&temp_u,&pp.u);
    FP12 left = e(temp_u,sigma.tau0.gr);
    FP12 right =e(sigma.beta,pp.g);
    ok = ok && FP12_equals(&left,&right);
    // update sigma -> sigma'
    for (int k = 0; k < idx.K1.size(); ++k) {
        int i = idx.K1[k];
        mpz_class mi = rand_mpz(state_DIA);
        ECP temp_beta;
        ECP_copy(&temp_beta, &sigma.beta);
        ECP_mul(temp_beta, (mi - sigma.m_star[i]) % p_DIA);
        ECP_add(&sigma.phi[i], &temp_beta);
    }
    return sigma;
}

Proof_DIA ProofGen_DIA(vector<mpz_class> m, Sigma_DIA sigma, vector<int> chal_i, vector<mpz_class> chal_v) {
    Proof_DIA proof;
    proof.lambda = 0;
    ECP_inf(&proof.sigma);
    // λ = sum{ m[i] * v_i mod p }  and  σ *= σ_i^v_i
    for (int idx = 0; idx < chal_i.size(); ++idx) {
        int i = chal_i[idx];
        mpz_class vi = chal_v[idx];
        mpz_class term = (m[i] * vi) % p_DIA;
        proof.lambda = (proof.lambda + term) % p_DIA;
        ECP sigma_i = sigma.phi[i];
        ECP_mul(sigma_i, vi);
        if (ECP_isinf(&proof.sigma)) {
            ECP_copy(&proof.sigma, &sigma_i);
        } else {
            ECP_add(&proof.sigma, &sigma_i);
        }
    }
    return proof;
}

bool ProofVerify_DIA(Proof_DIA proof, vector<int> chal_i, vector<mpz_class> chal_v, Params_DIA& pp, mpz_class& ID, Tau_0 tau0) {
    // compute lhs = e(sigma, g)
    FP12 lhs = e(proof.sigma, pp.g);
    // compute rhs = e(g1, g2)^sum(vi) * e( μ′ · ∏ μ_j^{ID_j}, sk_IDpp)^sum(vi) * e(∏ H(name||i)^v_i · u^λ, g^r)
    vector<int> ID_bits = getBits(ID);
    ECP mu_ID = prodMiu(pp.miu, ID_bits);
    mpz_class sum_v = 0;
    for (auto& v : chal_v) sum_v = (sum_v + v) % p_DIA;
    FP12 t1 = e(pp.g2, pp.g1);
    FP12_pow(t1, sum_v);
    FP12 t2 = e(mu_ID, tau0.grid);
    FP12_pow(t2, sum_v);
    ECP prod_H;
    ECP_inf(&prod_H);
    for (int idx = 0; idx < chal_i.size(); ++idx) {
        int i = chal_i[idx];
        mpz_class vi = chal_v[idx];
        ECP h_i = H_DIA(tau0.name, i);
        ECP_mul(h_i, vi);
        ECP u_term = pp.u;
        ECP_mul(u_term, proof.lambda);
        ECP_add(&h_i, &u_term);
        if (ECP_isinf(&prod_H)) {
            ECP_copy(&prod_H, &h_i);
        } else {
            ECP_add(&prod_H, &h_i);
        }
    }
    FP12 t3 = e(prod_H, tau0.gr);
    FP12 rhs;
    FP12_copy(&rhs, &t1);
    FP12_mul(&rhs, &t2);
    FP12_mul(&rhs, &t3);
    return FP12_equals(&lhs, &rhs);
}

//int main() {
//    initRNG(&rng_DIA);
//    initState(state_DIA);
//
//    printLine("Setup");
//    ECP msk;
//    Params_DIA pp = Setup_DIA(msk);
//
//    printLine("Extract");
//    mpz_class ID = rand_mpz(state_DIA);
//    KeyPair_DIA keyPair = Extract_DIA(pp, ID, msk);
//    int ok = Extract_verify(keyPair, pp);
//    cout << "Extract verify result : " << ok << endl;
//
//    printLine("SinGen");
//    Params_SSig pp_S = Setup_SSig();
//    KeyPair_SSig ssk = SKGen(pp_S);
//    Index_DIA idx;
//    vector<int> K1 = {0};
//    vector<int> K2 = {0}; // suppose K1 ∪ K2 = K1 ,otherwise, a function needs to be implemented to compute K1 ∪ K2
//    int n = K1.size() + K2.size();
//    initIndex(idx,K1,K2);
//    vector<mpz_class> m;
//    for (int i = 0; i < n; ++i) {
//        m.push_back(rand_mpz(state_DIA));
//    }
//    Sigma_DIA sigma = SignGen_DIA(m,idx,msk,ID,keyPair,pp,ssk,pp_S);
//
//    //
//    printLine("Sanitizing");
//    Sigma_DIA sigma_p = Sanitization_DIA(sigma,pp,pp_S,ID,keyPair,idx);
//
//    printLine("ProofGen");
//    vector<int> chal_i = {0};
//    vector<mpz_class > chal_v;
//    for (int i = 0; i < chal_i.size(); ++i) {
//        chal_v.push_back(rand_mpz(state_DIA));
//    }
//    Proof_DIA proof = ProofGen_DIA(sigma.m_star, sigma, chal_i, chal_v);
//
//    printLine("Verify");
//    bool valid = ProofVerify_DIA(proof, chal_i, chal_v, pp, ID, sigma.tau0);
//    cout << "proof verified : " << valid << endl;
//
//    return 0;
//}

static void BM_Setup(benchmark::State &state) {
    initRNG(&rng_DIA);
    initState(state_DIA);
    ECP msk;
    for (auto _: state) {
        Params_DIA pp = Setup_DIA(msk);
    }
}

static void BM_KeyGen(benchmark::State &state) {
    initRNG(&rng_DIA);
    initState(state_DIA);

    ECP msk;
    Params_DIA pp = Setup_DIA(msk);
    mpz_class ID = rand_mpz(state_DIA);
    for (auto _: state) {
        KeyPair_DIA keyPair = Extract_DIA(pp, ID, msk);
        Extract_verify(keyPair, pp);
    }
}

static void BM_Sign(benchmark::State &state) {
    initRNG(&rng_DIA);
    initState(state_DIA);
    ECP msk;
    Params_DIA pp = Setup_DIA(msk);
    mpz_class ID = rand_mpz(state_DIA);
    KeyPair_DIA keyPair = Extract_DIA(pp, ID, msk);
    int ok = Extract_verify(keyPair, pp);
    Params_SSig pp_S = Setup_SSig();
    KeyPair_SSig ssk = SKGen(pp_S);
    Index_DIA idx;
    vector<int> K1 = {0};
    vector<int> K2 = {0}; // suppose K1 ∪ K2 = K1 ,otherwise, a function needs to be implemented to compute K1 ∪ K2
    int n = K1.size() + K2.size();
    initIndex(idx,K1,K2);
    vector<mpz_class> m;
    for (int i = 0; i < n; ++i) {
        m.push_back(rand_mpz(state_DIA));
    }
    for (auto _: state) {
        SignGen_DIA(m,idx,msk,ID,keyPair,pp,ssk,pp_S);
    }
}

static void BM_Sanitizing(benchmark::State &state) {
    initRNG(&rng_DIA);
    initState(state_DIA);

    ECP msk;
    Params_DIA pp = Setup_DIA(msk);
    mpz_class ID = rand_mpz(state_DIA);
    KeyPair_DIA keyPair = Extract_DIA(pp, ID, msk);
    int ok = Extract_verify(keyPair, pp);

    Params_SSig pp_S = Setup_SSig();
    KeyPair_SSig ssk = SKGen(pp_S);
    Index_DIA idx;
    vector<int> K1 = {0};
    vector<int> K2 = {0}; // suppose K1 ∪ K2 = K1 ,otherwise, a function needs to be implemented to compute K1 ∪ K2
    int n = K1.size() + K2.size();
    initIndex(idx,K1,K2);
    vector<mpz_class> m;
    for (int i = 0; i < n; ++i) {
        m.push_back(rand_mpz(state_DIA));
    }
    Sigma_DIA sigma = SignGen_DIA(m,idx,msk,ID,keyPair,pp,ssk,pp_S);
    for (auto _: state) {
        Sanitization_DIA(sigma,pp,pp_S,ID,keyPair,idx);
    }
}

static void BM_ProofGen(benchmark::State &state) {
    initRNG(&rng_DIA);
    initState(state_DIA);

    ECP msk;
    Params_DIA pp = Setup_DIA(msk);

    mpz_class ID = rand_mpz(state_DIA);
    KeyPair_DIA keyPair = Extract_DIA(pp, ID, msk);
    int ok = Extract_verify(keyPair, pp);

    Params_SSig pp_S = Setup_SSig();
    KeyPair_SSig ssk = SKGen(pp_S);
    Index_DIA idx;
    vector<int> K1 = {0};
    vector<int> K2 = {0}; // suppose K1 ∪ K2 = K1 ,otherwise, a function needs to be implemented to compute K1 ∪ K2
    int n = K1.size() + K2.size();
    initIndex(idx,K1,K2);
    vector<mpz_class> m;
    for (int i = 0; i < n; ++i) {
        m.push_back(rand_mpz(state_DIA));
    }
    Sigma_DIA sigma = SignGen_DIA(m,idx,msk,ID,keyPair,pp,ssk,pp_S);
    Sigma_DIA sigma_p = Sanitization_DIA(sigma,pp,pp_S,ID,keyPair,idx);

    vector<int> chal_i = {0};
    vector<mpz_class > chal_v;
    for (int i = 0; i < chal_i.size(); ++i) {
        chal_v.push_back(rand_mpz(state_DIA));
    }
    for (auto _: state) {
        Proof_DIA proof = ProofGen_DIA(sigma.m_star, sigma, chal_i, chal_v);
    }
}

void BM_ProofVerify(benchmark::State &state) {
    initRNG(&rng_DIA);
    initState(state_DIA);
    ECP msk;
    Params_DIA pp = Setup_DIA(msk);
    mpz_class ID = rand_mpz(state_DIA);
    KeyPair_DIA keyPair = Extract_DIA(pp, ID, msk);
    int ok = Extract_verify(keyPair, pp);
    Params_SSig pp_S = Setup_SSig();
    KeyPair_SSig ssk = SKGen(pp_S);
    Index_DIA idx;
    vector<int> K1 = {0};
    vector<int> K2 = {0}; // suppose K1 ∪ K2 = K1 ,otherwise, a function needs to be implemented to compute K1 ∪ K2
    int n = K1.size() + K2.size();
    initIndex(idx,K1,K2);
    vector<mpz_class> m;
    for (int i = 0; i < n; ++i) {
        m.push_back(rand_mpz(state_DIA));
    }
    Sigma_DIA sigma = SignGen_DIA(m,idx,msk,ID,keyPair,pp,ssk,pp_S);
    Sigma_DIA sigma_p = Sanitization_DIA(sigma,pp,pp_S,ID,keyPair,idx);
    vector<int> chal_i = {0};
    vector<mpz_class > chal_v;
    for (int i = 0; i < chal_i.size(); ++i) {
        chal_v.push_back(rand_mpz(state_DIA));
    }
    Proof_DIA proof = ProofGen_DIA(sigma.m_star, sigma, chal_i, chal_v);
    for (auto _: state) {
        bool valid = ProofVerify_DIA(proof, chal_i, chal_v, pp, ID, sigma.tau0);
    }
}

// register
BENCHMARK(BM_Setup);
BENCHMARK(BM_KeyGen);
BENCHMARK(BM_Sign);
BENCHMARK(BM_Sanitizing);
BENCHMARK(BM_ProofGen);
BENCHMARK(BM_ProofVerify);

// run benchmark
BENCHMARK_MAIN();