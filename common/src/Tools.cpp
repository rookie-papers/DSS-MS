#include "../include/Tools.h"

void initRNG(csprng *rng) {
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    unsigned long ran;
    time((time_t *) &ran);

    RAW.len = 100; // fake random seed source
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (int i = 4; i < 100; i++)
        RAW.val[i] = i;

    CREATE_CSPRNG(rng, &RAW);
}


void randBig(BIG big, csprng &rng) {
    BIG mod;
    BIG_rcopy(mod, CURVE_Order);
    BIG_randtrunc(big, mod, 2 * CURVE_SECURITY_BLS12381, &rng);
}

ECP randECP(csprng &rng) {
    ECP ecp;
    ECP_generator(&ecp);
    BIG r;
    randBig(r, rng);
    ECP_mul(&ecp, r);
    return ecp;
}

ECP2 randECP2(csprng &rng) {
    ECP2 ecp2;
    ECP2_generator(&ecp2);
    BIG r;
    randBig(r, rng);
    ECP2_mul(&ecp2, r);
    return ecp2;
}

string charsToString(char *ch) {
    ostringstream oss;
    for (size_t i = 0; i < 48; ++i) {
        unsigned char ucharValue = static_cast<unsigned char>(ch[i]);
        oss << hex << setw(2) << setfill('0') << static_cast<int>(ucharValue);
    }
    return oss.str();
}

mpz_class BIG_to_mpz(BIG big) {
    char ch[48];
    BIG_toBytes(ch, big);
    mpz_class t;
    t.set_str(charsToString(ch).c_str(), 16);
    return t;
}

void mpz_to_BIG(const mpz_class &t, BIG &big) {
    std::string hexStr = t.get_str(16);

    if (hexStr.length() < 64) {
        hexStr.insert(0, 64 - hexStr.length(), '0');
    }
    char ch[32] = {0};
    for (size_t i = 0; i < 32; ++i) {
        std::string byteStr = hexStr.substr(2 * i, 2);
        ch[i] = static_cast<unsigned char>(strtol(byteStr.c_str(), nullptr, 16));
    }
    BIG_fromBytesLen(big, ch, 32);
}

void str_to_BIG(string hex_string, BIG &big) {
    if (hex_string.length() < 96) {
        hex_string.insert(0, 96 - hex_string.length(), '0'); // 在前部填充 '0'
    }
    char byte_array[48];
    for (size_t i = 0; i < 48; i++) {
        sscanf(hex_string.substr(i * 2, 2).c_str(), "%2hhx", &byte_array[i]);
    }
    BIG_fromBytes(big, byte_array);
}


void ECP_mul(ECP &P1, const mpz_class &t) {
    BIG t1;
    mpz_to_BIG(t, t1);
    ECP_mul(&P1, t1);
}

void ECP2_mul(ECP2 &P2, const mpz_class &t) {
    BIG t1;
    mpz_to_BIG(t, t1);
    ECP2_mul(&P2, t1);
}

void FP12_pow(FP12 &fp12, const mpz_class &t) {
    BIG t1;
    mpz_to_BIG(t, t1);
    FP12_pow(&fp12, &fp12, t1);
}

void initState(gmp_randstate_t &state) {
    gmp_randinit_default(state);
    gmp_randseed_ui(state, duration_cast<nanoseconds>(high_resolution_clock::now().time_since_epoch()).count());
}

mpz_class rand_mpz(gmp_randstate_t state) {
    mpz_class res;
    mpz_class max_value = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001_mpz;  // 设置最大值为 椭圆曲线阶-1
    mpz_urandomm(res.get_mpz_t(), state, max_value.get_mpz_t());
    return res + 1;
}

mpz_class rand_mpz_w(gmp_randstate_t state) {
    mpz_class res;
    mpz_class n = 100000000;  // 设置最大值为 椭圆曲线阶-1
    mpz_urandomm(res.get_mpz_t(), state, n.get_mpz_t());
    return res + 1;
}

mpz_class pow_mpz(const mpz_class &base, const mpz_class &exp, const mpz_class &mod) {
    mpz_class res;
    mpz_powm(res.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return res;
}

mpz_class invert_mpz(const mpz_class &a, const mpz_class &m) {
    mpz_class res;
    mpz_invert(res.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t());
    return res;
}

vector<mpz_class> getLagrangeCoffs(const vector<mpz_class> &x, const vector<mpz_class> &y, const mpz_class &modulus) {
    size_t n = x.size();
    assert(n == y.size() && n > 0);
    vector<mpz_class> result(n, 0);
    for (size_t i = 0; i < n; ++i) {
        vector<mpz_class> basis(1, 1);
        mpz_class denom = 1;
        for (size_t j = 0; j < n; ++j) {
            if (i == j) continue;
            vector<mpz_class> temp(basis.size() + 1, 0);
            for (size_t k = 0; k < basis.size(); ++k) {
                temp[k] = (temp[k] - basis[k] * x[j]) % modulus;
                temp[k + 1] = (temp[k + 1] + basis[k]) % modulus;
            }
            basis = temp;
            denom = (denom * (x[i] - x[j])) % modulus;
        }
        denom = denom < 0 ? denom + modulus : denom;
        mpz_class denomInv;
        if (mpz_invert(denomInv.get_mpz_t(), denom.get_mpz_t(), modulus.get_mpz_t()) == 0) {
            throw runtime_error("Modular inverse does not exist");
        }
        for (size_t k = 0; k < basis.size(); ++k) {
            basis[k] = (basis[k] * y[i] % modulus) * denomInv % modulus;
            if (basis[k] < 0) {
                basis[k] += modulus;
            }
        }
        if (result.size() < basis.size()) {
            result.resize(basis.size(), 0);
        }
        for (size_t k = 0; k < basis.size(); ++k) {
            result[k] = (result[k] + basis[k]) % modulus;
            if (result[k] < 0) {
                result[k] += modulus;
            }
        }
    }
    while (result.size() > 1 && result.back() == 0) {
        result.pop_back();
    }
    return result;
}

mpz_class computePoly(const vector<mpz_class> &poly, const mpz_class &x, const mpz_class &modulus) {
    mpz_class result = 0;
    mpz_class power = 1;
    for (const auto &coef: poly) {
        result = (result + (coef * power) % modulus) % modulus;
        power = (power * x) % modulus;
    }
    return result;
}

vector<mpz_class> getLagrangeBasis(const vector<mpz_class> &x, const mpz_class &q) {
    size_t n = x.size();
    vector<mpz_class> lambdas(n);
    for (size_t i = 0; i < n; ++i) {
        mpz_class numerator = 1, denominator = 1;
        for (size_t j = 0; j < n; ++j) {
            if (i != j) {
                numerator = (numerator * (-x[j])) % q;
                mpz_class diff = (x[i] - x[j]) % q;
                if (diff < 0) diff += q;
                denominator = (denominator * diff) % q;
            }
        }
        mpz_class denominator_inv = invert_mpz(denominator, q);
        lambdas[i] = (numerator * denominator_inv) % q;
        if (lambdas[i] < 0) lambdas[i] += q;
    }
    return lambdas;
}

void show_mpz(mpz_t mpz) {
    gmp_printf("%Zx", mpz);
    cout << endl;
}

octet getOctet(int maxLen) {
    octet S;
    S.val = (char *) malloc(maxLen);
    memset(S.val, 0, maxLen);
    S.max = maxLen;
    S.len = 0;
    return S;
}

void showOctet(const octet *S) {
    printf("Octet={max:%d,", S->max);
    printf("len:%d,", S->len);
    printf("data:");
    for (int i = 0; i < S->len; i++) {
        printf("%02x", (unsigned char) S->val[i]); // Print each byte in hex
    }
    printf("}\n");
}

mpz_class octetToMpz(const octet &o) {
    if (o.len <= 0 || o.val == nullptr) {
        std::cerr << "Error: Invalid octet structure." << std::endl;
        return mpz_class(0); // 返回零作为默认值
    }

    mpz_class num;
    // 使用 GMP 的 mpz_import 函数从字节数组导入数据
    mpz_import(num.get_mpz_t(), o.len, 1, 1, 0, 0, o.val);
    return num;
}

octet concat_Octet(const octet *oc1, const octet *oc2) {
    int new_len = oc1->len + oc2->len;
    octet result;
    result.val = (char *) malloc(new_len);
    result.max = new_len;
    result.len = new_len;
    memcpy(result.val, oc1->val, oc1->len);
    memcpy(result.val + oc1->len, oc2->val, oc2->len);
    return result;
}

bool concatOctet(octet *oc1, const octet *oc2) {
    if (!oc1 || !oc2 || !oc1->val) return false;
    int required_len = oc1->len + oc2->len;
    if (oc1->max < required_len) {
        char *new_val = (char *) realloc(oc1->val, required_len);
        if (!new_val) return false;
        oc1->val = new_val;
        oc1->max = required_len;
    }
    memcpy(oc1->val + oc1->len, oc2->val, oc2->len);
    oc1->len = required_len;
    return true;
}


octet mpzToOctet(const mpz_class &num) {
    // 获取字节数组所需的空间
    size_t count = 0;
    unsigned char *buffer = (unsigned char *) mpz_export(nullptr, &count, 1, 1, 0, 0, num.get_mpz_t());

    if (buffer == nullptr || count == 0) {
        std::cerr << "Error: Failed to export mpz_class to bytes." << std::endl;
        return {0, 0, nullptr};
    }

    // 动态分配 octet 的缓冲区，大小等于 count
    char *octetBuffer = new char[count];
    octet o = {0, (int) count, octetBuffer};

    // 填充 octet 的内容
    o.len = (int) count; // 设置 octet 的长度
    memcpy(o.val, buffer, count); // 将字节数组拷贝到 octet 的值

    // 释放 GMP 分配的内存
    free(buffer);

    return o;
}

void hashZp256(BIG res, octet *ct, BIG q) {
    hash256 h;
    char hashstr[48];
    memset(hashstr, 0, 48);
    HASH256_init(&h);
    for (int j = 0; j < ct->max; j++) {
        HASH256_process(&h, ct->val[j]);
    }
    HASH256_hash(&h, hashstr);
    BIG_fromBytesLen(res, hashstr, 48);
    BIG_mod(res, q);
}

void hashToZp256(BIG res, BIG beHashed, BIG q) {
    char idChar[48];
    BIG_toBytes(idChar, beHashed);
    octet id_i_oc;
    id_i_oc.max = 48;
    id_i_oc.val = idChar;
    hashZp256(res, &id_i_oc, q);
}

mpz_class hashToZp256(mpz_class beHashed, mpz_class q) {
    mpz_class res;
    BIG res_b, beHashed_b, module_b;
    mpz_to_BIG(res, res_b);
    mpz_to_BIG(beHashed, beHashed_b);
    mpz_to_BIG(q, module_b);
    hashToZp256(res_b, beHashed_b, module_b);
    return BIG_to_mpz(res_b);
}

ECP hashToPoint(BIG big, BIG q) {
    BIG hash;
    hashToZp256(hash, big, q);
    ECP res;
    ECP_generator(&res);
    ECP_mul(&res, hash);
    return res;
}

ECP hashToPoint(mpz_class big, mpz_class q) {
    BIG tb, tq;
    mpz_to_BIG(big, tb);
    mpz_to_BIG(q, tq);
    return hashToPoint(tb, tq);
}


FP12 e(ECP P1, ECP2 P2) {
    FP12 temp1;
    PAIR_ate(&temp1, &P2, &P1);
    PAIR_fexp(&temp1);
    FP12_reduce(&temp1);
    if (FP12_isunity(&temp1) || FP12_iszilch(&temp1)) {
        printf("pairing error [temp1]\n");
    }
    return temp1;
}


void BIG_inv(BIG &res, const BIG a, const BIG m) {
    BIG m0, x0, x1, one, a_back, module;
    // 此处大费周折复制变量是为了防止求逆元时改变了参数a,m的值
    BIG_rcopy(a_back, a);
    BIG_rcopy(module, m);
    BIG_rcopy(m0, m);
    BIG_one(one);
    // 1. 初始化参数
    BIG_zero(x0);
    BIG_one(x1);
    BIG q, temp;
    while (BIG_comp(a_back, one) > 0) {
        // q 是 a 和 m 的商
        BIG_copy(q, a_back);
        BIG_sdiv(q, module);
        // 更新 a = m ; 并更新 m = a % m;
        BIG_copy(temp, module);
        BIG_copy(module, a_back);
        BIG_mod(module, temp);
        BIG_copy(a_back, temp);
        // 更新 x1 = x0 ; x0 = x1 - q * x0
        BIG_copy(temp, x0);
        BIG_modmul(x0, q, x0, m0);
        BIG_modneg(x0, x0, m0);
        BIG_modadd(x0, x0, x1, m0);
        BIG_copy(x1, temp);
    }
    BIG_copy(res, x1);
}

void showBIG(BIG big) {
    BIG_output(big);
    cout << endl;
}

void showFP12(FP12 fp12) {
    FP12_output(&fp12);
    cout << endl;
}

void printLine(const string &text) {
    cout << "--------------------------------------------------\t " + text +
            " \t--------------------------------------------------" << endl;
}