#include "../include/Serializer.h"


std::string Package_to_str(TransmissionPackage pkg) {
    std::ostringstream oss;
    oss << mpz_to_str(pkg.pp.q) << "#"
        << ECP_to_str(pkg.pp.P) << "#"
        << mpz_to_str(pkg.pp.u_s) << "#"

        << mpz_to_str(pkg.sigma.m0) << "#"
        << mpz_to_str(pkg.sigma.m) << "#"
        << ECP_to_str(pkg.sigma.R) << "#"
        << ECP_to_str(pkg.sigma.T) << "#"
        << mpz_to_str(pkg.sigma.z) << "#"
        << mpz_to_str(pkg.sigma.s) << "#"

        << mpz_to_str(pkg.sk_i) << "#"
        << ECP_to_str(pkg.PK_san) << "#"
        << ECP_to_str(pkg.PK_sig);

    return oss.str();
}


TransmissionPackage str_to_Package(string str) {
    TransmissionPackage pkg;
    std::vector<std::string> fields;
    size_t start = 0, end;

    while ((end = str.find('#', start)) != std::string::npos) {
        fields.push_back(str.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(str.substr(start));

    if (fields.size() != 12) {
        throw std::runtime_error("Invalid transmission package format.");
    }

    pkg.pp.q = str_to_mpz(fields[0]);
    pkg.pp.P = str_to_ECP(fields[1]);
    pkg.pp.u_s = str_to_mpz(fields[2]);

    pkg.sigma.m0 = str_to_mpz(fields[3]);
    pkg.sigma.m = str_to_mpz(fields[4]);
    pkg.sigma.R = str_to_ECP(fields[5]);
    pkg.sigma.T = str_to_ECP(fields[6]);
    pkg.sigma.z = str_to_mpz(fields[7]);
    pkg.sigma.s = str_to_mpz(fields[8]);

    pkg.sk_i = str_to_mpz(fields[9]);
    pkg.PK_san = str_to_ECP(fields[10]);
    pkg.PK_sig = str_to_ECP(fields[11]);


    return pkg;
}

void showPackage(TransmissionPackage pkg) {
    cout << "===== Received TransmissionPackage =====" << endl;

    cout << "[Params]" << endl;
    cout << "q: ";
    show_mpz(pkg.pp.q.get_mpz_t());
    cout << "u_s: ";
    show_mpz(pkg.pp.u_s.get_mpz_t());
    cout << "P: ";
    ECP_output(&pkg.pp.P);

    cout << "\n[Sigma]" << endl;

    printLine("showSigma");
    cout << "sigma.m0 = ";
    show_mpz(pkg.sigma.m0.get_mpz_t());
    cout << "sigma.m = ";
    show_mpz(pkg.sigma.m.get_mpz_t());
    cout << "sigma.R = ";
    ECP_output(&pkg.sigma.R);
    cout << "sigma.z = ";
    show_mpz(pkg.sigma.z.get_mpz_t());
    cout << "sigma.s = ";
    show_mpz(pkg.sigma.s.get_mpz_t());
    cout << "sigma.T = ";
    ECP_output(&pkg.sigma.T);

    cout << "\n[PK_san]" << endl;
    ECP_output(&pkg.PK_san);

    cout << "\n[PK_sig]" << endl;
    ECP_output(&pkg.PK_sig);

    if (pkg.sk_i != 0) {
        cout << "[sk_i] (should be hidden): ";
        show_mpz(pkg.sk_i.get_mpz_t());
    }
    cout << "========================================" << endl;
}

std::string mpz_to_str(const mpz_class &value) {
    return value.get_str(16);
}

mpz_class str_to_mpz(const string &str) {
    return mpz_class(str, 16);
}

std::string ECP_to_str(ECP ecp) {
    BIG x, y;// 每个坐标的长度是96个字节
    ECP_get(x, y, &ecp);
    return mpz_to_str(BIG_to_mpz(x)) + "," + mpz_to_str(BIG_to_mpz(y));
}

ECP str_to_ECP(const std::string &str) {
    ECP ecp;
    int pos = str.find(",");
    BIG x, y;
    str_to_BIG(str.substr(0, pos), x);
    str_to_BIG(str.substr(pos + 1), y);
    ECP_set(&ecp, x, y);
    return ecp;
}

std::string ECP2_to_str(ECP2 ecp2, bool compressed) {
    char buffer[2 * 48 * 2];
    octet S;
    S.val = buffer;
    S.max = sizeof(buffer);
    S.len = 0;
    ECP2_toOctet(&S, const_cast<ECP2 *>(&ecp2), compressed);
    std::string hex_string;
    for (int i = 0; i < S.len; i++) {
        char hex[3];
        sprintf(hex, "%02X", (unsigned char) S.val[i]);
        hex_string.append(hex);
    }
    return hex_string;
}

ECP2 str_to_ECP2(const std::string &hex_string) {
    ECP2 ecp2;
    size_t len = hex_string.length() / 2;
    char buffer[len];
    for (size_t i = 0; i < len; i++) {
        sscanf(hex_string.substr(i * 2, 2).c_str(), "%2hhX", &buffer[i]);
    }
    octet S;
    S.val = buffer;
    S.max = len;
    S.len = len;
    if (ECP2_fromOctet(&ecp2, &S) != 1) {
        std::cerr << "Invalid ECP2 point representation." << std::endl;
    }
    return ecp2;
}


std::string FP12_to_str(FP12 fp12) {
    char buffer[24 * 48];
    octet S;
    S.val = buffer;
    S.max = sizeof(buffer);
    S.len = 0;
    FP12_toOctet(&S, const_cast<FP12 *>(&fp12));
    std::string hex_string;
    for (int i = 0; i < S.len; i++) {
        char hex[3];
        sprintf(hex, "%02X", (unsigned char) S.val[i]);
        hex_string.append(hex);
    }
    return hex_string;
}

FP12 str_to_FP12(const std::string &hex_string) {
    FP12 fp12;
    size_t len = hex_string.length() / 2;
    char buffer[len];
    for (size_t i = 0; i < len; i++) {
        sscanf(hex_string.substr(i * 2, 2).c_str(), "%2hhX", &buffer[i]);
    }
    octet S;
    S.val = buffer;
    S.max = len;
    S.len = len;
    FP12_fromOctet(&fp12, &S);
    return fp12;
}

std::string mpzArr_to_str(const std::vector<mpz_class> &mpzs) {
    string str;
    for (int i = 0; i < mpzs.size(); i++) {
        str += mpzs[i].get_str() + ",";
    }
    return str;
}

std::vector<mpz_class> str_to_mpzArr(const std::string &str) {
    vector<mpz_class> mpzs;
    stringstream ss(str);
    string item;
    while (getline(ss, item, ',')) {
        mpzs.push_back(mpz_class(item));
    }
    return mpzs;
}

std::string ECPArr_to_str(const std::vector<ECP> &ecps) {
    std::ostringstream oss;
    for (size_t i = 0; i < ecps.size(); ++i) {
        if (i != 0) oss << ";";
        oss << ECP_to_str(ecps[i]);
    }
    return oss.str();
}

std::vector<ECP> str_to_ECPArr(const std::string &str) {
    std::vector<ECP> ecps;
    size_t start = 0;
    size_t end = str.find(';');
    while (end != std::string::npos) {
        ecps.emplace_back(str_to_ECP(str.substr(start, end - start))); // 直接构造 ECP
        start = end + 1;
        end = str.find(';', start);
    }
    if (start < str.size()) {
        ecps.emplace_back(str_to_ECP(str.substr(start)));
    }
    return ecps;
}


std::string ECP2Arr_to_str(const std::vector<ECP2> &ecp2s, bool compressed) {
    std::ostringstream oss;
    for (size_t i = 0; i < ecp2s.size(); ++i) {
        if (i != 0) oss << ";";
        oss << ECP2_to_str(ecp2s[i], compressed);
    }
    return oss.str();
}

vector<ECP2> str_to_ECP2Arr(const std::string &str) {
    std::vector<ECP2> ecp2s;
    size_t start = 0;
    size_t end = str.find(';');
    while (end != std::string::npos) {
        ecp2s.emplace_back(str_to_ECP2(str.substr(start, end - start))); // 直接构造 ECP
        start = end + 1;
        end = str.find(';', start);
    }
    if (start < str.size()) {
        ecp2s.emplace_back(str_to_ECP2(str.substr(start)));
    }
    return ecp2s;
}