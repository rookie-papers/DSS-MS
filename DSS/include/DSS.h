#include <iostream>
#include "../../common/include/Tools.h"


typedef struct {
    mpz_class q;
    ECP P;
    mpz_class u_s;
}Params;

typedef struct {
    mpz_class sk;
    ECP PK;
}KeyPair;


typedef struct {
    mpz_class m0,m;
    ECP R,T;
    mpz_class z,s;
}Sigma;


/**
 * Check whether two integers a and b are coprime.
 * @param a First integer.
 * @param b Second integer.
 * @return True if a and b are coprime; otherwise, false.
 */
bool are_coprime(const mpz_class &a, const mpz_class &b);

/**
 * Generate public parameters for the DSS-MS scheme.
 * @return A structure containing the generated public parameters.
 */
Params Setup();

/**
 * Generate keys for the DSS-MS scheme.
 * @param pp Public parameters.
 * @param keyPair Output parameter to store the signing key pair.
 * @param k Number of sanitizers.
 * @param bits Key length in bits for each sanitizer (default: 256 bits).
 * @return A vector of private keys for the sanitizers.
 */
vector<mpz_class> KeyGen(Params &pp, KeyPair &keyPair, int k, int bits);

/**
 * Hash function H_ch(m, T) used in the chameleon hash component.
 * @param m Message.
 * @param T G_1 element.
 * @return Hash output as a large integer.
 */
mpz_class H_ch(mpz_class m, ECP T);

/**
 * Hash function H(m0, R, CH) used in the sanitizable signature scheme.
 * @param m0 Original message (Non-Sanitizable part).
 * @param R Commitment or randomness component.
 * @param CH Chameleon hash component.
 * @return Hash output as a large integer.
 */
mpz_class H(mpz_class m0, ECP R, ECP CH);

/**
 * Signing algorithm: the signer generates a signature on the original message.
 * @param pp Public parameters.
 * @param sk Signing private key.
 * @param PK_s Sanitizer’s public key.
 * @return The generated signature.
 */
Sigma Sign(Params pp, mpz_class sk, ECP PK_s);

/**
 * Sanitization algorithm: a sanitizer transforms a signature using its private key.
 * @param pp Public parameters.
 * @param sigma Original signature.
 * @param sk_i Private key of the i-th sanitizer.
 * @param PK_s Sanitizer’s public key.
 * @return The sanitized signature.
 */
Sigma Sainting(Params pp, Sigma sigma, mpz_class sk_i, ECP PK_s);

/**
 * Verify the validity of a signature (original or sanitized).
 * @param pp Public parameters.
 * @param sigma Signature to be verified.
 * @param PK_s sanitizer’s public key.
 * @param PK Public key of the signer.
 * @return Verification result: 1 if valid; 0 if invalid.
 */
int Verify(Params pp, Sigma sigma, ECP PK_s, ECP PK);