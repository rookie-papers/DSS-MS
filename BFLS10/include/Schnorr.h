#include "../../common/include/Tools.h"

// Structure representing public parameters for Schnorr signatures
typedef struct {
    mpz_class q;  // Group order
    ECP P;        // Group generator
} Params_schnorr;

// Structure representing a Schnorr signature
typedef struct {
    ECP R;        // Commitment
    mpz_class z;  // Response
} Sigma_schnorr;

// Structure representing a Schnorr key pair
typedef struct {
    mpz_class sk; // Secret key
    ECP PK;       // Public key
} KeyPair_schnorr;


/**
 * @brief Hash function used in Schnorr signature scheme.
 *
 * This function hashes the message, commitment (R), and public key into a value modulo the group order.
 *
 * @param m0 The message to hash.
 * @param R  The commitment point.
 * @param PK The public key.
 * @return The resulting hash value as an element of Z_q.
 */
mpz_class H(mpz_class m0, ECP R, ECP PK);

/**
 * @brief Setup the Schnorr public parameters.
 *
 * Initializes the generator and group order.
 *
 * @return The initialized public parameters.
 */
Params_schnorr Setup_schnorr();

/**
 * @brief Generate a Schnorr key pair.
 *
 * Randomly selects a secret key and computes the corresponding public key.
 *
 * @param pp The public parameters.
 * @return The generated key pair.
 */
KeyPair_schnorr SKGen(Params_schnorr pp);

/**
 * @brief Sign a message using the Schnorr signature scheme.
 *
 * Computes the signature (R, z) for a given message using the private key.
 *
 * @param keyPair  The key pair containing the secret key and public key.
 * @param m        The message to sign (as an integer).
 * @param pp       The public parameters.
 * @return The generated signature.
 */
Sigma_schnorr SSign(KeyPair_schnorr keyPair, mpz_class m,Params_schnorr pp);

/**
 * @brief Verify a Schnorr signature.
 *
 * Checks whether the given signature is valid for the message and public key.
 *
 * @param pp   The public parameters.
 * @param PK   The public key.
 * @param sig  The Schnorr signature to verify.
 * @param m    The message that was signed.
 * @return 1 if the signature is valid, 0 otherwise.
 */
int SVf(Params_schnorr pp, ECP PK, Sigma_schnorr sig, mpz_class m);