#include "../../common/include/Tools.h"
#include "../include/SSig.h"

// System public parameters for DIA scheme
typedef struct {
    ECP2 g;               // Generator of G2
    vector<ECP> miu;      // Attribute-related public parameters (μ′, μ₁,...,μ_l)
    ECP u;                // Public parameter for message embedding
    ECP2 g1;              // Public parameter g₁ ∈ G2
    ECP g2;               // Public parameter g₂ ∈ G1
} Params_DIA;

// Identity-based secret key
typedef struct {
    ECP sk_IDp;           // First part of secret key (∈ G1)
    ECP2 sk_IDpp;         // Second part of secret key (∈ G2)
    mpz_class ID;         // User identity
} KeyPair_DIA;

// Index used to mark sensitive data positions
typedef struct {
    vector<int> K1;       // Indices of sensitive blocks (to be hidden)
    vector<int> K2;
} Index_DIA;

// Auxiliary information
typedef struct {
    mpz_class name;       // File name identifier (random)
    ECP2 grid;            // g^r_ID (∈ G2)
    ECP2 gr;              // g^r (∈ G2)
} Tau_0;

// Full signature over data blocks (including sanitizable structure)
typedef struct {
    vector<mpz_class> m_star; // Sanitized message blocks
    vector<ECP> phi;          // Signature on each block
    Tau_0 tau0;               // Tag used for auditing
    Sigma_SSig SSign;         // Schnorr signature over tau0
    ECP PK_s;                 // Signer public key
    ECP beta;                 // Commitment to r: β = u^r
} Sigma_DIA;

// Proof of possession for audit
typedef struct {
    mpz_class lambda;     // Linear combination of data blocks
    ECP sigma;            // Aggregated signature
} Proof_DIA;

// Initialize system public parameters and master secret key
Params_DIA Setup_DIA(ECP &msk);

// Convert a user's identity to a binary vector representation
vector<int> getBits(mpz_class ID);

// Compute μ′ · ∏ μ_j^{ID_j} from given miu and ID bits
ECP prodMiu(vector<ECP> mius, vector<int> ID_bits);

// Extract user secret key (sk′, sk′′) based on ID and master key
KeyPair_DIA Extract_DIA(Params_DIA pp, mpz_class ID, ECP msk);

// Verify the extracted key satisfies
bool Extract_verify(KeyPair_DIA keyPair, Params_DIA pp);

// Initialize index with positions of sensitive blocks
void initIndex(Index_DIA &index, vector<int> K1, vector<int> K2);

/**
 * @brief Pseudorandom function used to compute alpha_i values.
 *
 * @param k1 secret key.
 * @param i The attribute index.
 * @param name The session name or nonce.
 * @return mpz_class The computed alpha_i.
 */
mpz_class f_k(gmp_randstate_t &k1, int i, mpz_class name);

/**
 * @brief Hash function used to generate group elements from name and index.
 *
 * @param name The input name or nonce.
 * @param i The attribute index.
 * @return ECP The resulting group element.
 */
ECP H_DIA(mpz_class name, int i);

/**
 * @brief Generate a digest from a Tau_0 structure. To reduce the cost, return the name directly
 *
 * @param tau0 The Tau_0 structure.
 * @return tau0.name
 */
mpz_class getTauDigest(Tau_0 tau0);

/**
 * @brief Generate a one-time signature over the Tau_0 structure.
 *
 * @param keyPair Schnorr signature secret key.
 * @param tau0 message.
 * @param pp Public parameters for signature scheme.
 * @return Sigma_SSig The resulting signature.
 */
Sigma_SSig SSig(KeyPair_SSig keyPair, Tau_0 tau0,Params_SSig pp);

/**
 * @brief Generate a signature over the message vector with embedded sanitization support.
 *
 * This function computes a signature on the message vector using the DIA scheme.
 * It embeds a Schnorr-style one-time signature over Tau_0,
 * and supports future sanitization of sensitive components.
 *
 * @param m The message vector to be signed.
 * @param idx The index structure indicating sensitive (K1) and non-sensitive (K2) positions.
 * @param msk The master secret key.
 * @param ID The signer’s identity.
 * @param keyPair The private key corresponding to the signer’s identity.
 * @param pp Public parameters for the DIA scheme.
 * @param ssk The secret key used for the one-time Schnorr signature.
 * @param pp_S Public parameters for the one-time Schnorr signature scheme.
 * @return Sigma_DIA The generated signature structure.
 */
Sigma_DIA SignGen_DIA(vector<mpz_class> m, Index_DIA idx, ECP msk, mpz_class ID, KeyPair_DIA keyPair,Params_DIA pp,
                      KeyPair_SSig ssk,Params_SSig pp_S);

/**
 * @brief Perform sanitization on a signature.
 *
 * This function verifies the one-time Schnorr signature embedded in the DIA signature,
 * and then validates the correctness of the signature using pairing equations.
 * If the verification passes, it sanitizes the sensitive components in the signature
 * by randomizing selected parts based on index set K1.
 *
 * @param sigma The original signature to be sanitized.
 * @param pp Public parameters for the scheme.
 * @param pp_S Public parameters for the Schnorr signature scheme.
 * @param ID The identity of the signer.
 * @param keyPair The signer’s key pair.
 * @param idx The index structure indicating which parts are sensitive.
 * @return Sigma_DIA The sanitized signature.
 */
Sigma_DIA Sanitization_DIA(Sigma_DIA sigma,Params_DIA pp,Params_SSig pp_S,mpz_class ID,KeyPair_DIA keyPair,Index_DIA idx);

/**
 * @brief Generate a proof of correct redaction over selected indices and values.
 *
 * @param m The original message vector.
 * @param sigma The DIA signature over the message.
 * @param chal_i The indices of the challenged message components.
 * @param chal_v The corresponding values of the challenged components.
 * @return Proof_DIA The generated proof structure.
 */
Proof_DIA ProofGen_DIA(vector<mpz_class> m, Sigma_DIA sigma, vector<int> chal_i, vector<mpz_class> chal_v);

/**
 * @brief Verify the proof of correct redaction.
 *
 * @param proof The proof structure.
 * @param chal_i The challenge indices.
 * @param chal_v The challenge values.
 * @param pp Public parameters.
 * @param ID Identity used in the signature.
 * @param tau0 The Tau_0 commitment used in signature.
 * @return true If the proof is valid.  false If the proof is invalid.
 */
bool ProofVerify_DIA(Proof_DIA proof, vector<int> chal_i, vector<mpz_class> chal_v, Params_DIA& pp, mpz_class& ID, Tau_0 tau0);

