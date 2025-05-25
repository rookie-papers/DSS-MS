#include "../../common/include/Tools.h"
#include "../include/Schnorr.h"
#include "../include/BBS.h"

/**
 * @brief Implementation overview of BFLS10 in this work
 *
 * This implementation aims to reproduce the BFLS10 framework while ensuring practical feasibility and minimal deviation from original cryptographic constructions.
 *
 * The BFLS10 framework requires that group member secret keys can be generated independently of the group manager,
 * and potentially even before the generation of the group public key. Group signature schemes that satisfy this property are relatively rare.
 * Among them, two representative constructions are:
 * - "Group Signatures with Separate and Distributed Authorities"
 *   (https://link.springer.com/chapter/10.1007/978-3-540-30598-9_6)
 * - "Fully Anonymous Group Signatures Without Random Oracles"
 *   (https://link.springer.com/chapter/10.1007/978-3-540-76900-2_10)
 *
 * However, as analyzed in
 * - "Efficient Unlinkable Sanitizable Signatures from Signatures with Re-Randomizable Keys"
 *   (https://link.springer.com/chapter/10.1007/978-3-662-49384-7_12),
 * these constructions incur high computational overhead.
 *
 * Therefore, in this work, we instantiate the BFLS10 group signature component
 *      GS = (\text{GKen}, \text{UKGen}, \text{GSig}, \text{GVf}, \text{Open}, \text{GJudge})
 * using the well-established and highly efficient BBS group signature scheme.
 *
 * Similarly, the standard signature component
 *      S = (\text{SKGen}, \text{SSign}, \text{SVf})
 * is instantiated using the Schnorr signature scheme, which is widely recognized for its simplicity and efficiency.
 *
 * For instantiating the PRF required by the BFLS10 framework, we adopt GMP's built-in function `mpz_urandomm()`,
 * which serves as a practical pseudorandom number generator for experimental purposes.
 *
 * ------------------------------------------------------------------------------------
 *
 * ① Notably, in the original BFLS10 design, the PRF key k is embedded as part of the signer's private key and is used in the `Proof` algorithm to deterministically derive the group signing key for `Open`.
 * In our implementation, we simplify this by omitting k from the signer’s private key and instead directly exposing `gmsk` as a global variable. This simplification does not affect the correctness or experimental validity of our results.
 *
 * ② Moreover, BFLS10 distinguishes between two parts of the group member secret key: `gsk_sig` and `cert_sig`.
 * In our implementation, we treat them as a unified entity for simplicity, without loss of generality.
 *
 * ③ Regarding the signing procedure, in BFLS10, the standard signature signs the tuple (m_FIX, ADM, pk_san, gpk).
 * For efficiency, we compute a digest using `ComDigest_FIX`, which simply returns m_{\text{FIX}} to avoid extra computation.
 * The group signature input message is handled analogously.
 *
 * ④ Finally, since the BBS signature scheme does not inherently support publicly verifiable opening,
 * we augment the `Open` result with a NIZK proof of the following relation:
 *      NIZK{ ksi_1, ksi_2 : u^{ksi_1} \cdot v^{ksi_2} = T_3 / A }
 * This proof is verified within the `Judge` procedure to establish signer accountability.
 * Importantly, we do not modify the BBS signature scheme itself; all enhancements are applied externally and modularly to comply with BFLS10's verifiability requirements.
 */




/**
 * @brief Complete signature package for the BFLS10 scheme.
 *
 * This structure includes:
 * - Schnorr signature on the fixed message part.
 * - BBS signature on the sanitizable message part.
 * - The saint policy ADM.
 * - The sanitizer's public key.
 * - The group public key (gpk) for BBS.
 */
typedef struct {
    Sigma_schnorr sigma_FIX;
    Sigma_BBS sigma_FULL;
    mpz_class ADM;
    ECP PK_san;
    // Cert cert_san; // Unused
    GPK gpk;
} Sigma_BFLS10;

/**
 * @brief Non-interactive zero-knowledge proof structure (Okamoto-style).
 *
 * Represents a NIZK proof that a decrypted value A is correct, based on discrete log relationships.
 */
typedef struct {
    mpz_class c;  ///< Fiat-Shamir challenge
    mpz_class s1; ///< Response for exponent x1 (i.e. , BBS gmsk.ksi1)
    mpz_class s2; ///< Response for exponent x2 (i.e. , BBS gmsk.ksi2)
} PI;

/**
 * @brief Opened evidence used for traceability.
 *
 * Includes the recovered identity element A and the accompanying NIZK proof.
 */
typedef struct {
    ECP A; ///< Recovered value (identity or tag)
    PI pi; ///< Proof that A was correctly derived
} Evidence;
//  事实上，可以维护一个身份表 : Lists = {<ID,H(A)>} ,这样，当Proof之后就可以公布A，别人可以验证 pi 并查lists找到签名者身份

/**
 * @brief Computes the hash digest for the fixed message portion to be signed using Schnorr.
 *      The message m_FIX is returned directly as the signature result here,
 *      in order to avoid additional computational overhead from further processing.
 * @param m_FIX The fixed part of the message.
 * @param ADM The sanit control policy.
 * @param PK_san The public key of the sanitizer.
 * @param gpk The group public key.
 * @return A digest (hash value) to be used as the Schnorr message input.
 */
mpz_class ComDigest_FIX(mpz_class m_FIX, mpz_class ADM, ECP PK_san, GPK gpk);

// same ComDigest_FIX
mpz_class ComDigest_FULL(mpz_class m, ECP PK_sig);

/**
 * @brief Generates key pairs for both Schnorr and BBS signature schemes.
 *
 * @param keyPair_Schnorr Output: Schnorr key pair.
 * @param keyPair_BBS Output: BBS group signing key.
 * @param pp_S Public parameters for Schnorr.
 * @param gamma Global system secret used in BBS.
 */
void KeyGeneration(KeyPair_schnorr &keyPair_Schnorr, GSK_sig &keyPair_BBS, Params_schnorr pp_S, mpz_class gamma);

/**
 * @brief Performs the signing phase by the original signer.
 *
 * Generates:
 * - A Schnorr signature on the fixed message part.
 * - A BBS signature on the sanitizable part.
 *
 * @param KP_Schnorr_sig Schnorr key pair of the signer.
 * @param m_FIX The fixed message content.
 * @param pp_S Schnorr public parameters.
 * @param KP_BBS_sig Group secret key for BBS signature.
 * @param m The full message to be BBS signed.
 * @param PK_san The public key of the intended sanitizer.
 * @param ADM Sanit policy metadata.
 * @param gamma BBS secret parameter.
 * @return A full Sigma_BFLS10 signature package.
 */
Sigma_BFLS10 Signing(KeyPair_schnorr KP_Schnorr_sig, mpz_class m_FIX, Params_schnorr pp_S,
                     GSK_sig KP_BBS_sig, mpz_class m, ECP PK_san,
                     mpz_class ADM, mpz_class gamma);

/**
 * @brief Performs message sanitization and re-signing by the sanitizer.
 *
 * @param pp_S Schnorr public parameters.
 * @param PK_sig Public key of the original signer.
 * @param sigma The original Sigma_BFLS10 signature to be sanitized.
 * @param msgDigest_FIX The fixed message digest (Schnorr).
 * @param KP_BBS_san Group key of the sanitizer.
 * @param m_p Output: Sanitized message.
 * @return A new sanitized signature.
 */
Sigma_BFLS10 Sanitizing(Params_schnorr pp_S, ECP PK_sig, Sigma_BFLS10 sigma, mpz_class msgDigest_FIX,
                        GSK_sig KP_BBS_san, mpz_class &m_p);

/**
 * @brief Verifies the signature after sanitizable sanitization.
 *
 * @param pp_S Schnorr public parameters.
 * @param PK_sig Public key of the original signer.
 * @param msgDigest_FIX Digest for the fixed message.
 * @param msgDigest_FULL Digest for the full message (BBS).
 * @param sigma Signature package to verify.
 * @return 1 if valid, 0 otherwise.
 */
int Verification(Params_schnorr pp_S, ECP PK_sig, mpz_class msgDigest_FIX,
                 mpz_class msgDigest_FULL, Sigma_BFLS10 sigma);

/**
 * @brief Hash function used in Fiat–Shamir transformation for NIZK.
 *
 * @param T1 BBS ciphertext component.
 * @param T2 BBS ciphertext component.
 * @param T3 BBS ciphertext component.
 * @param A Recovered value.
 * @param R Commitment in the NIZK proof.
 * @return Fiat–Shamir challenge (as a field element).
 */
mpz_class H_NIZK(ECP T1, ECP T2, ECP T3, ECP A, ECP R);

/**
 * @brief Prover's side of the NIZK proof for BBS signature opening.
 *
 * Constructs a proof that:
 * A = T3 / (T1^x1 * T2^x2)
 *
 * @param x1 First secret exponent (e.g., ξ1).
 * @param x2 Second secret exponent (e.g., ξ2).
 * @param T1 Ciphertext component.
 * @param T2 Ciphertext component.
 * @param T3 Ciphertext component.
 * @param A Recovered identity or message.
 * @return A non-interactive zero-knowledge proof (PI).
 */
PI NIZK_proof(mpz_class x1, mpz_class x2, ECP T1, ECP T2, ECP T3, ECP A);

/**
 * @brief Verifier's side of the NIZK proof.
 *
 * @param pi The proof structure.
 * @param T1 Ciphertext component.
 * @param T2 Ciphertext component.
 * @param T3 Ciphertext component.
 * @param A Recovered value.
 * @return true if the proof is valid, false otherwise.
 */
bool NIZK_verify(PI pi, ECP T1, ECP T2, ECP T3, ECP A) ;

/**
 * @brief Executes the tracing procedure to extract and prove the signer identity.
 *
 * @param pp_S Schnorr public parameters.
 * @param PK_sig Public key of the original signer.
 * @param sigma The BFLS10 signature package.
 * @param msgDigest_FIX Fixed message digest.
 * @param gpk The group public key.
 * @return The opened evidence including identity A and a NIZK proof.
 */
Evidence Proof(Params_schnorr pp_S, ECP PK_sig, Sigma_BFLS10 sigma, mpz_class msgDigest_FIX, GPK gpk);


/**
 * @brief Judge the validity and source of the evidence based on the BBS signature and its NIZK proof.
 *
 * This function determines whether a given piece of evidence (i.e., a BBS signature trace result and its proof)
 * is valid, and if so, identifies the responsible signer or sanitizer.
 *
 * Interpretation of return values:
 * - If `idx == 1`, it refers to the first signer (registered in `main`), as signers start with index 1.
 * - If `idx == 0`, it means the evidence is invalid (i.e., the `A` in the evidence is not from a valid signer).
 * - If `idx > 1`, it identifies a sanitizer with the corresponding index.
 *
 * @param evidence The `Evidence` structure containing the opened identity `A` and the NIZK proof `pi`.
 * @param sigma The `Sigma_BFLS10` structure containing the full BBS signature parameters used for verification.
 * @return An integer representing the identity:
 *         - 0: invalid identity (`A` not in valid list),
 *         - 1: original signer,
 *         - >1: corresponding sanitizer index.
 */
int Judge(Evidence evidence, Sigma_BFLS10 sigma);