#ifndef IUT_K_SAN_H
#define IUT_K_SAN_H

#include "Tools.h"
#include <vector>
#include <string>
#include <stdexcept>
#include <tuple>
#include <cassert>

using namespace std;

// ============================================================================
// VRS (Verifiable Ring Signature) — EVeR + LogEq NIZKP
// ============================================================================
namespace VRS
{

    extern csprng rng;
    extern gmp_randstate_t state_gmp;

    // ---------- Structures ----------

    // System public parameters for Verifiable Ring Signatures
    struct VRS_Params
    {
        mpz_class p; // Prime order
        ECP G;       // Generator of the group
    };

    // VRS Secret Key
    struct VRS_SecretKey
    {
        mpz_class sk; // Private scalar
    };

    // VRS Public Key
    struct VRS_PublicKey
    {
        ECP pk; // Public group element
    };

    // Zero-Knowledge Proof for Logical Equivalence (LogEq)
    struct LogEq_Proof
    {
        vector<ECP> R, S;        // Commitments
        vector<mpz_class> c;     // Challenges
        vector<mpz_class> gamma; // Responses
    };

    // The Verifiable Ring Signature
    struct VRS_Signature
    {
        mpz_class r;   // Randomness
        ECP z;         // Linkability tag
        LogEq_Proof P; // NIZK proof of validity and anonymity
    };

    // Proof structure used by the Judge algorithm
    struct VRS_Proof_Judge
    {
        ECP z_bar;         // Tag tied to the prover
        LogEq_Proof P_bar; // NIZK proof to claim/disclaim origin
    };

    // ---------- Serialization helpers ----------
    inline string SerializeRing(vector<ECP> &L)
    {
        string s;
        for (auto &pt : L)
        {
            s += GenericSerializer::encode(pt) + "|";
        }
        return s;
    }

    inline void appendToOctet(octet *hash, const VRS_PublicKey &tag)
    {
        hash_recursive(hash, tag.pk);
    }

    inline void appendToOctet(octet *hash, const VRS_Signature &tag)
    {
        hash_recursive(hash, tag.r, tag.z);
        for (size_t i = 0; i < tag.P.R.size(); i++)
        {
            hash_recursive(hash, tag.P.R[i], tag.P.S[i]);
        }
    }

    // ---------- Algorithms ----------

    /**
     * @brief Initialize public parameters for VRS (SetupVRS).
     * @return VRS_Params The generated parameters.
     */
    VRS_Params V_Init();

    /**
     * @brief Generate a key pair for a ring member (KGenVRS).
     * @param pp Public parameters.
     * @return pair<VRS_PublicKey, VRS_SecretKey> The generated public and secret keys.
     */
    pair<VRS_PublicKey, VRS_SecretKey> V_Gen(VRS_Params pp);

    /**
     * @brief Generate an anonymous ring signature (SignVRS).
     * @param pp Public parameters.
     * @param L The ring of public keys.
     * @param m The message to sign.
     * @param sk The secret key of the actual signer.
     * @param my_index The index of the actual signer's public key within the ring L.
     * @return VRS_Signature The generated ring signature.
     */
    VRS_Signature V_Sig(VRS_Params pp, vector<ECP> &L, string m, VRS_SecretKey sk, size_t my_index);

    /**
     * @brief Verify a ring signature (VerifyVRS).
     * @param pp Public parameters.
     * @param L The ring of public keys.
     * @param m The signed message.
     * @param sig The ring signature to verify.
     * @return true if valid, false otherwise.
     */
    bool V_Ver(VRS_Params pp, vector<ECP> &L, string m, VRS_Signature sig);

    /**
     * @brief Produce a proof to claim or disavow a signature (ProveVRS).
     * @param pp Public parameters.
     * @param L The ring of public keys.
     * @param m The signed message.
     * @param sig The target signature.
     * @param my_pk The public key of the prover.
     * @param my_sk The secret key of the prover.
     * @return VRS_Proof_Judge The generated proof of origin (or non-origin).
     */
    VRS_Proof_Judge V_Proof(VRS_Params pp, vector<ECP> &L, string m, VRS_Signature sig,
                            VRS_PublicKey my_pk, VRS_SecretKey my_sk);

    /**
     * @brief Verify the origin proof provided by a ring member (JudgeVRS).
     * @param pp Public parameters.
     * @param L The ring of public keys.
     * @param m The signed message.
     * @param sig The target signature.
     * @param target_pk The public key of the member being judged.
     * @param pi The proof to evaluate.
     * @return int 1 if the target member created the signature, 0 otherwise.
     */
    int V_Judge(VRS_Params pp, vector<ECP> &L, string m, VRS_Signature sig,
                VRS_PublicKey target_pk, VRS_Proof_Judge pi);

} // namespace VRS

// ============================================================================
// EQS (Equivalence Signature) — Mercurial Signatures on BLS12-381
// ============================================================================
namespace EQS
{

    extern csprng rng;
    extern gmp_randstate_t state_gmp;

    // ---------- Structures ----------

    // System public parameters for EQS (Bilinear Group)
    struct Merc_Params
    {
        mpz_class p; // Prime order
        ECP P;       // Generator of G1
        ECP2 P_hat;  // Generator of G2
    };

    // EQS Secret Key
    struct Merc_SecretKey
    {
        vector<mpz_class> x; // Vector of secret scalars (length l)
    };

    // EQS Public Key
    struct Merc_PublicKey
    {
        vector<ECP2> X_hat; // Vector of public elements in G2 (length l)
    };

    // Mercurial Signature
    struct Merc_Signature
    {
        ECP Z, Y;   // Elements in G1
        ECP2 Y_hat; // Element in G2
    };

    // ---------- Serialization helpers ----------
    inline string SerializePK_EQS(Merc_PublicKey pk)
    {
        string s;
        for (auto &X : pk.X_hat)
        {
            s += GenericSerializer::encode(X) + "|";
        }
        return s;
    }

    inline void appendToOctet(octet *hash, const Merc_Signature &tag)
    {
        hash_recursive(hash, tag.Z, tag.Y, tag.Y_hat);
    }

    inline void appendToOctet(octet *hash, const Merc_PublicKey &tag)
    {
        for (size_t i = 0; i < tag.X_hat.size(); i++)
        {
            hash_recursive(hash, tag.X_hat[i]);
        }
    }

    // ---------- Algorithms ----------

    /**
     * @brief Initialize Bilinear Group parameters (BGGen).
     * @return Merc_Params The generated parameters.
     */
    Merc_Params PPGen();

    /**
     * @brief Generate an EQS key pair for vectors of length l (KGenEQS).
     * @param pp Public parameters.
     * @param l The length of the message vector to be signed.
     * @return pair<Merc_PublicKey, Merc_SecretKey> The generated key pair.
     */
    pair<Merc_PublicKey, Merc_SecretKey> KeyGen(Merc_Params pp, size_t l);

    /**
     * @brief Sign a vector of group elements (SignEQS).
     * @param pp Public parameters.
     * @param sk The EQS secret key.
     * @param M The vector of group elements to sign.
     * @return Merc_Signature The generated equivalence class signature.
     */
    Merc_Signature Sign(Merc_Params pp, Merc_SecretKey sk, vector<ECP> &M);

    /**
     * @brief Verify an equivalence class signature (VerifyEQS).
     * @param pp Public parameters.
     * @param pk The EQS public key.
     * @param M The signed vector of group elements.
     * @param sig The signature to verify.
     * @return true if valid, false otherwise.
     */
    bool Verify(Merc_Params pp, Merc_PublicKey pk, vector<ECP> &M, Merc_Signature sig);

    /**
     * @brief Convert secret key by scalar rho.
     */
    Merc_SecretKey ConvertSK(Merc_Params pp, Merc_SecretKey sk, mpz_class rho);

    /**
     * @brief Convert public key by scalar rho.
     */
    Merc_PublicKey ConvertPK(Merc_PublicKey pk, mpz_class rho);

    /**
     * @brief Convert signature by scalar rho.
     */
    Merc_Signature ConvertSig(Merc_Params pp, Merc_PublicKey pk, vector<ECP> &M,
                              Merc_Signature sig, mpz_class rho);

    /**
     * @brief Adapt a representative and its signature to a new random representative (ChgRepEQS).
     * Allows re-randomization of the signature within the same equivalence class to ensure unlinkability.
     * @param pp Public parameters.
     * @param pk The EQS public key.
     * @param M The original vector of group elements.
     * @param sig The original signature.
     * @param mu The randomization scalar.
     * @return pair<vector<ECP>, Merc_Signature> The randomized message vector and adapted signature.
     */
    pair<vector<ECP>, Merc_Signature> ChangeRep(Merc_Params pp, Merc_PublicKey pk,
                                                vector<ECP> &M, Merc_Signature sig, mpz_class mu);

} // namespace EQS

// ============================================================================
// PKE (Paillier Encryption)
// ============================================================================
namespace PKE
{

    extern csprng rng;
    extern gmp_randstate_t state_gmp;

    // ---------- Structures ----------

    // Paillier Public Key
    struct PKE_PublicKey
    {
        mpz_class n, g, n_sq;
    };

    // Paillier Secret Key
    struct PKE_SecretKey
    {
        mpz_class lambda, mu;
    };

    // Paillier Ciphertext
    struct PKE_Ciphertext
    {
        mpz_class c;
    };

    // ---------- Serialization helpers ----------
    inline string SerializePK(PKE_PublicKey pk)
    {
        return pk.n.get_str(16);
    }

    inline void appendToOctet(octet *hash, const PKE_Ciphertext &tag)
    {
        hash_recursive(hash, tag.c);
    }

    inline void appendToOctet(octet *hash, const PKE_PublicKey &tag)
    {
        hash_recursive(hash, tag.n, tag.g, tag.n_sq);
    }

    // ---------- Algorithms ----------

    /**
     * @brief Generate a Paillier key pair (returns only public key for convenience).
     */
    PKE_PublicKey KGenPKE(int lambda_bits);

    /**
     * @brief Generate a full Paillier key pair (KGenPKE).
     * @param lambda_bits Security parameter / bit length.
     * @param pk Output public key.
     * @param sk Output secret key.
     */
    void KGenPKE_full(int lambda_bits, PKE_PublicKey &pk, PKE_SecretKey &sk);

    /**
     * @brief Encrypt a scalar (EncryptPKE).
     * @param pk The receiver's public key.
     * @param m The plaintext scalar.
     * @return PKE_Ciphertext The generated ciphertext.
     */
    PKE_Ciphertext EncryptPKE(PKE_PublicKey pk, mpz_class m);

    /**
     * @brief Decrypt a ciphertext (DecryptPKE).
     * @param pk The public key.
     * @param sk The secret key.
     * @param ctx The ciphertext.
     * @return mpz_class The decrypted plaintext.
     */
    mpz_class DecryptPKE(PKE_PublicKey pk, PKE_SecretKey sk, PKE_Ciphertext ctx);

    /**
     * @brief Homomorphically multiply the encrypted plaintext by a scalar (MultiplyPKE).
     * This enables the sanitizer to unlinkably randomize the encrypted BLS inner keys without decrypting others' keys.
     * @param pk The public key.
     * @param ctx The original ciphertext E(m).
     * @param s The scalar to multiply.
     * @return PKE_Ciphertext A new ciphertext containing E(m * s).
     */
    PKE_Ciphertext MultiplyPKE(PKE_PublicKey pk, PKE_Ciphertext ctx, mpz_class s);

} // namespace PKE

// ============================================================================
// IUT-k-SAN (Main Scheme)
// ============================================================================
namespace IUT
{

    extern csprng rng;
    extern gmp_randstate_t state_gmp;

    // ---------- Structures ----------

    // System public parameters aggregating BLS, VRS, and EQS parameters.
    struct Params
    {
        mpz_class q;
        ECP g1;
        ECP2 g2;
        VRS::VRS_Params vrs_pp;
        EQS::Merc_Params eqs_pp;
    };

    // Signer's long-term key pairs
    struct IUT_SignerKey
    {
        EQS::Merc_SecretKey sk_EQS; // Used for the outer signature over inner keys
        EQS::Merc_PublicKey pk_EQS;
        VRS::VRS_SecretKey sk_SP; // Used to sign the final tuple in the anonymity ring
        VRS::VRS_PublicKey pk_SP;
    };

    // Sanitizer's long-term key pairs
    struct IUT_SanitizerKey
    {
        PKE::PKE_SecretKey sk_ZE; // Used to decrypt inner BLS keys for sanitization
        PKE::PKE_PublicKey pk_ZE;
        VRS::VRS_SecretKey sk_ZP; // Used to sign the modified tuple in the anonymity ring
        VRS::VRS_PublicKey pk_ZP;
    };

    // Core signature components excluding the final VRS ring signature
    struct IUT_SigmaSS
    {
        EQS::Merc_Signature mu;                  // Outer signature over X_j
        EQS::Merc_Signature eta;                 // Outer signature over Y_j
        vector<ECP2> sigma_j;                    // BLS-like inner signatures on hashes of blocks
        vector<ECP> X_j;                         // Ephemeral BLS public keys (base part)
        vector<ECP> Y_j;                         // Ephemeral BLS public keys (exponentiated part)
        vector<vector<PKE::PKE_Ciphertext>> SKZ; // Encrypted inner private keys. Size: [k sanitizers] x [N blocks]
    };

    // The complete IUT-k-SAN signature
    struct IUT_Signature
    {
        IUT_SigmaSS sigma_SS;         // Core signature with inner keys and ciphertexts
        VRS::VRS_Signature sigma_VRS; // Final ring signature providing sanitizer anonymity
    };

    // ---------- Serialization helpers ----------
    string Serialize(VRS::VRS_PublicKey pk_SP, vector<string> &m_ext,
                     vector<IUT_SanitizerKey> &PKZ, IUT_SigmaSS &sigma_SS);

    inline void appendToOctet(octet *hash, const IUT_SigmaSS &tag)
    {
        hash_recursive(hash, tag.mu, tag.eta);
        for (size_t j = 0; j < tag.sigma_j.size(); j++)
        {
            hash_recursive(hash, tag.sigma_j[j], tag.X_j[j], tag.Y_j[j]);
        }
    }

    // ---------- Core Algorithms ----------

    /**
     * @brief Initialize system parameters (Setup).
     * @param n Base number of message blocks.
     * @param k Number of authorized sanitizers.
     * @return Params The initialized system parameters.
     */
    Params Setup(size_t n, size_t k);

    /**
     * @brief Generate the key pairs for the original signer (KGen_S).
     * @param pp System parameters.
     * @param expected_N Total number of elements signed by EQS (n message blocks + PKZ size).
     * @return IUT_SignerKey The generated signer keys.
     */
    IUT_SignerKey KGen_S(Params pp, size_t expected_N);

    /**
     * @brief Generate the key pairs for a sanitizer (KGen_Z).
     * @param pp System parameters.
     * @return IUT_SanitizerKey The generated sanitizer keys.
     */
    IUT_SanitizerKey KGen_Z(Params pp);

    /**
     * @brief Sign a message authorizing specific sanitizers to modify specific blocks (Sign).
     * Creates inner BLS signatures, encrypts the inner keys into SKZ according to admissibility matrix A,
     * signs the public components with EQS, and finalizes with a VRS ring signature.
     * @param pp System parameters.
     * @param skS Signer's private keys.
     * @param PKZ List of public keys of the k authorized sanitizers.
     * @param m The message divided into blocks.
     * @param A Admissibility matrix (k x n) indicating which sanitizer can modify which block.
     * @return IUT_Signature The generated multi-sanitizer signature.
     */
    IUT_Signature Sign(Params pp, IUT_SignerKey skS, vector<IUT_SanitizerKey> &PKZ,
                       vector<string> &m, vector<vector<int>> &A);

    /**
     * @brief Alter authorized message blocks and update the signature to maintain unlinkability (Sanitize).
     * Decrypts inner keys, modifies blocks, updates signatures, homomorphically randomizes all encrypted SKZ,
     * and generates a new VRS ring signature using the sanitizer's key.
     * @param pp System parameters.
     * @param skZ Private keys of the sanitizer performing the operation.
     * @param pkS Public keys of the original signer.
     * @param PKZ List of public keys of all authorized sanitizers.
     * @param m The current message vector.
     * @param MOD_indices The indices of the blocks to modify.
     * @param m_prime The new content for the modified blocks.
     * @param sig The current signature to be sanitized.
     * @return IUT_Signature The newly sanitized and unlinkable signature.
     */
    IUT_Signature Sanitize(Params pp, IUT_SanitizerKey &skZ, IUT_SignerKey &pkS,
                           vector<IUT_SanitizerKey> &PKZ, vector<string> &m,
                           vector<int> &MOD_indices, vector<string> &m_prime,
                           IUT_Signature &sig);

    /**
     * @brief Verify an IUT-k-SAN signature (Verify).
     * Checks the EQS signatures, VRS ring signature, and validates each inner BLS signature via pairings.
     * @param pp System parameters.
     * @param pkS Public keys of the original signer.
     * @param PKZ List of public keys of the authorized sanitizers.
     * @param m The message vector to verify.
     * @param sig The signature.
     * @return true if valid, false otherwise.
     */
    bool Verify(Params pp, IUT_SignerKey &pkS, vector<IUT_SanitizerKey> &PKZ,
                vector<string> &m, IUT_Signature &sig);

    /**
     * @brief Produce a proof of origin (or non-origin) for a signature (Prove).
     * Used by the signer to enforce accountability.
     * @param skS Signer's private keys.
     * @param PKZ List of public keys of the authorized sanitizers.
     * @param m The message vector.
     * @param sig The signature.
     * @return VRS::VRS_Proof_Judge The generated proof evaluating origin.
     */
    VRS::VRS_Proof_Judge Prove(IUT_SignerKey &skS, vector<IUT_SanitizerKey> &PKZ,
                               vector<string> &m, IUT_Signature &sig);

    /**
     * @brief Evaluate the proof of origin produced by a member (Judge).
     * @param pkS Public keys of the original signer.
     * @param PKZ List of public keys of the authorized sanitizers.
     * @param m The message vector.
     * @param sig The signature.
     * @param pi The proof to evaluate.
     * @return int 1 (S) if the signer generated it, 0 (Z) if a sanitizer generated it.
     */
    int Judge(IUT_SignerKey &pkS, vector<IUT_SanitizerKey> &PKZ,
              vector<string> &m, IUT_Signature &sig, VRS::VRS_Proof_Judge pi);

} // namespace IUT

#endif // IUT_K_SAN_H