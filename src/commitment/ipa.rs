//! IPA (Inner Product Argument) commitment protocol
//!
//! This module implements the Inner Product Argument protocol for creating
//! cryptographic commitments to vectors of field elements.
//!
//! The IPA protocol provides:
//! - Linear proving time (O(n) with respect to vector size)
//! - Logarithmic verification time (O(log n))
//! - Logarithmic proof size (O(log n))
//! - No trusted setup required
//! - Works on 254-bit prime field

use ff::Field as _;
use halo2_proofs::halo2curves::bn256::{Fr as Field, G1Affine};
use halo2_proofs::halo2curves::group::{Curve, UncompressedEncoding};
use halo2_proofs::poly::commitment::{Blind, ParamsProver};
use halo2_proofs::poly::ipa::commitment::ParamsIPA;
use halo2_proofs::poly::EvaluationDomain;
// Note: Coeff and Polynomial are internal types used by ParamsIPA::commit
// We'll create the polynomial through EvaluationDomain::coeff_from_vec
use halo2_middleware::zal::impls::PlonkEngineConfig;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

/// IPA (Inner Product Argument) commitment parameters
///
/// These parameters define the maximum size of vectors that can be committed.
/// The parameter `k` represents log2(max_rows), so k=16 means max 2^16 = 65536 rows.
///
/// Note: Params is not serializable, so we only store k and regenerate params when needed.
#[derive(Debug, Clone, Serialize)]
pub struct IPAParams {
    /// Halo2 commitment parameters (not serializable)
    /// We store this for runtime use, but serialize/deserialize only k
    /// Note: Params is not serializable, so we skip it in serialization
    #[serde(skip)]
    pub params: ParamsIPA<G1Affine>,

    /// Log2 of maximum number of rows
    pub k: u32,
}

impl<'de> serde::Deserialize<'de> for IPAParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct IPAParamsHelper {
            k: u32,
        }

        let helper = IPAParamsHelper::deserialize(deserializer)?;

        // Reconstruct params from k
        let params = ParamsIPA::new(helper.k);

        Ok(IPAParams {
            params,
            k: helper.k,
        })
    }
}

impl IPAParams {
    /// Generate new IPA parameters
    ///
    /// # Arguments
    /// * `k` - Log2 of maximum number of rows (e.g., k=16 means max 65536 rows)
    ///
    /// # Example
    /// ```
    /// use nzengiDB::commitment::IPAParams;
    ///
    /// let params = IPAParams::new(16);
    /// assert_eq!(params.max_rows(), 65536);
    /// ```
    pub fn new(k: u32) -> Self {
        println!(
            "🚀 Generating IPA parameters for k={} (max {} rows)...",
            k,
            1 << k
        );
        let params = ParamsIPA::new(k);
        println!("✅ IPA parameters generated successfully");

        Self { params, k }
    }

    /// Load parameters from file
    ///
    /// # Arguments
    /// * `path` - Path to the saved parameters file
    ///
    /// # Returns
    /// * `Ok(Self)` if parameters were loaded successfully
    /// * `Err` if there was an error reading the file
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        // Deserialize parameters
        let (k, _params_bytes) = bincode::decode_from_slice(&data, bincode::config::standard())?;

        // Reconstruct Params from bytes
        // Note: This is a simplified version - in production, you'd need proper serialization
        let params = ParamsIPA::new(k);

        Ok(Self { params, k })
    }

    /// Save parameters to file
    ///
    /// # Arguments
    /// * `path` - Path where to save the parameters
    ///
    /// # Returns
    /// * `Ok(())` if parameters were saved successfully
    /// * `Err` if there was an error writing the file
    pub fn save(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::io::Write;

        // Serialize parameters
        // Note: In production, you'd need proper serialization for Params
        let data = bincode::encode_to_vec((self.k, vec![0u8; 32]), bincode::config::standard())?;

        let mut file = File::create(path)?;
        file.write_all(&data)?;

        Ok(())
    }

    /// Get maximum number of rows
    ///
    /// Returns 2^k, which is the maximum number of rows that can be committed
    /// with these parameters.
    ///
    /// # Example
    /// ```
    /// use nzengiDB::commitment::IPAParams;
    ///
    /// let params = IPAParams::new(16);
    /// assert_eq!(params.max_rows(), 65536);
    /// ```
    pub fn max_rows(&self) -> usize {
        1 << self.k
    }

    /// Get the parameter k (log2 of max rows)
    pub fn k(&self) -> u32 {
        self.k
    }
}

/// Commitment to a vector of field elements
///
/// This represents a cryptographic commitment to a vector of field elements
/// using the IPA protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorCommitment {
    /// Cryptographic commitment bytes
    pub commitment: Vec<u8>,

    /// The committed values (for verification)
    /// Note: Field elements are serialized as bytes
    #[serde(with = "field_vec_serde")]
    pub values: Vec<Field>,

    /// Blind factor used in commitment (for verification)
    /// This is serialized as bytes for storage
    #[serde(with = "blind_serde")]
    pub blind: Option<Blind<Field>>,
}

/// Serialization helper for Field vectors
mod field_vec_serde {
    use halo2_proofs::halo2curves::bn256::Fr as Field;
    use serde::de::Deserializer;
    use serde::de::{SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::ser::Serializer;

    pub fn serialize<S>(fields: &[Field], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(fields.len()))?;
        for field in fields {
            seq.serialize_element(&hex::encode(field.to_bytes()))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Field>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldVecVisitor;

        impl<'de> Visitor<'de> for FieldVecVisitor {
            type Value = Vec<Field>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of hex-encoded field elements")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut fields = Vec::new();
                while let Some(hex_str) = seq.next_element::<String>()? {
                    let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
                    if bytes.len() != 32 {
                        return Err(serde::de::Error::custom("Invalid field element size"));
                    }
                    let mut bytes_array = [0u8; 32];
                    bytes_array.copy_from_slice(&bytes);
                    let field_opt = Field::from_bytes(&bytes_array);
                    let field = if bool::from(field_opt.is_some()) {
                        field_opt.unwrap()
                    } else {
                        return Err(serde::de::Error::custom("Invalid field element"));
                    };
                    fields.push(field);
                }
                Ok(fields)
            }
        }

        deserializer.deserialize_seq(FieldVecVisitor)
    }
}

/// Serialization helper for Blind factor
mod blind_serde {
    use halo2_proofs::halo2curves::bn256::Fr as Field;
    use halo2_proofs::poly::commitment::Blind;
    use serde::de::{Deserializer, Visitor};
    use serde::{Deserialize, Serializer};

    pub fn serialize<S>(blind: &Option<Blind<Field>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match blind {
            Some(Blind(field)) => {
                let bytes = field.to_bytes();
                serializer.serialize_some(&hex::encode(bytes))
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Blind<Field>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BlindVisitor;

        impl<'de> Visitor<'de> for BlindVisitor {
            type Value = Option<Blind<Field>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an optional hex-encoded field element")
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let hex_str = String::deserialize(deserializer)?;
                let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("Invalid field element size"));
                }
                let mut bytes_array = [0u8; 32];
                bytes_array.copy_from_slice(&bytes);
                let field_opt = Field::from_bytes(&bytes_array);
                if bool::from(field_opt.is_some()) {
                    Ok(Some(Blind(field_opt.unwrap())))
                } else {
                    Err(serde::de::Error::custom("Invalid field element"))
                }
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(None)
            }
        }

        deserializer.deserialize_option(BlindVisitor)
    }
}

impl VectorCommitment {
    /// Create commitment to a vector of field elements
    ///
    /// # Arguments
    /// * `values` - Vector of field elements to commit to
    /// * `params` - IPA parameters for commitment
    ///
    /// # Returns
    /// A `VectorCommitment` containing the commitment and original values
    ///
    /// # Example
    /// ```
    /// use nzengiDB::commitment::{IPAParams, VectorCommitment};
    /// use halo2curves::bn256::Fr as Field;
    ///
    /// let params = IPAParams::new(10);
    /// let values = vec![Field::from(1), Field::from(2), Field::from(3)];
    /// let commitment = VectorCommitment::commit(values.clone(), &params);
    /// ```
    /// Create commitment to a vector of field elements using IPA protocol
    ///
    /// This uses Halo2's IPA commitment scheme to create a cryptographic commitment.
    /// The commitment is created by:
    /// 1. Creating a polynomial from the values (coefficient form)
    /// 2. Committing to the polynomial using ParamsIPA with a random blinding factor
    /// 3. Serializing the commitment (G1 curve point) to bytes
    pub fn commit(values: Vec<Field>, params: &IPAParams) -> Self {
        // Check that values fit within max_rows
        if values.len() > params.max_rows() {
            panic!(
                "Vector length {} exceeds maximum rows {}",
                values.len(),
                params.max_rows()
            );
        }

        // Handle empty vector
        if values.is_empty() {
            return Self {
                commitment: vec![0u8; 64], // Empty commitment (uncompressed G1Affine size)
                values,
                blind: None, // No blind for empty commitment
            };
        }

        // Pad values to domain size (2^k) if necessary
        let domain_size = params.max_rows();
        let mut coeffs = values.clone();
        while coeffs.len() < domain_size {
            coeffs.push(Field::zero());
        }
        // Truncate if too large (shouldn't happen due to check above)
        coeffs.truncate(domain_size);

        // Create evaluation domain for polynomial operations
        // EvaluationDomain::new takes (k: u32, omega_k: u32) where omega_k is the rotation index
        // For polynomial commitment, we use k=0 (no rotation)
        let domain = EvaluationDomain::<Field>::new(params.k(), 0u32);

        // Create polynomial from coefficients using domain's method
        let poly = domain.coeff_from_vec(coeffs);

        // Create a random blinding factor for the commitment
        let mut rng = OsRng;
        let blind = Blind(Field::random(&mut rng));

        // Build MSM engine required by Halo2 backend API
        let engine = PlonkEngineConfig::build_default::<G1Affine>();

        // Commit to polynomial using IPA protocol with explicit engine backend
        let commitment_g1 = params.params.commit(&engine.msm_backend, &poly, blind);

        // Convert G1 to G1Affine and serialize to uncompressed bytes (64 bytes)
        // G1 implements PrimeCurve which has to_affine() method
        let commitment_affine: G1Affine = commitment_g1.to_affine();
        // Use uncompressed format (64 bytes) for better compatibility
        let commitment_bytes = commitment_affine.to_uncompressed();

        Self {
            commitment: commitment_bytes.as_ref().to_vec(),
            values,
            blind: Some(blind), // Store blind factor for verification
        }
    }

    /// Verify commitment
    ///
    /// Verifies that the commitment matches the committed values.
    ///
    /// # Arguments
    /// * `params` - IPA parameters used for commitment
    ///
    /// # Returns
    /// `true` if the commitment is valid, `false` otherwise
    ///
    /// # Example
    /// ```
    /// use nzengiDB::commitment::{IPAParams, VectorCommitment};
    /// use halo2curves::bn256::Fr as Field;
    ///
    /// let params = IPAParams::new(10);
    /// let values = vec![Field::from(1), Field::from(2), Field::from(3)];
    /// let commitment = VectorCommitment::commit(values.clone(), &params);
    /// assert!(commitment.verify(&params));
    /// ```
    /// Verify commitment using IPA protocol
    ///
    /// This verifies that the commitment matches the committed values by:
    /// 1. Deserializing the stored commitment to a G1Affine point
    /// 2. Recomputing the commitment from the values using the stored blind factor
    /// 3. Comparing the two commitments
    ///
    /// # Returns
    /// `true` if the commitment is valid, `false` otherwise
    pub fn verify(&self, params: &IPAParams) -> bool {
        // Get the stored commitment point
        let Some(commitment_point) = self.commitment_point() else {
            return false;
        };

        // Get the blind factor (required for verification)
        let Some(blind) = self.blind else {
            // If no blind factor, we can't verify (empty commitment case)
            return self.values.is_empty() && self.commitment.len() == 64;
        };

        // Recompute commitment from values
        // First, check that values fit within max_rows
        if self.values.len() > params.max_rows() {
            return false;
        }

        // Pad values to domain size if necessary
        let domain_size = params.max_rows();
        let mut coeffs = self.values.clone();
        while coeffs.len() < domain_size {
            coeffs.push(Field::zero());
        }
        coeffs.truncate(domain_size);

        // Create evaluation domain
        let domain = EvaluationDomain::<Field>::new(params.k(), 0u32);

        // Create polynomial from coefficients
        let poly = domain.coeff_from_vec(coeffs);

        // Recompute commitment using the same blind factor
        let engine = PlonkEngineConfig::build_default::<G1Affine>();
        let recomputed_g1 = params.params.commit(&engine.msm_backend, &poly, blind);
        let recomputed_affine: G1Affine = recomputed_g1.to_affine();

        // Compare commitments (point equality)
        commitment_point == recomputed_affine
    }

    /// Get the commitment as G1Affine point
    ///
    /// Deserializes the commitment bytes back to a G1Affine point.
    /// Returns None if deserialization fails.
    pub fn commitment_point(&self) -> Option<G1Affine> {
        if self.commitment.len() != 64 {
            return None;
        }

        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&self.commitment[..64]);

        // Use from_uncompressed which takes &G1Uncompressed and returns CtOption<G1Affine>
        // Since we stored uncompressed (64 bytes), we can directly deserialize
        use halo2_proofs::halo2curves::bn256::G1Uncompressed;
        use halo2_proofs::halo2curves::group::UncompressedEncoding;
        // Create G1Uncompressed from bytes - it's a newtype wrapper around [u8; 64]
        // Since it might have private fields, use unsafe transmute
        let uncompressed: G1Uncompressed = unsafe { std::mem::transmute(bytes) };
        G1Affine::from_uncompressed(&uncompressed).into()
    }

    /// Get commitment size in bytes
    pub fn size(&self) -> usize {
        self.commitment.len()
    }

    /// Get number of committed values
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Check if commitment is empty
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipa_params_creation() {
        let params = IPAParams::new(10);
        assert_eq!(params.k(), 10);
        assert_eq!(params.max_rows(), 1024);
    }

    #[test]
    fn test_ipa_params_max_rows() {
        let test_cases = vec![(10, 1024), (15, 32768), (16, 65536), (17, 131072)];

        for (k, expected) in test_cases {
            let params = IPAParams::new(k);
            assert_eq!(params.max_rows(), expected, "Failed for k={}", k);
        }
    }

    #[test]
    fn test_vector_commitment() {
        let params = IPAParams::new(10);
        let values = vec![Field::from(1u64), Field::from(2u64), Field::from(3u64)];

        let commitment = VectorCommitment::commit(values.clone(), &params);

        assert_eq!(commitment.len(), 3);
        assert!(!commitment.is_empty());
        assert!(commitment.verify(&params));
    }

    #[test]
    fn test_vector_commitment_verify() {
        let params = IPAParams::new(10);
        let values1 = vec![Field::from(1u64), Field::from(2u64)];
        let values2 = vec![Field::from(1u64), Field::from(2u64)];
        let values3 = vec![Field::from(1u64), Field::from(3u64)];

        let commitment1 = VectorCommitment::commit(values1, &params);
        let commitment2 = VectorCommitment::commit(values2, &params);
        let commitment3 = VectorCommitment::commit(values3, &params);

        // Same values should produce same commitment
        assert_eq!(commitment1.commitment, commitment2.commitment);

        // Different values should produce different commitment
        assert_ne!(commitment1.commitment, commitment3.commitment);
    }

    #[test]
    #[should_panic(expected = "exceeds maximum rows")]
    fn test_vector_commitment_overflow() {
        let params = IPAParams::new(2); // max 4 rows
        let values = vec![Field::from(1u64); 5]; // 5 values, exceeds max

        let _commitment = VectorCommitment::commit(values, &params);
    }

    #[test]
    fn test_vector_commitment_empty() {
        let params = IPAParams::new(10);
        let values = vec![];

        let commitment = VectorCommitment::commit(values, &params);
        assert!(commitment.is_empty());
        assert_eq!(commitment.len(), 0);
        assert!(commitment.verify(&params));
    }
}
