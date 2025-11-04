//! Proof generation and verification module
//!
//! This module provides functionality for generating and verifying zero-knowledge proofs
//! for SQL query execution using Halo2's PLONKish proving system.
//!
//! The proof system consists of:
//! - `prover`: Proof generation from circuits
//! - `verifier`: Proof verification
//!
//! # Overview
//!
//! The proof system enables:
//! - Non-interactive zero-knowledge proofs
//! - Proof generation from SQL query circuits
//! - Proof verification without revealing private data
//! - Integration with database commitments
//!
//! # Workflow
//!
//! 1. **Key Generation**: Generate proving and verifying keys from circuit
//! 2. **Proof Generation**: Create proof from circuit using proving key
//! 3. **Proof Verification**: Verify proof using verifying key
//!
//! # Example
//!
//! ```rust
//! use nzengi_db::proof::{Prover, Verifier};
//! use nzengi_db::circuit::NzengiCircuit;
//! use nzengi_db::commitment::IPAParams;
//!
//! // Generate parameters
//! let params = IPAParams::new(10); // 2^10 = 1024 rows
//!
//! // Create circuit
//! let circuit = NzengiCircuit::new();
//!
//! // Generate keys
//! let prover = Prover::new(&params);
//! let (pk, vk) = prover.generate_keys(&circuit)?;
//!
//! // Generate proof
//! let proof = prover.create_proof(&pk, &circuit, &[])?;
//!
//! // Verify proof
//! let verifier = Verifier::new(&params);
//! assert!(verifier.verify(&vk, &proof, &[])?);
//! ```

pub mod prover;
pub mod recursive;
pub mod verifier;

// Re-export main types for convenience
pub use prover::Prover;
pub use recursive::{ComposedProof, CompositionMetadata, RecursiveProver, RecursiveVerifier};
pub use verifier::Verifier;
