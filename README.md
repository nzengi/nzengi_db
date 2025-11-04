# nzengi_db

Zero-knowledge proofs for SQL query verification. Allows clients to verify query correctness without accessing the database.

## Quick Start

```bash
cargo build --release
cargo test
```

## Architecture

The system follows a standard prover-verifier model:

```
Client (Verifier) → SQL Query → Prover (with private DB) → Proof + Result → Client verifies
```

### Components

- **Database Commitment**: IPA-based commitment scheme for database integrity
- **PLONKish Circuits**: Custom gates for SQL operations (range checks, sort, group-by, join, aggregation)
- **Proof System**: Halo2-based prover and verifier
- **Query Processing**: SQL parser, planner, optimizer, executor

## Dependencies

```toml
halo2_proofs = { git = "https://github.com/privacy-scaling-explorations/halo2", tag = "v0.4.0" }
halo2curves = "0.9"
sqlparser = "0.59"
```

See `Cargo.toml` for full dependency list.

## Database Commitment

IPA protocol implementation for committing to database columns. Commitment time is O(n), verification is O(log n).

```rust
use nzengi_db::commitment::{IPAParams, VectorCommitment};

let params = IPAParams::new(15); // 2^15 max rows
let commitment = VectorCommitment::commit(&params, &values, None)?;
```

## Custom Gates

### Range Check

Bitwise decomposition for 64-bit integers. Splits values into 8 u8 cells with a 256-entry lookup table.

```rust
use nzengi_db::gates::range_check::BitwiseRangeCheckConfig;

let config = BitwiseRangeCheckConfig::configure(meta);
config.assign(layouter, value)?;
```

### Sort Gate

Proves that output table is a sorted permutation of input table. Two constraints:
- Permutation check: `Zi+1 · (Di + α) - Zi · (Ri + α) = 0`
- Sortedness: `Ri+1 - Ri ≥ 0`

### Group-By Gate

Identifies group boundaries in sorted data. Uses equality check:
- `b = 1 - (v1 - v2) · p` where `p = 0` if `v1 = v2`, else `p = 1/(v1-v2)`
- Validation: `b · (v1 - v2) = 0`

### Join Gate

Equality joins with permutation checks for both tables and deduplication verification.

### Aggregation Gate

Supports SUM, COUNT, AVG operations within groups. Uses accumulator pattern:
- SUM: `Mi = bi · Mi-1 + valuei · (1 - bi)`
- COUNT: `counti = endi - starti + 1`
- AVG: `avgi · counti - sumi = 0`

## Circuit Construction

The main circuit (`NzengiCircuit`) integrates all gates dynamically based on query operations:

```rust
use nzengi_db::circuit::NzengiCircuit;

let circuit = NzengiCircuit::new()
    .with_range_check(&values)
    .with_sort(&input, &sorted)
    .with_group_by(&grouped_data)
    .with_aggregation(&agg_data);
```

## Proof Generation

```rust
use nzengi_db::proof::{Prover, Verifier};

let prover = Prover::new(&params);
let (pk, vk) = prover.generate_keys(&circuit)?;
let proof = prover.create_proof(&pk, &circuit, &public_inputs)?;

let verifier = Verifier::new(&params);
assert!(verifier.verify(&vk, &proof, &public_inputs)?);
```

## Query Processing

SQL queries are parsed, planned, optimized, and executed:

```rust
use nzengi_db::query::{QueryParser, QueryPlanner, QueryExecutor};

let parser = QueryParser::new();
let ast = parser.parse("SELECT * FROM table WHERE id > 100")?;

let planner = QueryPlanner::new();
let plan = planner.plan(&ast)?;

let executor = QueryExecutor::new(&params);
let (result, proof) = executor.execute(&plan, &database)?;
```

## Performance

Tested on TPC-H benchmark (60k rows):

| Query | Proving Time | Verification Time | Proof Size |
|-------|--------------|-------------------|------------|
| Q1    | 110s         | 0.617s            | 8.6 KB     |
| Q3    | 161s         | 0.725s            | 24.7 KB    |
| Q5    | 313s         | 0.739s            | 29.6 KB    |

Database commitment scales linearly: ~2.9s for 60k rows, ~5.5s for 120k rows.

## Security

- **Completeness**: Honest prover always generates valid proofs
- **Soundness**: Dishonest prover cannot convince verifier (negligible probability)
- **Knowledge Soundness**: Proof implies prover has valid witness
- **Zero-Knowledge**: Verifier learns only circuit structure and output

Trust model assumes database commitment is verified by a trusted auditor (e.g., via blockchain).

## Implementation Details

### Field Arithmetic

Uses BN254 curve (254-bit prime field) via `halo2curves::bn256::Fr`.

### Polynomial Commitment

IPA (Inner Product Argument) backend. No trusted setup required.

### Constraint System

PLONKish arithmetization with:
- Fixed columns (circuit constants)
- Advice columns (private witnesses)
- Instance columns (public inputs)
- Lookup tables (for range checks)

### Permutation Checks

Low-degree polynomial form:
```
Zi+1 = Zi · [(Pi + α)(Qi + β)] / [(P'i + α)(Q'i + β)]
```

## Known Limitations

- Proof verification currently uses simplified check (TODO: full Halo2 verification)
- Database serialization uses JSON (bincode requires Encode/Decode traits)
- Some SQL dialects may not be fully supported

## Testing

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test --lib commitment
cargo test --lib gates
```

## Contributing

This is a research implementation. For production use, consider:
- Performance optimizations (parallel proof generation)
- Additional SQL operation gates
- Better error handling and diagnostics
- Full recursive proof composition

## License

See LICENSE file for details.

