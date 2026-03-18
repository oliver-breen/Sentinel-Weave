# QuantaWeave Formal Proof Sketches

This document collects formal proof sketches and security reductions for the QuantaWeave construction. These are *not* machine-checked proofs. They outline the assumptions, games, and reductions needed for a full formalization.

## Scope

QuantaWeave combines:
- LWE-based PKE for message confidentiality.
- ML-KEM for KEM-based shared-secret establishment.
- ML-DSA and Falcon for signatures.
- Hybrid KEM secret combiner to derive a single shared key.

The proofs below focus on *reductions* to well-studied assumptions. A complete proof would require formal definitions and parameter-specific bounds.

## Notation

- $\mathcal{A}$: PPT adversary.
- $\mathsf{Adv}^{\mathsf{X}}_{\mathcal{A}}$: Advantage of $\mathcal{A}$ in game X.
- LWE: Learning With Errors assumption for chosen parameters.
- ML-KEM: NIST-standardized KEM based on Module-LWE.
- ML-DSA: NIST-standardized signature based on Module-LWE.
- Falcon: NTRU-lattice signature scheme.

## 1. LWE PKE Confidentiality (CPA)

**Claim (informal):** The LWE-based PKE in `quantaweave/` is IND-CPA secure under the LWE assumption for the chosen parameters.

### Game Hop Outline

- **Game 0:** Real IND-CPA game for LWE PKE.
- **Game 1:** Replace public key $b = As + e$ with uniformly random $b \leftarrow \mathbb{Z}_q^n$.

**Reduction:** If $\mathcal{A}$ distinguishes Game 0 and Game 1, then we build $\mathcal{B}$ that solves LWE by embedding the LWE challenge into $(A, b)$.

**Conclusion:** $|\mathsf{Adv}^{\mathsf{IND-CPA}}_{\mathcal{A}}| \le \mathsf{Adv}^{\mathsf{LWE}}_{\mathcal{B}}$.

## 2. ML-KEM IND-CPA/IND-CCA (External)

**Claim (informal):** ML-KEM provides IND-CCA security as defined by the NIST standardization process (under Module-LWE with FO transform).

**Note:** This is inherited from the ML-KEM specification and liboqs implementation. QuantaWeave does not modify the algorithm.

## 3. Hybrid KEM Secret Combiner

Let the combiner be $H(\cdot)$ applied to the concatenation of shared secrets, with canonical scheme ordering.

**Claim (informal):** If at least one component KEM shared secret is computationally indistinguishable from random, then the combined secret is also indistinguishable from random (modeled as a random oracle over $H$).

### Assumptions

- $H$ is modeled as a random oracle (or a PRF-based KDF with domain separation).
- The shared secrets are length-regularized prior to concatenation.

### Sketch

If one component secret $s_i$ is uniform (or pseudorandom), then $H(s_1 || ... || s_i || ... || s_k)$ is pseudorandom in the random oracle model, regardless of the other components.

## 4. Signature Security

### ML-DSA (EUF-CMA)

**Claim (informal):** ML-DSA is EUF-CMA secure under Module-LWE / Module-SIS assumptions as per the NIST specification.

### Falcon (EUF-CMA)

**Claim (informal):** Falcon is EUF-CMA secure under the NTRU-lattice assumption with appropriate Gaussian sampling bounds.

**Note:** QuantaWeave treats ML-DSA and Falcon as black-box signatures; the security is inherited from their standardized/academic proofs and the correctness of implementations.

## 5. Hybrid Signature Verification

QuantaWeave verifies multiple signatures and can enforce a threshold.

**Claim (informal):** If the threshold is $t$, and at least $t$ schemes are EUF-CMA secure, then the hybrid verification is EUF-CMA secure against adversaries that must forge $t$ valid signatures.

### Sketch

Given a successful forgery on the hybrid scheme, extract a valid forgery for at least one of the component schemes by fixing the others and rewinding the adversary. The reduction loss scales with the number of schemes and the threshold.

## 6. Composition Notes

### Confidentiality + Authenticity

When using the hybrid KEM to derive a key and then encrypting via AES-GCM:

- If the derived key is indistinguishable from random, AES-GCM provides IND-CPA/INT-CTXT security under standard assumptions.
- Authenticity depends on correct nonce handling and no key reuse.

### Practical Caveats

- Side-channel resistance is not proven here.
- Concrete security depends on parameter selection and implementation correctness.
- Random oracle assumptions are heuristic.

## 7. Proof Obligations Checklist

To convert this into a full formal proof, define and prove:

1. IND-CPA for LWE PKE with explicit parameter bounds.
2. Hybrid KEM security in the random oracle or KDF model.
3. EUF-CMA for ML-DSA and Falcon from their standard assumptions.
4. Hybrid signature threshold reduction with tight bounds.
5. End-to-end security for the KEM+AEAD composition.

## References

- Regev, O. (2005/2009): LWE hardness and worst-case lattice reductions.
- NIST PQC: ML-KEM and ML-DSA specifications.
- Falcon: Fast-Fourier lattice-based compact signatures over NTRU.
