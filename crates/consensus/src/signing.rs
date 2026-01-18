use std::fmt::{Debug, Display};
use std::io::{Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use cipherbft_crypto::{
    Ed25519KeyPair, Ed25519PublicKey as CryptoPublicKey, Ed25519SecretKey as CryptoSecretKey,
    Ed25519Signature as CryptoSignature,
};
use informalsystems_malachitebft_core_types::SigningScheme;
use serde::{Deserialize, Serialize};

/// Wrapper around Ed25519 public key for Malachite.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusPublicKey(pub CryptoPublicKey);

impl BorshSerialize for ConsensusPublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_bytes())
    }
}

impl BorshDeserialize for ConsensusPublicKey {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        let pk = CryptoPublicKey::from_bytes(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Self(pk))
    }
}

impl Debug for ConsensusPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConsensusPublicKey({:?})", self.0)
    }
}

/// Wrapper around Ed25519 secret key for Malachite.
#[derive(Clone)]
pub struct ConsensusPrivateKey(pub CryptoSecretKey);

impl Debug for ConsensusPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConsensusPrivateKey([REDACTED])")
    }
}

/// Wrapper around Ed25519 signature for Malachite.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsensusSignature(pub [u8; 64]);

impl BorshSerialize for ConsensusSignature {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0)
    }
}

impl BorshDeserialize for ConsensusSignature {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; 64];
        reader.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl Debug for ConsensusSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConsensusSignature({})", hex::encode(&self.0[..8]))
    }
}

impl From<CryptoSignature> for ConsensusSignature {
    fn from(sig: CryptoSignature) -> Self {
        Self(sig.to_bytes())
    }
}

impl ConsensusSignature {
    pub fn to_crypto(&self) -> Result<CryptoSignature, cipherbft_crypto::error::CryptoError> {
        CryptoSignature::from_bytes(&self.0)
    }
}

/// Error when decoding a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureDecodingError(&'static str);

impl Display for SignatureDecodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Ed25519 signing scheme for Malachite integration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519SigningScheme;

impl SigningScheme for Ed25519SigningScheme {
    type DecodingError = SignatureDecodingError;
    type Signature = ConsensusSignature;
    type PublicKey = ConsensusPublicKey;
    type PrivateKey = ConsensusPrivateKey;

    fn decode_signature(bytes: &[u8]) -> Result<Self::Signature, Self::DecodingError> {
        if bytes.len() != 64 {
            return Err(SignatureDecodingError("invalid signature length"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        Ok(ConsensusSignature(arr))
    }

    fn encode_signature(signature: &Self::Signature) -> Vec<u8> {
        signature.0.to_vec()
    }
}

/// Thin wrapper to keep consensus signing concerns localized.
#[derive(Clone, Debug)]
pub struct ConsensusSigner {
    keypair: Ed25519KeyPair,
}

impl ConsensusSigner {
    /// Create from an existing keypair.
    pub fn new(keypair: Ed25519KeyPair) -> Self {
        Self { keypair }
    }

    /// Public key accessor.
    pub fn public_key(&self) -> ConsensusPublicKey {
        ConsensusPublicKey(self.keypair.public_key.clone())
    }

    /// Validator ID derived from the public key.
    pub fn validator_id(&self) -> cipherbft_types::ValidatorId {
        self.keypair.validator_id()
    }

    /// Sign arbitrary bytes.
    pub fn sign(&self, msg: &[u8]) -> ConsensusSignature {
        ConsensusSignature(self.keypair.sign(msg).to_bytes())
    }
}

#[cfg(feature = "malachite")]
mod signing_provider {
    use super::{ConsensusPublicKey, ConsensusSignature, ConsensusSigner};
    use crate::context::CipherBftContext;
    use crate::proposal::{CutProposal, CutProposalPart};
    use crate::vote::ConsensusVote;
    use informalsystems_malachitebft_core_types::{Signature, SignedMessage, SigningProvider};

    /// Deterministic byte encoding for signatures.
    fn encode_vote(vote: &ConsensusVote) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&vote.height.0.to_be_bytes());
        out.extend_from_slice(&vote.round.as_i64().to_be_bytes());
        out.push(match vote.vote_type {
            informalsystems_malachitebft_core_types::VoteType::Prevote => 0,
            informalsystems_malachitebft_core_types::VoteType::Precommit => 1,
        });
        match vote.value.as_ref() {
            informalsystems_malachitebft_core_types::NilOrVal::Nil => out.push(0),
            informalsystems_malachitebft_core_types::NilOrVal::Val(id) => {
                out.push(1);
                out.extend_from_slice(id.0.as_bytes());
            }
        }
        out.extend_from_slice(vote.validator.0.as_bytes());
        if let Some(ext) = &vote.extension {
            out.extend_from_slice(&(ext.signature.0.len() as u32).to_be_bytes());
            out.extend_from_slice(&ext.signature.0);
        } else {
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        out
    }

    fn encode_proposal(proposal: &CutProposal) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&proposal.height.0.to_be_bytes());
        out.extend_from_slice(&proposal.round.as_i64().to_be_bytes());
        out.extend_from_slice(&proposal.pol_round.as_i64().to_be_bytes());
        out.extend_from_slice(proposal.value.cut().hash().as_bytes());
        out.extend_from_slice(proposal.proposer.0.as_ref());
        out
    }

    fn encode_proposal_part(part: &CutProposalPart) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(part.cut.hash().as_bytes());
        out.push(part.first as u8);
        out.push(part.last as u8);
        out
    }

    #[derive(Clone, Debug)]
    pub struct ConsensusSigningProvider {
        signer: ConsensusSigner,
    }

    impl ConsensusSigningProvider {
        pub fn new(signer: ConsensusSigner) -> Self {
            Self { signer }
        }

        pub fn public_key(&self) -> ConsensusPublicKey {
            self.signer.public_key()
        }

        pub fn validator_id(&self) -> cipherbft_types::ValidatorId {
            self.signer.validator_id()
        }

        fn sign_bytes(&self, bytes: &[u8]) -> ConsensusSignature {
            self.signer.sign(bytes)
        }

        fn verify_bytes(
            &self,
            pk: &ConsensusPublicKey,
            sig: &ConsensusSignature,
            bytes: &[u8],
        ) -> bool {
            if let Ok(crypto_sig) = sig.to_crypto() {
                pk.0.verify(bytes, &crypto_sig)
            } else {
                false
            }
        }
    }

    impl SigningProvider<CipherBftContext> for ConsensusSigningProvider {
        fn sign_vote(&self, vote: ConsensusVote) -> SignedMessage<CipherBftContext, ConsensusVote> {
            let bytes = encode_vote(&vote);
            let signature = self.sign_bytes(&bytes);
            SignedMessage::new(vote, signature)
        }

        fn verify_signed_vote(
            &self,
            vote: &ConsensusVote,
            signature: &Signature<CipherBftContext>,
            public_key: &informalsystems_malachitebft_core_types::PublicKey<CipherBftContext>,
        ) -> bool {
            let bytes = encode_vote(vote);
            self.verify_bytes(public_key, signature, &bytes)
        }

        fn sign_proposal(
            &self,
            proposal: CutProposal,
        ) -> SignedMessage<CipherBftContext, CutProposal> {
            let bytes = encode_proposal(&proposal);
            let signature = self.sign_bytes(&bytes);
            SignedMessage::new(proposal, signature)
        }

        fn verify_signed_proposal(
            &self,
            proposal: &CutProposal,
            signature: &Signature<CipherBftContext>,
            public_key: &informalsystems_malachitebft_core_types::PublicKey<CipherBftContext>,
        ) -> bool {
            let bytes = encode_proposal(proposal);
            self.verify_bytes(public_key, signature, &bytes)
        }

        fn sign_proposal_part(
            &self,
            proposal_part: CutProposalPart,
        ) -> SignedMessage<CipherBftContext, CutProposalPart> {
            let bytes = encode_proposal_part(&proposal_part);
            let signature = self.sign_bytes(&bytes);
            SignedMessage::new(proposal_part, signature)
        }

        fn verify_signed_proposal_part(
            &self,
            proposal_part: &CutProposalPart,
            signature: &Signature<CipherBftContext>,
            public_key: &informalsystems_malachitebft_core_types::PublicKey<CipherBftContext>,
        ) -> bool {
            let bytes = encode_proposal_part(proposal_part);
            self.verify_bytes(public_key, signature, &bytes)
        }

        fn sign_vote_extension(
            &self,
            extension: Vec<u8>,
        ) -> SignedMessage<CipherBftContext, Vec<u8>> {
            let signature = self.sign_bytes(&extension);
            SignedMessage::new(extension, signature)
        }

        fn verify_signed_vote_extension(
            &self,
            extension: &Vec<u8>,
            signature: &Signature<CipherBftContext>,
            public_key: &informalsystems_malachitebft_core_types::PublicKey<CipherBftContext>,
        ) -> bool {
            self.verify_bytes(public_key, signature, extension)
        }
    }
}

#[cfg(feature = "malachite")]
pub use signing_provider::ConsensusSigningProvider;
