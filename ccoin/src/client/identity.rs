use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPublicKey, pkcs1::LineEnding};
use rand::rngs::OsRng;
use std::fmt;
use hex;

use rsa::pkcs1v15::Pkcs1v15Sign;
use sha2::Sha256;

use super::block::{PublicKey, SignatureVal, Sha256DigestVal};

/// Represents an owner with an RSA key pair
pub struct Owner {
    private_key: RsaPrivateKey,
}

pub struct Checker {
    public_key: RsaPublicKey,
}

impl Checker {
    pub fn new(public_key: RsaPublicKey) -> Self {
        Checker { public_key }
    }

    pub fn verify(&self, digest: &Sha256DigestVal, signature: &SignatureVal) -> Result<(), Box<dyn std::error::Error>> {
        self.public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest.0, &signature.0)?;
        Ok(())
    }

    pub fn public_key(&self) -> PublicKey {
        let pem = self.public_key.to_pkcs1_pem(LineEnding::LF).expect("Failed to encode public key to PEM");
        PublicKey(pem)
    }
}

impl Owner {
    /// Creates a new Owner with a generated RSA key pair
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = OsRng;
        
        // Generate a 2048-bit RSA key pair
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        
        Ok(Owner {
            private_key        })
    }

    /// Returns the private key
    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

    pub fn checker(&self) -> Checker {
        Checker::new(self.private_key.to_public_key())
    }

    /// Signs a Vec<u8> input and returns the signature
    pub fn sign(&self, digest: &Sha256DigestVal) -> Result<SignatureVal, Box<dyn std::error::Error>> {
        let signature = self.private_key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest.0)?;
        Ok(SignatureVal(signature))
    }
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Owner {{ public_key: {:?} }}", self.private_key.to_public_key())
    }
}

impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Owner {{ public_key: {:?} }}", self.private_key.to_public_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::block::{AsBytes, HexStr, Sha256DigestVal};

    #[test]
    fn test_sign_and_verify() {
        // Create a new owner
        let owner = Owner::new().expect("Failed to create owner");
        
        // Create some input data
        let input = b"test data".to_vec();
        let digest = Sha256DigestVal::digest_from_data(&input);
        println!("Digest: {}", digest.to_hex_str());
        
        // Sign the input
        let signature = owner.sign(&digest).expect("Failed to sign");
        
        // Verify the signature can be converted to bytes
        let signature_bytes = signature.as_bytes();
        assert!(!signature_bytes.is_empty());
        
        // Verify the signature is a valid string
        assert!(!signature.0.is_empty());
        
        println!("Signature created successfully:\n->{}", signature.to_hex_str());

        // Verify the signature
        owner.checker().verify(&digest, &signature).expect("Failed to verify signature");
        println!("Signature verified successfully");
    }

    #[test]
    fn test_sign_different_inputs() {
        let owner = Owner::new().expect("Failed to create owner");
        
        // Sign different inputs
        let input1 = b"first input".to_vec();
        let input2 = b"second input".to_vec();
        
        let sig1 = owner.sign(&Sha256DigestVal::digest_from_data(&input1)).expect("Failed to sign first input");
        let sig2 = owner.sign(&Sha256DigestVal::digest_from_data(&input2)).expect("Failed to sign second input");
        
        // Signatures should be different for different inputs
        assert_ne!(sig1.0, sig2.0);
        
        println!("Signatures are different as expected");
    }
}