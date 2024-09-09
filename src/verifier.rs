use base64::engine::GeneralPurpose;
use base64::{engine::general_purpose, Engine as _};
use bitcoin::sign_message::signed_msg_hash;
use secp256k1::ecdsa::{RecoveryId, Signature};
use secp256k1::{Error, Message, PublicKey, Secp256k1, VerifyOnly};
use std::str::FromStr;

pub trait Verifier {
    fn verify(&self, message: &str, signature: &str, public_key: &str) -> bool;
    fn verify_bip322_only_message(&self, message: &str, signature: &str);
    fn verify_only_message(&self, message: &str, signature: &str) -> Result<PublicKey, Error>;
}

pub struct ECDSAVerifier {
    secp: Secp256k1<VerifyOnly>,
    base_64_decoder: GeneralPurpose,
}
impl ECDSAVerifier {
    pub fn new() -> Self {
        ECDSAVerifier {
            secp: Secp256k1::verification_only(),
            base_64_decoder: general_purpose::STANDARD,
        }
    }
}
impl Verifier for ECDSAVerifier {
    fn verify(&self, message: &str, signature: &str, public_key: &str) -> bool {
        let provided_pubkey = match PublicKey::from_str(public_key) {
            Ok(pubkey) => pubkey,
            Err(_) => return false,
        };
        self.verify_only_message(message, signature)
            .and_then(|recovered_pubkey| Ok(recovered_pubkey == provided_pubkey))
            .unwrap_or(false)
    }

    fn verify_bip322_only_message(&self, message: &str, signature: &str) {
        let base_64_encoded = self
            .base_64_decoder
            .decode(signature.as_bytes())
            .map_err(|_| Error::InvalidSignature)
            .unwrap();
        let signature = Signature::from_der(&signature.as_bytes());
        if signature.is_err() {
            let err = signature.unwrap_err();
            println!("Error: {:?}", err);
            return;
        }
        let signature = signature.unwrap();
        // this is the signature in DER format with 66 bytes, get recoverable signature from it
        for recovery_id in 0..4 {
            let rec_id = RecoveryId::from_i32(recovery_id).expect("Invalid recovery ID");
            let recoverable_sig = secp256k1::ecdsa::RecoverableSignature::from_compact(
                &base_64_encoded.clone()[1..],
                rec_id,
            );
            if recoverable_sig.is_err() {
                let recoverable_sig = recoverable_sig.unwrap();
                let magic_hash = signed_msg_hash(message);
                let message = Message::from_digest_slice((&magic_hash).as_ref()).unwrap();
                let recovered_pubkey = self.secp.recover_ecdsa(&message, &recoverable_sig).unwrap();
                let verified = self
                    .secp
                    .verify_ecdsa(&message, &recoverable_sig.to_standard(), &recovered_pubkey)
                    .is_ok();
                if verified {
                    return;
                }
            }
        }
    }

    fn verify_only_message(&self, message: &str, signature: &str) -> Result<PublicKey, Error> {
        let compact_sig = self
            .base_64_decoder
            .decode(signature.as_bytes())
            .map_err(|_| Error::InvalidSignature)?;
        let recovery_id = RecoveryId::from_i32(((compact_sig[0] - 27) % 4) as i32)?;
        let recoverable_sig =
            secp256k1::ecdsa::RecoverableSignature::from_compact(&compact_sig[1..], recovery_id)?;
        let magic_hash = signed_msg_hash(message);
        let message = Message::from_digest_slice((&magic_hash).as_ref())?;
        let recovered_pubkey = self.secp.recover_ecdsa(&message, &recoverable_sig)?;
        self.secp
            .verify_ecdsa(&message, &recoverable_sig.to_standard(), &recovered_pubkey)
            .map(|_| recovered_pubkey)
    }
}
#[cfg(test)]
mod tests {
    use crate::verifier::Verifier;

    #[test]
    fn test_ecdsa_verify() {
        let verifier = super::ECDSAVerifier::new();
        let pub_key = "0261417bc4f3c71a348f22c168925fb0bba297b552734cb8450eb3c7317e75373d";
        let message = "hello world~";
        let signature = "IB5disFKMA+6p6fhM2zO6WLq5hFdYLjEwUQhCV4BoKRaTouIacrE0QB6CeiQNaMimtW+3OoB8/XKMe9w0R3sHSA=";
        assert!(verifier.verify(message, signature, pub_key));
    }
    #[test]
    fn test_ecdsa_verify_only_message() {
        let verifier = super::ECDSAVerifier::new();
        let message = "hello world~";
        let signature = "IB5disFKMA+6p6fhM2zO6WLq5hFdYLjEwUQhCV4BoKRaTouIacrE0QB6CeiQNaMimtW+3OoB8/XKMe9w0R3sHSA=";
        let verified_pubkey = verifier.verify_only_message(message, signature).unwrap();
        let xonly_pubkey = &verified_pubkey.x_only_public_key().0;
        let secp = secp256k1::Secp256k1::verification_only();
        let taproot_address =
            bitcoin::Address::p2tr(&secp, xonly_pubkey.clone(), None, bitcoin::Network::Bitcoin)
                .to_string();
        assert_eq!(
            taproot_address,
            "bc1py467s8cw4252m63pn9efr4fupe4rfwmv9atv5mzagmjw3kt4teaqlx3wnq"
        );
    }

    #[test]
    fn test_bip322_signed_message() {
        let verifier = super::ECDSAVerifier::new();
        let message = "hello";
        let signature = "AUDKZpBI+I93qGPv9qmtr1h8W0FGnv1SFdWNBskAVHlPnI0jzCl7AaCnlDgqS6cCiRqCRr6eolK2iGl0iiw3Pe01";
        verifier.verify_bip322_only_message(message, signature)
    }
}
