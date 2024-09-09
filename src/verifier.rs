use base64::engine::GeneralPurpose;
use base64::{engine::general_purpose, Engine as _};
use bitcoin::sign_message::signed_msg_hash;
use secp256k1::ecdsa::{RecoveryId, Signature};
use secp256k1::{Error, Message, PublicKey, Secp256k1, VerifyOnly};
use std::str::FromStr;

pub trait Verifier {
    fn verify(&self, message: &str, signature: &str, public_key: &str) -> bool;
    fn verify_bip322_only_message(
        &self,
        message: &str,
        signature: &str,
    ) -> Result<PublicKey, Error>;
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

    fn verify_bip322_only_message(
        &self,
        message: &str,
        signature: &str,
    ) -> Result<PublicKey, Error> {
        let base_64_encoded = self
            .base_64_decoder
            .decode(signature.as_bytes())
            .map_err(|_| Error::InvalidSignature)?;
        for recovery_id in 0..4 {
            println!("{}", recovery_id);
            let rec_id = RecoveryId::from_i32(recovery_id).expect("Invalid recovery ID");
            let recoverable_sig = secp256k1::ecdsa::RecoverableSignature::from_compact(
                &base_64_encoded.clone()[2..],
                rec_id,
            );
            if recoverable_sig.is_ok() {
                let recoverable_sig = recoverable_sig.unwrap();
                let magic_hash = signed_msg_hash(message);
                let message = Message::from_digest_slice((&magic_hash).as_ref()).unwrap();
                let recovered_pubkey = self.secp.recover_ecdsa(&message, &recoverable_sig);
                if recovered_pubkey.is_err() {
                    continue;
                }
                let verified = self
                    .secp
                    .verify_ecdsa(
                        &message,
                        &recoverable_sig.to_standard(),
                        &recovered_pubkey.unwrap(),
                    )
                    .is_ok();
                if verified {
                    println!("{}", verified);
                    // get taproot address
                    let xonly_pubkey = &recovered_pubkey.unwrap().x_only_public_key().0;
                    let secp = secp256k1::Secp256k1::verification_only();
                    let taproot_address = bitcoin::Address::p2tr(
                        &secp,
                        xonly_pubkey.clone(),
                        None,
                        bitcoin::Network::Bitcoin,
                    )
                    .to_string();
                    println!("{}", taproot_address);
                }
            }
        }
        Err(Error::InvalidSignature)
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
        let message = "hello world~";
        let signature = "AUCeEKDgQ6gaMHjAWsO5NLd/eo3aNJuyIz8sQS1G7L8jmhEcKYnn7/e4W9l1KDpbe7+d7CRNhhZVVADUM5x4Ykut";
        let pubk_key = verifier
            .verify_bip322_only_message(message, signature)
            .unwrap();
        let xonly_pubkey = &pubk_key.x_only_public_key().0;
        let secp = secp256k1::Secp256k1::verification_only();
        let taproot_address =
            bitcoin::Address::p2tr(&secp, xonly_pubkey.clone(), None, bitcoin::Network::Bitcoin)
                .to_string();
        assert_eq!(
            taproot_address,
            "bc1p7dpnhaywwpk35qac2re3q3wfps8hmwcuffxjqemdqzq4r9ls23ss9asvzd"
        );
    }
}
