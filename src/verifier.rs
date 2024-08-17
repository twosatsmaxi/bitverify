use std::str::FromStr;

use base64::engine::GeneralPurpose;
use base64::{engine::general_purpose, Engine as _};
use bitcoin::sign_message::signed_msg_hash;
use secp256k1::ecdsa::RecoveryId;
use secp256k1::{Message, PublicKey, Secp256k1, VerifyOnly};

pub trait Verifier {
    fn verify(&self, message: &str, signature: &str, public_key: &str) -> bool;
    fn verify_only_message(&self, message: &str, signature: &str) -> Result<PublicKey, ()>;
}

pub struct ECDSAVerifier {
    secp: Secp256k1<VerifyOnly>,
    base_64_decoder: GeneralPurpose,
}
impl ECDSAVerifier {
    pub(crate) fn new() -> Self {
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

    fn verify_only_message(&self, message: &str, signature: &str) -> Result<PublicKey, ()> {
        let compact_sig = self.base_64_decoder.decode(signature.as_bytes()).unwrap();
        let recovery_id = RecoveryId::from_i32(((compact_sig[0] - 27) % 4) as i32).unwrap();
        let recoverable_sig =
            secp256k1::ecdsa::RecoverableSignature::from_compact(&compact_sig[1..], recovery_id)
                .unwrap();
        let magic_hash = signed_msg_hash(message);
        let message = Message::from_digest_slice((&magic_hash).as_ref()).unwrap();
        let recovered_pubkey = self.secp.recover_ecdsa(&message, &recoverable_sig).unwrap();
        let result = self
            .secp
            .verify_ecdsa(&message, &recoverable_sig.to_standard(), &recovered_pubkey)
            .map(|_| recovered_pubkey);
        result.map_err(|_| ())
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
}
