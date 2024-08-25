use bitcoin::Address;
use secp256k1::{PublicKey, Secp256k1, VerifyOnly};

pub trait AddressConverter {
    fn convert(&self, pub_key: PublicKey) -> Address;
}
pub struct TaprootConverter {
    secp: Secp256k1<VerifyOnly>,
}
impl TaprootConverter {
    pub fn new() -> Self {
        TaprootConverter {
            secp: Secp256k1::verification_only(),
        }
    }
}
impl AddressConverter for TaprootConverter {
    fn convert(&self, pub_key: PublicKey) -> Address {
        let xonly_pubkey = pub_key.x_only_public_key();
        Address::p2tr(&self.secp, xonly_pubkey.0, None, bitcoin::Network::Bitcoin)
    }
}

#[cfg(test)]
mod tests {
    use crate::address_converter::{AddressConverter, TaprootConverter};
    use bitcoin::Address;
    use bitcoin::Network::Bitcoin;
    use secp256k1::{PublicKey, Secp256k1, VerifyOnly};
    use std::str::FromStr;

    #[test]
    fn test_convert() {
        let converter = TaprootConverter::new();
        let secp = Secp256k1::verification_only();
        let pub_key = PublicKey::from_str(
            "0261417bc4f3c71a348f22c168925fb0bba297b552734cb8450eb3c7317e75373d",
        )
        .unwrap();
        let taproot_address = converter.convert(pub_key).to_string();
        let xonly_pubkey = &pub_key.x_only_public_key().0;
        let secp = Secp256k1::verification_only();
        let expected_address = Address::p2tr(&secp, xonly_pubkey.clone(), None, Bitcoin);
        assert_eq!(
            taproot_address,
            "bc1py467s8cw4252m63pn9efr4fupe4rfwmv9atv5mzagmjw3kt4teaqlx3wnq"
        );
    }
}
