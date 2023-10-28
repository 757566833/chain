use bip39::rand::Rng;
use k256::{elliptic_curve::sec1::ToEncodedPoint, AffinePoint, SecretKey};
use sha3::{Digest, Keccak256};

use crate::CustomError;
pub fn generate_private_key() -> [u8; 32] {
    let mut rng = bip39::rand::thread_rng();
    let mut private_key: [u8; 32] = [0; 32];
    rng.fill(&mut private_key);

    return private_key;
}
#[derive(Clone, Debug)]
pub struct Wallet {
    private_key: [u8; 32],
    un_compressed_public_key: Vec<u8>,
    public_key: Vec<u8>,
    address: [u8; 20],
}
pub fn private_key_to_wallet(private_key: &[u8; 32]) -> Result<Wallet, CustomError> {
    let secret_key = SecretKey::from_slice(private_key)?;
    // 压缩公钥匙 hex
    let compress_public_key = secret_key.public_key().to_sec1_bytes().to_vec();

    let affine_point = AffinePoint::from(secret_key.public_key());
    // 非压缩公钥
    let un_comporess_affine_point = affine_point.to_encoded_point(false).to_bytes();
    // println!("{}", hex::encode(un_comporess_affine_point));

    let mut hasher = Keccak256::new();
    // 去掉开头的 02、03、04
    hasher.update(&un_comporess_affine_point[1..]);
    let address_vec: Vec<u8> = hasher.finalize().to_vec();
    let mut address = [0; 20];
    address.copy_from_slice(&address_vec[12..]);
    return Ok(Wallet {
        private_key: private_key.clone(),
        un_compressed_public_key: un_comporess_affine_point.to_vec(),
        public_key: compress_public_key,
        address,
    });
}

#[cfg(test)]
mod tests {
    use super::private_key_to_wallet;

    #[test]
    fn test_generate_private_key() {}

    #[test]
    fn test_private_key_to_wallet() {
        let private =
            hex::decode("43ddf386c3a0427fb04d4fef4c407f91fa57a087c90c154c218a6d926ec7d9df")
                .unwrap();
        let mut private_key: [u8; 32] = [0; 32];
        private_key.copy_from_slice(&private[0..32]);
        let wallet = private_key_to_wallet(&private_key).unwrap();
        assert_eq!(
            "43ddf386c3a0427fb04d4fef4c407f91fa57a087c90c154c218a6d926ec7d9df",
            hex::encode(wallet.private_key)
        );
        assert_eq!("04dbed8dcd18aab3ca0b72011294db2464e7a50c3e337a941aeb4a465539eaca9f69374b47c8bfd82a503c2952d22b92256a5a0d90c88fd394137085a8279b8a0a",hex::encode( wallet.un_compressed_public_key));
        assert_eq!(
            "02dbed8dcd18aab3ca0b72011294db2464e7a50c3e337a941aeb4a465539eaca9f",
            hex::encode(wallet.public_key)
        );
        assert_eq!(
            "9a052d8a01a7b0995a472481cff673084a8a81bc",
            hex::encode(wallet.address)
        );
    }
}
