use hmac::{Hmac, Mac};
use k256::{elliptic_curve::sec1::ToEncodedPoint, AffinePoint, SecretKey};
use sha2::Sha512;
use sha3::{Digest, Keccak256};
use std::str::FromStr;
pub struct HDNode {
    entryop: Vec<u8>,
    seed: [u8; 64],
    address: Vec<u8>,
    private_key: [u8; 32],
    public_key: Vec<u8>,
    chain_code: [u8; 32],
    path: String,
    index: u64,
    depth: u64,
}
#[derive(Debug, Clone)]

pub struct CustomError {
    pub msg: String,
}

impl From<bip39::Error> for CustomError {
    fn from(error: bip39::Error) -> Self {
        CustomError {
            msg: error.to_string(),
        }
    }
}
impl From<sha2::digest::InvalidLength> for CustomError {
    fn from(error: sha2::digest::InvalidLength) -> Self {
        CustomError {
            msg: error.to_string(),
        }
    }
}
impl From<k256::elliptic_curve::Error> for CustomError {
    fn from(error: k256::elliptic_curve::Error) -> Self {
        CustomError {
            msg: error.to_string(),
        }
    }
}

const MASTER_SECRET: [u8; 12] = [66, 105, 116, 99, 111, 105, 110, 32, 115, 101, 101, 100];
pub fn get_master_by_mnemonic_str(mnemonic_str: &str) -> Result<HDNode, CustomError> {
    type HmacSha512 = Hmac<Sha512>;
    let mnemonic: bip39::Mnemonic = bip39::Mnemonic::from_str(mnemonic_str)?;
    let entryop = mnemonic.to_entropy();
    let seed = mnemonic.to_seed("");
    let mut mac = HmacSha512::new_from_slice(&MASTER_SECRET)?;
    mac.update(&seed);
    let result = mac.finalize();
    let code_bytes = result.into_bytes().to_vec();
    let mut private_key = [0; 32];
    private_key.copy_from_slice(&code_bytes[0..32]);
    let mut chain_code = [0; 32];
    chain_code.copy_from_slice(&code_bytes[32..]);
    let secret_key = SecretKey::from_slice(&private_key)?;
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

    let address = address_vec[12..].to_vec();
    return Ok(HDNode {
        entryop,
        seed,
        address,
        private_key,
        public_key: compress_public_key,
        chain_code,
        path: "m".to_string(),
        index: 0,
        depth: 0,
    });
}

#[cfg(test)]
mod tests {
    use crate::mnemonic::get_master_by_mnemonic_str;

    #[test]
    fn test_master_key() {
        let master_node = get_master_by_mnemonic_str(
            "soldier shell mango cricket future true olympic sleep cupboard easy record hero",
        )
        .unwrap();
        assert_eq!(
            "ce98ae1c99b5e9d2a6965935c8bacf35",
            hex::encode(&master_node.entryop)
        );
        assert_eq!("7a17d52d7ad8bb1a280337686867c6a1c27180d6f38b7215299fa92b8e4ee4153eb4aca41db0fd79774bb34a57ecdbbf83db8f23bfa57ff2673f7c05d3d2b172",hex::encode(&master_node.seed));
        assert_eq!(
            "4e76830cd1ded64f0a2f216a7af2b80c7aaa6dbd700693d8cb08cc001dfa458c",
            hex::encode(master_node.chain_code)
        );
        assert_eq!(
            "af69679d4e2dde95b5d585fc4e74b2318612a34e600356d81c6b2b3fd986cd0d",
            hex::encode(master_node.private_key)
        );
        assert_eq!(
            "0353f006bb6bcf336fef39d827a245d7bef5555ce0cf0d27363b6cc080f1467b93",
            hex::encode(master_node.public_key)
        );
        assert_eq!(
            "2f42b653f585b3bc8448187dce37eebaf8da2812",
            hex::encode(master_node.address)
        );
        // m2.to_seed("")
    }
}
