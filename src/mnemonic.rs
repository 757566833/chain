use hmac::{Hmac, Mac};
use k256::{elliptic_curve::sec1::ToEncodedPoint, AffinePoint, SecretKey};
use sha2::Sha512;
use sha3::{Digest, Keccak256};
use std::str::FromStr;
#[derive(Debug)]
pub struct HDNode {
    entryop: Vec<u8>,
    seed: [u8; 64],
    address: Vec<u8>,
    private_key: [u8; 32],
    un_compressed_public_key: Vec<u8>,
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
impl From<std::num::ParseIntError> for CustomError {
    fn from(error: std::num::ParseIntError) -> Self {
        CustomError {
            msg: error.to_string(),
        }
    }
}

const MASTER_SECRET: [u8; 12] = [66, 105, 116, 99, 111, 105, 110, 32, 115, 101, 101, 100];
const HARDENED_BIT: u64 = 0x80000000;
type HmacSha512 = Hmac<Sha512>;
pub fn get_master_by_mnemonic_str(mnemonic_str: &str) -> Result<HDNode, CustomError> {
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
        un_compressed_public_key: un_comporess_affine_point.to_vec(),
        chain_code,
        path: "m".to_string(),
        index: 0,
        depth: 0,
    });
}

pub fn get_children_node_by_path(node: HDNode, path: String) -> Result<HDNode, CustomError> {
    let mut target: HDNode = node;
    let components = path.split("/");
    for component in components {
        if component.contains("m") {
            continue;
        }
        let index;
        if component.contains("'") {
            println!("{}", component.replace("'", ""));
            index = component.replace("'", "").parse::<u64>()? + HARDENED_BIT;
            // index, this.chainCode, this.publicKey, this.privateKey
        } else {
            println!("{}", component);
            index = component.parse::<u64>()?;
        }
        println!("index is {}", index);
        let (il, ir) = ser_i(
            index,
            &target.chain_code,
            &target.public_key,
            &target.private_key,
        )?;
        let n = num_bigint::BigUint::parse_bytes(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".as_bytes(),
            16,
        )
        .unwrap();
        println!("parse n:{}", n.to_string());
        // todo
        let code_bytes = (vec_u8_to_biguint(il)
            + vec_u8_to_biguint(target.private_key.to_vec()) % n)
            .to_bytes_be();
        println!("{}",hex::encode(code_bytes.clone()));
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

        target.address = address;
        target.private_key = private_key;

        target.un_compressed_public_key = un_comporess_affine_point.to_vec();
        target.public_key = compress_public_key;
        let mut chain_code = [0; 32];
        chain_code.copy_from_slice(&ir[0..32]);
        target.chain_code = chain_code;
        // target = HDNode {
        //     entryop: a,
        //     seed: node.seed.clone(),
        //     address: todo!(),
        //     private_key: todo!(),
        //     un_compressed_public_key: todo!(),
        //     public_key: todo!(),
        //     chain_code: todo!(),
        //     path,
        //     index,
        //     depth: todo!(),
        // }
    }
    return Ok(target);
}
pub fn ser_i(
    index: u64,
    chain_code: &[u8; 32],
    public_key: &[u8],
    private_key: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), CustomError> {
    let mut data: Vec<u8> = vec![0; 37];

    if index & HARDENED_BIT != 0 {
        data[1..33].copy_from_slice(private_key);
    } else {
        data[..public_key.len()].copy_from_slice(public_key);
    }
    for i in (0..=24).step_by(8) {
        let byte_index = 33 + (i >> 3);
        data[byte_index] = ((index >> (24 - i)) & 0xFF) as u8;
    }

    let mut mac = HmacSha512::new_from_slice(chain_code)?;
    mac.update(&data);
    let result = mac.finalize();
    let hmac_result = result.into_bytes().to_vec();

    Ok((hmac_result[..32].to_vec(), hmac_result[32..].to_vec()))
}
pub fn vec_u8_to_biguint(vec: Vec<u8>) -> num_bigint::BigUint {
    // Use BigUint::from_bytes_le to create a BigUint from the little-endian byte representation
    num_bigint::BigUint::from_bytes_be(&vec)
}
#[cfg(test)]
mod tests {

    use crate::mnemonic::{get_children_node_by_path, get_master_by_mnemonic_str};

    use super::{ser_i, vec_u8_to_biguint};

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
            "0453f006bb6bcf336fef39d827a245d7bef5555ce0cf0d27363b6cc080f1467b935bc89bdb5c09a4d07437f210a2177c4f263819344ee881bf6578566ec2e6bfcd",
            hex::encode(master_node.un_compressed_public_key)
        );

        assert_eq!(
            "2f42b653f585b3bc8448187dce37eebaf8da2812",
            hex::encode(master_node.address)
        );
        // m2.to_seed("")
    }

    #[test]
    fn test_ser_i() {
        let index: u64 = 2147483692;
        let mut chain_code = [0; 32];
        let chain_code_binding =
            hex::decode("4e76830cd1ded64f0a2f216a7af2b80c7aaa6dbd700693d8cb08cc001dfa458c")
                .unwrap();
        chain_code.copy_from_slice(&chain_code_binding.as_slice()[0..32]);

        let public_key =
            hex::decode("0353f006bb6bcf336fef39d827a245d7bef5555ce0cf0d27363b6cc080f1467b93")
                .unwrap();
        let mut private_key = [0; 32];
        let private_key_binding =
            hex::decode("af69679d4e2dde95b5d585fc4e74b2318612a34e600356d81c6b2b3fd986cd0d")
                .unwrap();
        private_key.copy_from_slice(&private_key_binding.as_slice()[0..32]);
        // let mut chainCode:&[u8; 32] = hex::decode("4e76830cd1ded64f0a2f216a7af2b80c7aaa6dbd700693d8cb08cc001dfa458c").unwrap().as_slice();
        let (il, ir) = ser_i(index, &chain_code, &public_key, &private_key).unwrap();
        assert_eq!(
            vec![
                243, 247, 234, 180, 36, 1, 115, 65, 160, 119, 90, 123, 55, 214, 193, 239, 218, 180,
                105, 245, 243, 200, 152, 191, 70, 91, 134, 126, 218, 138, 71, 216
            ],
            il
        );
        assert_eq!(
            vec![
                23, 207, 169, 120, 7, 85, 101, 29, 102, 142, 93, 82, 242, 186, 0, 122, 71, 68, 42,
                222, 188, 205, 11, 13, 219, 254, 207, 17, 165, 160, 185, 114
            ],
            ir
        );
        // println!("{:?}",b);
    }
    #[test]
    fn test_vec_to_big_num() {
        let res = vec_u8_to_biguint(vec![
            243, 247, 234, 180, 36, 1, 115, 65, 160, 119, 90, 123, 55, 214, 193, 239, 218, 180,
            105, 245, 243, 200, 152, 191, 70, 91, 134, 126, 218, 138, 71, 216,
        ]);
        assert_eq!(
            "110350053295961381469194980161768063875012486900999354933219462641092364224472",
            res.to_string()
        )
    }
    #[test]
    fn test_children_node() {
        let master_node = get_master_by_mnemonic_str(
            "soldier shell mango cricket future true olympic sleep cupboard easy record hero",
        )
        .unwrap();
        let res = get_children_node_by_path(master_node, "m/44'/60'/0'/0/0".to_string()).unwrap();
        println!("{:?}", res);
    }
}
