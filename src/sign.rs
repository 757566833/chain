use std::str::FromStr;

use k256::{ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey}, elliptic_curve};
use rlp::RlpStream;
use sha2::digest::core_api::CoreWrapper;
use sha3::{Digest, Keccak256, Keccak256Core};
use hmac::digest::typenum::Unsigned;

#[derive(Debug)]
pub struct Error {
    pub message: String,
}

/**
 * 私钥生成签名对象失败
 */
impl From<k256::ecdsa::Error> for Error {
    fn from(error: k256::ecdsa::Error) -> Self {
        Error {
            message: error.to_string(),
        }
    }
}

#[derive(Debug)]
pub struct SignLegacyTransaction {
    pub chain_id: num_bigint::BigUint,
    pub to: Vec<u8>,
    pub gas_price: num_bigint::BigUint,
    pub value: num_bigint::BigUint,
    pub nonce: num_bigint::BigUint,
    pub gas_limit: num_bigint::BigUint,
}
#[derive(Debug)]
pub struct SignEip1559transaction {
    pub chain_id: num_bigint::BigUint,
    pub to: Vec<u8>,
    pub max_fee_per_gas: num_bigint::BigUint,
    pub max_priority_fee_per_gas: num_bigint::BigUint,
    pub value: num_bigint::BigUint,
    pub nonce: num_bigint::BigUint,
    pub gas_limit: num_bigint::BigUint,
}
pub enum SignTransactionRequest {
    Legacy(SignLegacyTransaction),
    Eip1559(SignEip1559transaction),
}

pub fn big_num_to_vec(bg: &num_bigint::BigUint) -> Vec<u8> {
    return strip_zeros(&bg.to_str_radix(16));
}
fn strip_zeros(value: &str) -> Vec<u8> {
    let mut hex = value.to_string();
    if hex.len() % 2 != 0 {
        hex = format!("0{}", hex)
    }

    let mut result = hex::decode(hex).unwrap_or(Vec::new());

    if result.is_empty() {
        return result;
    }

    // Find the first non-zero entry
    let mut start = 0;
    while start < result.len() && result[start] == 0 {
        start += 1;
    }

    // If we started with zeros, strip them
    if start > 0 {
        result.drain(0..start);
    }

    result
}

pub fn rlp_encode(request: &SignTransactionRequest) -> Vec<u8> {
    let mut rlp_stream = RlpStream::new();
    match request {
        SignTransactionRequest::Legacy(legacy_transaction) => {
            rlp_stream.begin_list(9);
            rlp_stream.append(&big_num_to_vec(&legacy_transaction.nonce));
            rlp_stream.append(&big_num_to_vec(&legacy_transaction.gas_price));
            rlp_stream.append(&big_num_to_vec(&legacy_transaction.gas_limit));
            rlp_stream.append(&legacy_transaction.to);
            rlp_stream.append(&big_num_to_vec(&legacy_transaction.value));
            rlp_stream.append_empty_data();
            rlp_stream.append(&big_num_to_vec(&legacy_transaction.chain_id));
            rlp_stream.append_empty_data();
            rlp_stream.append_empty_data();
            let rlp_encoded = rlp_stream.as_raw();

            return rlp_encoded.to_owned();
        }
        SignTransactionRequest::Eip1559(eip1559_transaction) => {
            rlp_stream.begin_list(9);
            rlp_stream.append(&big_num_to_vec(&eip1559_transaction.chain_id));
            rlp_stream.append(&big_num_to_vec(&eip1559_transaction.nonce));
            rlp_stream.append(&big_num_to_vec(
                &eip1559_transaction.max_priority_fee_per_gas,
            ));
            rlp_stream.append(&big_num_to_vec(&eip1559_transaction.max_fee_per_gas));
            rlp_stream.append(&big_num_to_vec(&eip1559_transaction.gas_limit));
            rlp_stream.append(&eip1559_transaction.to);
            rlp_stream.append(&big_num_to_vec(&eip1559_transaction.value));
            // rlp_stream.append(&[].to_vec());
            rlp_stream.append_empty_data();
            let e: Vec<u8> = vec![];
            rlp_stream.append_list(&e);
            // Get the RLP-encoded bytes
            let rlp_encoded = rlp_stream.as_raw();
            let mut resut = rlp_encoded.to_owned();
            resut.splice(..0, vec![0x02]);

            return resut;
        }
    }
}

fn get_sign_key_by_vec(private: &[u8]) -> Result<SigningKey, Error> {
    let mut private_key_array: [u8; 32] = [0; 32];
    private_key_array.copy_from_slice(private);
    let result = k256::ecdsa::SigningKey::from_slice(&private_key_array)?;
    return Ok(result);
}
fn rlp_encode_full(
    request: &SignTransactionRequest,
    signature: Signature,
    id: RecoveryId,
) -> Vec<u8> {
    match request {
        SignTransactionRequest::Legacy(legacy_transaction) => {
            let mut rlp_stream = RlpStream::new();
            rlp_stream.begin_list(9);

            rlp_stream.append(&big_num_to_vec(&legacy_transaction.nonce));
            rlp_stream.append(&big_num_to_vec(&legacy_transaction.gas_price));
            rlp_stream.append(&big_num_to_vec(&legacy_transaction.gas_limit));
            rlp_stream.append(&legacy_transaction.to);
            rlp_stream.append(&big_num_to_vec(&legacy_transaction.value));
            rlp_stream.append_empty_data();

            let next_chain_id = legacy_transaction.chain_id.clone()
                * num_bigint::BigUint::from_str("2").unwrap()
                + num_bigint::BigUint::from_str("35").unwrap()
                + num_bigint::BigUint::from(id.to_byte());
            rlp_stream.append(&big_num_to_vec(&next_chain_id));

            rlp_stream.append(&signature.r().to_bytes().to_vec());
            rlp_stream.append(&signature.s().to_bytes().to_vec());
            let rlp_encoded = rlp_stream.as_raw();

            return rlp_encoded.to_owned();
        }
        SignTransactionRequest::Eip1559(eip1559_transaction) => {
            let mut rlp_stream = RlpStream::new();
            rlp_stream.begin_list(12);
            rlp_stream.append(&big_num_to_vec(&eip1559_transaction.chain_id));
            rlp_stream.append(&big_num_to_vec(&eip1559_transaction.nonce));
            rlp_stream.append(&big_num_to_vec(
                &eip1559_transaction.max_priority_fee_per_gas,
            ));
            rlp_stream.append(&big_num_to_vec(&eip1559_transaction.max_fee_per_gas));
            rlp_stream.append(&big_num_to_vec(&eip1559_transaction.gas_limit));
            rlp_stream.append(&eip1559_transaction.to);
            rlp_stream.append(&big_num_to_vec(&eip1559_transaction.value));
            // rlp_stream.append(&[].to_vec());
            rlp_stream.append_empty_data();
            let e: Vec<u8> = vec![];
            rlp_stream.append_list(&e);
            // Get the RLP-encoded bytes
            rlp_stream.append(&big_num_to_vec(&num_bigint::BigUint::from(id.to_byte())));
            rlp_stream.append(&signature.r().to_bytes().to_vec());
            rlp_stream.append(&signature.s().to_bytes().to_vec());
            let rlp_encoded = rlp_stream.as_raw();
            let mut resut = rlp_encoded.to_owned();
            resut.splice(..0, vec![0x02]);

            return resut;
        }
    }
}
pub fn sign(private: &[u8], request: SignTransactionRequest) -> Result<Vec<u8>, Error> {
    let rlp = rlp_encode(&request);
    let hasher = keccak256(&rlp);

    let sign = get_sign_key_by_vec(private)?;

    // let hash = hasher.clone().finalize();
    // Digest::

    // let (result, id) = sign.sign_digest(hash).unwrap();

    // id is 0
    let (signature, id) = sign.sign_digest_recoverable(hasher)?;

    // id is 0
    // let (result, id) = sign.sign_prehash_recoverable(&hash).unwrap();

    // id is 1
    // let (result, id) = sign.sign_recoverable(&hash).unwrap();

    // id is 1
    // let (result, id) = sign.try_sign(&hash).unwrap();
    let full = rlp_encode_full(&request, signature, id);
    return Ok(full);
}
pub struct S {
    pub signature: Signature,
    pub i: RecoveryId,
}
pub fn sign_message(private: &[u8], message: String) -> Result<S, Error> {
    let bytes: Vec<u8> = message.into_bytes();
    let digest = Keccak256::new_with_prefix(bytes);

    let sign = get_sign_key_by_vec(private)?;

    // let hash = hasher.clone().finalize();
    // Digest::

    // let (result, id) = sign.sign_digest(hash).unwrap();

    // id is 0
    let (signature, id) = sign.sign_digest_recoverable(digest)?;
    // signature: Signature,
    // id: RecoveryId,
    // id is 0
    // let (result, id) = sign.sign_prehash_recoverable(&hash).unwrap();

    // id is 1
    // let (result, id) = sign.sign_recoverable(&hash).unwrap();

    // id is 1
    // let (result, id) = sign.try_sign(&hash).unwrap();
    return Ok(S { signature, i: id });
}
pub fn verify_digest_recoverable_signature(s: S, message: String) -> Result<VerifyingKey, Error> {
    let bytes: Vec<u8> = message.into_bytes();
    let digest = Keccak256::new_with_prefix(bytes);
    let signature = s.signature;
    let id = s.i;
    let recovered_key = VerifyingKey::recover_from_digest(digest, &signature, id)?;
    return Ok(recovered_key);
}
pub fn verify_recoverable_signature(s: S, message: String) -> Result<VerifyingKey, Error> {

    let signature = s.signature;
    let id = s.i;
    let recovered_key = VerifyingKey::recover_from_msg(message.as_bytes(), &signature, id)?;
    return Ok(recovered_key);
}
// pub fn verify_signature(public :String,signature: Signature,message: String) -> Result<VerifyingKey, Error> {
//     let bytes: Vec<u8> = message.into_bytes();
//     println!("{:?}",bytes);
//     let digest = Keccak256::new_with_prefix(bytes);
//     let signature = s.signature;
//     let id = s.i;
//     let recovered_key = VerifyingKey::recover_from_digest(digest, &signature, id)?;
//     return Ok(recovered_key);
// }
pub fn keccak256(data: &Vec<u8>) -> CoreWrapper<Keccak256Core> {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    return hasher;
}
pub fn element_from_padded_slice<C: elliptic_curve::Curve>(
    data: &[u8],
) -> elliptic_curve::FieldBytes<C> {
    let point_len = C::FieldBytesSize::USIZE;
    if data.len() >= point_len {
        let offset = data.len() - point_len;
        for v in data.iter().take(offset) {
            assert_eq!(*v, 0, "EcdsaVerifier: point too large");
        }
        elliptic_curve::FieldBytes::<C>::clone_from_slice(&data[offset..])
    } else {
        let iter = core::iter::repeat(0)
            .take(point_len - data.len())
            .chain(data.iter().cloned());
        elliptic_curve::FieldBytes::<C>::from_exact_iter(iter).unwrap()
    }
}
#[cfg(test)]
mod tests {
   
    use std::str::FromStr;

    use k256::{ecdsa::{RecoveryId, Signature, VerifyingKey}, pkcs8::DecodePublicKey, Secp256k1, EncodedPoint};
    use sha3::Digest;
    use k256::ecdsa::signature::Verifier;

    use crate::{
        key::private_key_to_wallet,
        sign::{
            keccak256, rlp_encode, sign, SignEip1559transaction, SignLegacyTransaction,
            SignTransactionRequest, S,
        },
    };

    use super::{big_num_to_vec, sign_message, verify_digest_recoverable_signature, element_from_padded_slice};

    #[test]
    fn test_big_num_to_vec() {
        let bg = num_bigint::BigUint::from_str("79653").unwrap();
        let vec = big_num_to_vec(&bg);
        assert_eq!(vec![1, 55, 37], vec);
    }

    #[test]
    fn test_rlp() {
        let chain_id = num_bigint::BigUint::from_str("79653").unwrap();
        let nonce = num_bigint::BigUint::from_str("10").unwrap();
        let max_priority_fee_per_gas = num_bigint::BigUint::from_str("1000000000").unwrap();
        let max_fee_per_gas = num_bigint::BigUint::from_str("1000000007").unwrap();
        let gas_limit = num_bigint::BigUint::from_str("21000").unwrap();
        let to = hex::decode("A303721F08B85af1Fdf7C57152b9e31D4BCa397B").unwrap();
        let value = num_bigint::BigUint::from_str("5000000000000000000").unwrap();

        let gas_price = num_bigint::BigUint::from_str("1000000007").unwrap();

        let rlp_encoded = rlp_encode(&SignTransactionRequest::Eip1559(SignEip1559transaction {
            chain_id: chain_id.clone(),
            to: to.clone(),
            nonce: nonce.clone(),
            gas_limit: gas_limit.clone(),
            max_fee_per_gas: max_fee_per_gas.clone(),
            max_priority_fee_per_gas: max_priority_fee_per_gas.clone(),
            value: value.clone(),
        }));
        assert_eq!("02f2830137250a843b9aca00843b9aca0782520894a303721f08b85af1fdf7c57152b9e31d4bca397b884563918244f4000080c0",hex::encode(rlp_encoded));

        let rlp_encoded = rlp_encode(&SignTransactionRequest::Legacy(SignLegacyTransaction {
            chain_id,
            to,
            nonce,
            gas_limit,
            gas_price,
            value,
        }));
        assert_eq!("ee0a843b9aca0782520894a303721f08b85af1fdf7c57152b9e31d4bca397b884563918244f4000080830137258080",hex::encode(rlp_encoded))
    }

    #[test]
    fn test_keccak256() {
        let origin = vec![
            2, 242, 131, 1, 55, 37, 10, 132, 59, 154, 202, 0, 132, 59, 154, 202, 7, 130, 82, 8,
            148, 163, 3, 114, 31, 8, 184, 90, 241, 253, 247, 197, 113, 82, 185, 227, 29, 75, 202,
            57, 123, 136, 69, 99, 145, 130, 68, 244, 0, 0, 128, 192,
        ];
        let traget = keccak256(&origin);
        let address_1559_vec: Vec<u8> = traget.finalize().to_vec();
        assert_eq!(
            "3958b1ac401d6914ff218f44e414d6fb36b9dfc36028764597e3aacf7a1b13fc",
            hex::encode(address_1559_vec)
        );
    }

    #[test]
    fn test_secp256k1() {
        let chain_id = num_bigint::BigUint::from_str("79653").unwrap();
        let nonce = num_bigint::BigUint::from_str("10").unwrap();
        let max_priority_fee_per_gas = num_bigint::BigUint::from_str("1000000000").unwrap();
        let max_fee_per_gas = num_bigint::BigUint::from_str("1000000007").unwrap();
        let gas_limit = num_bigint::BigUint::from_str("21000").unwrap();
        let to = hex::decode("A303721F08B85af1Fdf7C57152b9e31D4BCa397B").unwrap();
        let value = num_bigint::BigUint::from_str("5000000000000000000").unwrap();

        let gas_price = num_bigint::BigUint::from_str("1000000007").unwrap();

        let result = sign(
            hex::decode(
                "f40bb21badf540a80c9cdadf38706408759786b6f991cfbc93556ac95baaf041".to_string(),
            )
            .unwrap()
            .as_slice(),
            SignTransactionRequest::Eip1559(SignEip1559transaction {
                chain_id: chain_id.clone(),
                to: to.clone(),
                nonce: nonce.clone(),
                gas_limit: gas_limit.clone(),
                max_fee_per_gas: max_fee_per_gas.clone(),
                max_priority_fee_per_gas: max_priority_fee_per_gas.clone(),
                value: value.clone(),
            }),
        )
        .unwrap();

        assert_eq!(
                "02f875830137250a843b9aca00843b9aca0782520894a303721f08b85af1fdf7c57152b9e31d4bca397b884563918244f4000080c080a0c5f931b3ca665cebfe376369d032fcca3f182941cd62c3df9adc57efdc69f9cfa0462081777809827579fc8f013240dfa20820e437a2e13baa07367827d6c660af",hex::encode(result)
            );

        let result = sign(
            hex::decode(
                "f40bb21badf540a80c9cdadf38706408759786b6f991cfbc93556ac95baaf041".to_string(),
            )
            .unwrap()
            .as_slice(),
            SignTransactionRequest::Legacy(SignLegacyTransaction {
                chain_id: chain_id.clone(),
                to: to.clone(),
                nonce: nonce.clone(),
                gas_limit: gas_limit.clone(),
                gas_price: gas_price.clone(),
                value: value.clone(),
            }),
        )
        .unwrap();

        assert_eq!(
                    "f86e0a843b9aca0782520894a303721f08b85af1fdf7c57152b9e31d4bca397b884563918244f400008083026e6da08deb712ee29375222cdfa3acabb2da5fc77d73896cd2d8213ff76a287eb16d88a07b112fe2be3aa993d1b0a75947209d1c233e93989923b609edc5c3e5fcc9f067",hex::encode(result)
                )
    }
    #[test]
    fn test_transaction_tx() {
        let chain_id = num_bigint::BigUint::from_str("79653").unwrap();
        let nonce = num_bigint::BigUint::from_str("1").unwrap();
        let max_priority_fee_per_gas = num_bigint::BigUint::from_str("1500000000").unwrap();
        let max_fee_per_gas = num_bigint::BigUint::from_str("1500000008").unwrap();
        let gas_limit = num_bigint::BigUint::from_str("21000").unwrap();
        let to = hex::decode("7be15c62e64458fb5e5ee32fed82692abf427d2c").unwrap();
        let value = num_bigint::BigUint::from_str("3000000000000000000").unwrap();

        let result = sign(
            hex::decode(
                "f40bb21badf540a80c9cdadf38706408759786b6f991cfbc93556ac95baaf041".to_string(),
            )
            .unwrap()
            .as_slice(),
            SignTransactionRequest::Eip1559(SignEip1559transaction {
                chain_id: chain_id.clone(),
                to: to.clone(),
                nonce: nonce.clone(),
                gas_limit: gas_limit.clone(),
                max_fee_per_gas: max_fee_per_gas.clone(),
                max_priority_fee_per_gas: max_priority_fee_per_gas.clone(),
                value: value.clone(),
            }),
        )
        .unwrap();

        let hash = keccak256(&result);
        let h = hash.finalize();
        assert_eq!(
            "3267e16968c2679c8132402277ef8296bc134e291bae05001eab6fbba61c016e",
            hex::encode(h)
        )
    }
    #[test]
    fn test_sign_message() {
        let res = sign_message(
            hex::decode(
                "f40bb21badf540a80c9cdadf38706408759786b6f991cfbc93556ac95baaf041".to_string(),
            )
            .unwrap()
            .as_slice(),
            "0".to_string(),
        )
        .unwrap();
        println!("{:?}", hex::encode(res.signature.r().to_bytes().to_vec()));
        println!("{:?}", hex::encode(res.signature.s().to_bytes().to_vec()));
        println!("{:?}", res.signature);
    }
    #[test]
    fn test_verify_digest_recoverable_signature() {
        let res = sign_message(
            hex::decode(
                "f40bb21badf540a80c9cdadf38706408759786b6f991cfbc93556ac95baaf041".to_string(),
            )
            .unwrap()
            .as_slice(),
            "0".to_string(),
        )
        .unwrap();
        let verify = verify_digest_recoverable_signature(res, "0".to_string()).unwrap();
        let un_comporess_affine_point = verify.to_encoded_point(false).to_bytes();

        let private =
            hex::decode("f40bb21badf540a80c9cdadf38706408759786b6f991cfbc93556ac95baaf041")
                .unwrap();
        let mut private_key: [u8; 32] = [0; 32];
        private_key.copy_from_slice(&private[0..32]);
        let wallet = private_key_to_wallet(&private_key).unwrap();

        assert_eq!(
            un_comporess_affine_point.to_vec(),
            wallet.un_compressed_public_key
        )
    }
    #[test]
    fn test_verify_signature() {
        let public_key_hex = "04af145963bb80bf09abf1c3be6b62929d7af388b92b588868a984833d9dabd5030eadadeedf95ab14e53b00ce1b2dcc2ef6289f9b7c12ef830f07fef5999deaad";
        let public_key_bytes = hex::decode(public_key_hex).expect("Invalid hex");
        let public_key = VerifyingKey::from_encoded_point(&EncodedPoint::from_bytes(&public_key_bytes).expect("Invalid public key")).expect("Invalid public key");
    
        // 从hex字符串解析签名
        let signature_hex = "2344a80ac25a9671859f2181ed39f28b55a43c513ab9de0f08b68c44e650a293474c014173727cb25f39c978cc7bbb5d99caf0527e6eec5214a58de5246461f3";
        let signature_bytes = hex::decode(signature_hex).expect("Invalid hex");
        let byte_slice: &[u8] = &signature_bytes;
        let signature = Signature::from_bytes(byte_slice.into()).expect("Invalid signature");
    
        // 准备要签名的消息
        let context = "test001";
        let message = context.as_bytes();
    
        // 验证签名
        let is_valid = public_key.verify(message, &signature).is_ok();
    
        // 打印验证结果
        if is_valid {
            println!("Signature is valid!");
        } else {
            println!("Signature is invalid!");
        }

    }
  
}
