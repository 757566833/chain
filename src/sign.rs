use std::str::FromStr;

use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use rlp::RlpStream;
use sha2::digest::core_api::CoreWrapper;
use sha3::{Digest, Keccak256, Keccak256Core};

use crate::error::ResponseError;

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

fn get_sign_key_by_vec(private: &[u8]) -> Result<SigningKey, ResponseError> {
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
pub fn sign(private: &[u8], request: SignTransactionRequest) -> Result<Vec<u8>, ResponseError> {
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

fn keccak256(data: &Vec<u8>) -> CoreWrapper<Keccak256Core> {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    return hasher;
}
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use sha3::Digest;

    use crate::utils::sign::{
        keccak256, rlp_encode, sign, SignEip1559transaction, SignLegacyTransaction,
        SignTransactionRequest,
    };

    use super::big_num_to_vec;

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
        assert_eq!("3267e16968c2679c8132402277ef8296bc134e291bae05001eab6fbba61c016e",hex::encode(h))

      
    }
}
