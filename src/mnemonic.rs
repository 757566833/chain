#[cfg(test)]
mod tests {
    use hmac::{Hmac, Mac};
    use k256::{elliptic_curve::sec1::ToEncodedPoint, AffinePoint, SecretKey};
    use sha2::Sha512;
    use sha3::{Digest, Keccak256};
    use std::str::FromStr;
    #[test]
    fn test_master_key() {
        // "Bitcoin seed"
        let master_secret = [66, 105, 116, 99, 111, 105, 110, 32, 115, 101, 101, 100];
        type HmacSha512 = Hmac<Sha512>;
        let mnemonic = bip39::Mnemonic::from_str(
            "soldier shell mango cricket future true olympic sleep cupboard easy record hero",
        )
        .unwrap();
        // bip39::Mnemonic::from_entropy(entropy)
        let entryop = mnemonic.to_entropy();
        assert_eq!("ce98ae1c99b5e9d2a6965935c8bacf35", hex::encode(&entryop));
        let m2 = bip39::Mnemonic::from_entropy(&entryop).unwrap();

        let seed = m2.to_seed("");
        assert_eq!("7a17d52d7ad8bb1a280337686867c6a1c27180d6f38b7215299fa92b8e4ee4153eb4aca41db0fd79774bb34a57ecdbbf83db8f23bfa57ff2673f7c05d3d2b172",hex::encode(&seed));
        // let m2 =bip39::Mnemonic::from(&entryop).unwrap();

        let mut mac =
            HmacSha512::new_from_slice(&master_secret).expect("HMAC can take key of any size");

        mac.update(&seed);

        // `result` has type `CtOutput` which is a thin wrapper around array of
        // bytes for providing constant time equality check
        let result = mac.finalize();
        // To get underlying array use `into_bytes`, but be careful, since
        // incorrect use of the code value may permit timing attacks which defeats
        // the security provided by the `CtOutput`
        let code_bytes: Vec<u8> = result.into_bytes().to_vec();
        let mut private_key_array: [u8; 32] = [0; 32];
        private_key_array.copy_from_slice(&code_bytes[0..32]);
        let secret_key = SecretKey::from_slice(&private_key_array).unwrap();

        // 压缩公钥匙
        // let compress_public_key =  secret_key.public_key().to_sec1_bytes().to_vec();

        // 压缩公钥匙 hex
        let compress_public_key_hex = hex::encode(secret_key.public_key().to_sec1_bytes().to_vec());
        assert_eq!(
            "0353f006bb6bcf336fef39d827a245d7bef5555ce0cf0d27363b6cc080f1467b93",
            compress_public_key_hex
        );

        let affine_point = AffinePoint::from(secret_key.public_key());
        // 非压缩公钥
        let un_comporess_affine_point = affine_point.to_encoded_point(false).to_bytes();
        // println!("{}", hex::encode(un_comporess_affine_point));

        let mut hasher = Keccak256::new();
        // 去掉开头的 02、03、04
        hasher.update(&un_comporess_affine_point[1..]);
        let address_vec: Vec<u8> = hasher.finalize().to_vec();

        let address = address_vec[12..].to_vec();
        assert_eq!(
            "2f42b653f585b3bc8448187dce37eebaf8da2812",
            hex::encode(address)
        );
        // m2.to_seed("")
    }
}
