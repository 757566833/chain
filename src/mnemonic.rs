fn g(){}

#[cfg(test)]
mod tests {
    #[test]
    fn test_big_num_to_vec() {
        let mnemonic = bip39::Mnemonic::generate(12).unwrap();
        // bip39::Mnemonic::from_entropy(entropy)
        let entryop = mnemonic.to_entropy();
        let m2 =bip39::Mnemonic::from_entropy(&entryop).unwrap();

        // let m2 =bip39::Mnemonic::from(&entryop).unwrap();
        
        println!("{}",mnemonic.to_string());
        println!("{}",m2.to_string());
        println!("{:?}",entryop);
        println!("{:?}",m2.to_seed_normalized("").to_vec())
        // m2.to_seed("")
    }
}