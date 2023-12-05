
pub mod mnemonic;
pub mod key;
pub mod sign;
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
fn main() {
    println!("Hello, world!");
}
