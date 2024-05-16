use base64::Engine;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
use ring::{digest::SHA512_256_OUTPUT_LEN, pbkdf2};
use std::num::NonZeroU32;
use std::process::exit;
use std::convert::TryInto;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::seq::SliceRandom;

use crate::engine_mod;

static ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;

pub mod cipher {
    // This class deals with its own file handling including reading, 
    // writing and creating files while encrypting and decrypting contents.
    use chacha20poly1305::{aead::{Aead, AeadCore, OsRng},ChaCha20Poly1305, Nonce};
    use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::Path, process::exit};
    use rand::RngCore;
    
    use crate::{cipher_mod::gen_key, file_mod};
    use super::stored_values;

    pub fn encrypt_contents(file: &Path, contents: &[u8], password: &str, index: i32) -> bool {
        fn exclude_value(random: &mut OsRng, value: &mut [u8]) {
            // prevents the byte value of "58" being generated within the salt or nonce.
            // The byte value "58" represents ":". i use ":" as a splitter when joining (concatenating) stored values,
            // allowing for splitting of values during decryption.
            let exclude = 58;
            for byte in value {
                while byte == &exclude {
                    *byte = random.next_u32() as u8;
                }
            }
        }

        let mut random = OsRng;
        let mut salt = [0u8; 16];
        random.fill_bytes(&mut salt);
        exclude_value(&mut random, &mut salt);

        let cipher = gen_key(password, &salt);
        let mut nonce = ChaCha20Poly1305::generate_nonce(&mut random);
        exclude_value(&mut random, &mut nonce);

        let encrypt = cipher.encrypt(&nonce, contents).map(|encrypted| {
            let mut out_file = file_mod::create_file(file, "lok".to_string());
            out_file.write_all(&(encrypted.len() as u64).to_le_bytes()).unwrap();
            out_file.write_all(&encrypted).unwrap(); 
            
            let display = file.file_name().unwrap().to_string_lossy().to_string();
            println!("({index}) * Encrypted file - {display}");
            fs::remove_file(file).unwrap();
            true
        }).unwrap_or_else(|err| {
            println!("({index}) Error: Encrypting file contents - {err}");
            false
        });
        encrypt_values(file, &nonce, &salt);
        encrypt
    }


    fn encrypt_values(file: &Path, nonce: &[u8], salt: &[u8]) {
        let stored = stored_values();
        let file_extension = file.extension().unwrap().to_string_lossy();
        let extension = file_extension.as_bytes();
        let split = ":".as_bytes();
        let values = [nonce, split, salt, split, extension].concat();

        let cipher = gen_key(&stored.v3, &stored.v2);
        cipher.encrypt(Nonce::from_slice(&stored.v1), &*values).map(|encrypted_values| {
            let open_file = file.with_extension("lok");
            let mut out_file = OpenOptions::new().append(true).open(open_file).unwrap();
            out_file.write_all(&(encrypted_values.len() as u64).to_le_bytes()).unwrap();
            out_file.write_all(&encrypted_values).unwrap();
        }).unwrap_or_else(|err| {
            println!("Error: Encrypting salt, nonce, and file extension - {err}");
            exit(1)
        });
    }


    struct DecryptedValues {
        nonce: Vec<u8>,
        salt: Vec<u8>,
        file_extension: Vec<u8>

    }
    
    fn decrypt_values(values: Vec<u8>) -> DecryptedValues {
        let stored = stored_values();

        let cipher = gen_key(&stored.v3, &stored.v2);
        let decrypted_values = cipher.decrypt(Nonce::from_slice(&stored.v1), &*values).map(|decrypted_values| {
            let values  = decrypted_values.split(|&s| s == "::".as_bytes()[0]).collect::<Vec<&[u8]>>();

            if values.len() != 3 {
                println!("Error: File is missing important values");
                println!("Error: File can not be decrypted");
                exit(1)
            }

            let nonce = values[0].to_vec();
            let salt = values[1].to_vec();
            let file_extension = values[2].to_vec();

            DecryptedValues { nonce, salt, file_extension }
        }).unwrap_or_else(|err| {
            println!("Error: Decrypting salt, nonce, and file extension - {err}");
            exit(1)
        });
        decrypted_values
    }
    

    pub fn decrypt_contents(file: &Path, password: &str, index: i32) -> bool {
        let mut input_file = File::open(file).unwrap();

        // find encrypted contents block for decryption
        let mut ciphertext_len = [0u8; 8];
        input_file.read_exact(&mut ciphertext_len).unwrap();
        let bytes_ciphertext = u64::from_le_bytes(ciphertext_len) as usize;
        let mut ciphertext = vec![0u8; bytes_ciphertext];
        input_file.read_exact(&mut ciphertext).unwrap();
        
        // find encrypted values block containing (nonce, salt and file extension) for decryption
        let mut values_len = [0u8; 8];
        input_file.read_exact(&mut values_len).unwrap();
        let bytes_values = u64::from_le_bytes(values_len) as usize;
        let mut values = vec![0u8; bytes_values];
        input_file.read_exact(&mut values).unwrap();

        let decrypted_values = decrypt_values(values);
        let cipher = gen_key(password, &decrypted_values.salt);
        let decrypt = cipher.decrypt(Nonce::from_slice(&decrypted_values.nonce), &*ciphertext).map(|decrypted| {
            let file_extension = String::from_utf8_lossy(&decrypted_values.file_extension).into_owned();
            let display = file.with_extension(&file_extension).file_name().unwrap().to_string_lossy().to_string();
           
            let mut create_file = file_mod::create_file(file, file_extension);
            create_file.write_all(&decrypted).unwrap();
            println!("({index}) + Decrypted File - {display}");
            fs::remove_file(file).unwrap();
            true
        }).unwrap_or_else(|_| {
            println!("({index}) Error: Wrong password file");
            encrypt_values(file, &decrypted_values.nonce, &decrypted_values.salt);
            false
        });
        decrypt
    }
}


fn gen_key(password: &str, salt: &[u8]) -> ChaCha20Poly1305 {
    let key = &derive_key(password, salt);
    let key = Key::from_slice(key);
    ChaCha20Poly1305::new(key)
}


fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    // chacha20poly1305 accepts a 256-bit key size (32 bytes)
    // using sha512 hashing converted to 32 bytes in length for the key 
    let mut key = [0u8; SHA512_256_OUTPUT_LEN];
    let iter = NonZeroU32::new(100_000).unwrap();
    let password = password.as_bytes();
    pbkdf2::derive(ALG, iter, salt, password, &mut key);
    key
}


pub fn get_salt(contents: &String) -> String {
    let con_silce: String;

    // getting salt depending on contents size
    if contents.len() >= 32 {
        con_silce  = contents[0..32].to_string();
    } else if contents.len() >= 16 {
        con_silce  = contents[0..16].to_string();
    } else if contents.len() >= 8 {
        con_silce  = contents[0..8].to_string();
    } else {
        con_silce  = contents.to_string()
    }
    
    let stored = stored_values();
    let seed = stored.v4.try_into().unwrap_or_else(|_| {
        println!("Error: Can not fill whole bytes array");
        exit(1)
    });

    let mut random = StdRng::from_seed(seed);
    let mut chars = con_silce.chars().map(|x |x.to_string()).collect::<Vec<String>>();

    // shuffle the content before returning it as the salt
    chars.shuffle(&mut random);
    chars.join("")
}


struct StoredValues {
    v1: Vec<u8>,
    v2: Vec<u8>,
    v3: String,
    v4: Vec<u8>
}

fn stored_values() -> StoredValues {
    // hard coded values used in the second round of encryption for sealing the 
    // randomly generated nonce, salt and file extension before writing to the file.
    
    // most likely a better way to do this but i wanted the executable to be as portable as possible, 
    // and having config files limits that.
    // values were generated using randomness from the operating system.

    // encoded using custom base64
    let mut values = Vec::new();
    let stored_values = vec!["eHgu8O0olXWH++Rp", "YE8DB2Hzz0INOoDlbmhbzm==", "ySzXKn4IGSHhKcoEowWKFcNVIuSBIFHz8w4o7uxG7Ik7kIH5", "KkHgKkHgKkHgKkHgKkHgKkHgKkHgKkHgKkHgKkHgKkw="];

    let engine = engine_mod::get_engine();
    for value in stored_values {
        let decode = engine.decode(value).unwrap_or_else(|err| {
            println!("Error: Can not decode base64 - {}", err); 
            exit(1);
        });
        
        values.push(decode);
    }
    
    let v1 = values[0].clone();
    let v2 = values[1].clone();
    let v3 = values[2].clone();
    let v3 = String::from_utf8(v3).unwrap();
    let v4 = values[3].clone();

    StoredValues { v1, v2, v3, v4 }
}

