use std::{path::Path, process::exit};
use base64::Engine;

use crate::{engine_mod::{self, get_engine}, file_mod};

pub fn to_binary(file: &Path) {
    let input_file = &file.with_extension("lok");
    let contents = file_mod::read_file(input_file);
    
    let mut data = String::new();
    for byte in &contents {
        let encode = format!("{:08b}", byte);
        data.push_str(&encode);
    }
    file_mod::write_strings(file, &data);
}


pub fn from_binary(file: &Path) {
    let input_file = &file.with_extension("lok");
    let contents = file_mod::read_file(input_file);
    
    let mut words = Vec::new();
    let mut chars = Vec::new();
    for byte in contents {
        chars.push(byte);

        if chars.len() == 8 {
            let string = std::str::from_utf8(&chars).unwrap_or_else(|err| {
                println!("Error: Converting to string - {err}");
                exit(1)
            });
            
            let chr = u8::from_str_radix(string, 2).unwrap_or_else(|err| {
                println!("Error: Converting to binary - {err}");
                exit(1)
            });
            words.push(chr);
            chars.clear();
        }
    }
    file_mod::write_vector(file, &words);
}


pub fn to_base64(file: &Path) {
    let input_file = &file.with_extension("lok");
    let contents = file_mod::read_file(input_file);
    
    let engine = engine_mod::get_engine();
    let encoded = engine.encode(contents);
    file_mod::write_strings(file, &encoded);
}


pub fn from_base64(file: &Path) {
    let input_file = file.with_extension("lok");
    let contents = file_mod::read_file(&input_file);

    let engine = get_engine();
    let decoded = engine.decode(contents).unwrap_or_else(|err| {
        println!("Error: Can not decode base64 contents - {err}");
        exit(1);
    });

    file_mod::write_vector(file, &decoded);
}

