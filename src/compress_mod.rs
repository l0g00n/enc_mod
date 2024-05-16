use std::{io::{BufReader, Read, Write}, path::Path, process::exit};
use zstd::{Decoder, Encoder};

use crate::file_mod;

pub fn compress(file: &Path) {
    let encode = Vec::new();
    let input_file = &file.with_extension("lok");
    let contents = file_mod::read_file(input_file);

    // level 0-21
    let mut encoder = Encoder::new(encode, 18).unwrap_or_else(|err| {
        println!("Error: Compressing file contents - {err}");
        exit(1)
    });

    encoder.write_all(&contents).unwrap();
    let data = encoder.finish().unwrap_or_else(|err| {
        println!("Error: Faild to compress contents - {err}");
        exit(1)
    });
    file_mod::write_vector(file, &data);
}


pub fn decompress(file: &Path) {
    let mut decode = Vec::new();
    let out_file = &file.with_extension("lok");
    let contents = file_mod::read_file(out_file);

    let mut buf = BufReader::new(contents.as_slice());
    let mut decoder = Decoder::new(&mut buf).unwrap_or_else(|err| {
        println!("Error: Decompressing file contents - {err}");
        exit(1)
    });
    
    let _ = decoder.read_to_end(&mut decode);
    file_mod::write_vector(file, &decode);
}

