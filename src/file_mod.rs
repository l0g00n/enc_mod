use std::{fs::{self, File}, io::Write, path::{Path, PathBuf}, process::exit};
use native_dialog::FileDialog;
use sha2::{Digest, Sha512};

use crate::cipher_mod;

pub fn get_password() -> String {
    let file = &get_file();
    let contents = fs::read_to_string(file).unwrap_or_else(|err| {
        println!("Error: Reading in password file - {err}");
        exit(1);
    });
    
    if contents.len() == 0 {
        println!("Error: File is empty");
        exit(1);
    }
    println!("Password file loaded");
    sha512_hasher(contents)
}


pub fn sha512_hasher(contents: String) -> String {
    let salt = cipher_mod::get_salt(&contents);
    let password = [contents, salt].concat();
    let mut hash = Sha512::new();
    hash.update(password);
    hex::encode(hash.finalize())
}


pub fn get_file() -> PathBuf {
    let file_path = FileDialog::new().show_open_single_file().unwrap_or_else(|err| {
        println!("Error: Invaild file path - {err}");
        exit(1)
    });

    if !file_path.is_some() {
        println!("Error: No file selected\n");
        return PathBuf::new();
    }
    file_path.unwrap()
}


pub fn get_folder() -> PathBuf {
    let folder_path = FileDialog::new().show_open_single_dir().unwrap_or_else(|err| {
        println!("Error: Invaild folder path - {err}");
        exit(1)
    });

    if !folder_path.is_some() {
        println!("Error: No Folder selected\n");
        return PathBuf::new();
    }
    folder_path.unwrap()
}


pub fn create_file(file: &Path, file_extension: String) -> File {
    let output_file = &file.with_extension(file_extension);
    let new_file = File::create(output_file).unwrap_or_else(|err| {
        println!("Error: Creating a file - {err}");
        exit(1)
    });
    new_file
}


pub fn write_strings(file: &Path, contents: &String) {
    let mut write_file = create_file(file, "lok".to_string());
    let bytes = contents.as_bytes();
    write_file.write_all(bytes).unwrap_or_else(|err| {
        println!("Error: Writing binary to file - {err}");
        exit(1)
    });
}


pub fn write_vector(file: &Path, contents: &[u8]) {
    let mut write_file = create_file(file, "lok".to_string());
    write_file.write_all(contents).unwrap_or_else(|err| {
        println!("Error: Writing vector binary to file - {err}");
        exit(1)
    });
}


pub fn read_file(file: &Path) -> Vec<u8> {
    let contents = fs::read(file).unwrap_or_else(|err| {
        println!("Error: Reading strings from file - {err}");
        exit(1)
    });
    contents
}


pub fn read_dir(file: &Path) -> Vec<PathBuf> {
    let mut dir = Vec::new();
    let mut index = 0;
    let files = fs::read_dir(file).unwrap_or_else(|err| {
        println!("Error: Directory is empty - {err}");
        exit(1)
    });

    println!("Folder contents:");
    for file in files {
        let file = file.map_err(|err| {
            println!("Error: {err}");
        });

        let file = file.unwrap();
        if !file.path().is_file() {
            continue; 
        }
        index += 1;
        let full_path = file.path();
        println!("({index}) - {path}",  path = full_path.display());
        dir.push(full_path);
    }
    println!("");
    dir
}

