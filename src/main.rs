use std::{env, io::{self, Write}, path::{Path, PathBuf}, process::exit};
use inquire::{Password, PasswordDisplayMode};

mod file_mod;
mod cipher_mod;
mod encode_mod;
mod compress_mod;
mod engine_mod;

fn print_options(error: &str) {
    println!("
    {error}
    
    Flags:
        -e Encryption
        -d Decryption
        -s Start a session
        -r Recursively processes files in a directory
        -p Prompted to type in a password
        
    Usage:
        datalok <file or folder> [-s] <-e -d> [-r][-p]")
}


fn print_commands() {
    println!("
    Commands:   
        e | encrypt - Encryption
        d | decrypt - Decryption
        h | help - Shows all commands
        cls - Clear the console
        exit - Exits the session
        
    Flags:
        -r Recursively processes files in a directory")
}


struct Options {
    file: PathBuf,
    session: String,
    options: Vec<String>
}

fn main() {
    let input = env::args().collect::<Vec<String>>();
    if input.len() == 1 {
        print_options("Error: No options chosen");
        return;
    }

    let args = &input[1..];
    let args = Options {
        file: std::path::PathBuf::from(&args[0]),
        session: args[0].clone(),
        options: args[1..].to_vec(),
    };

    if args.session == "-s" {
        let password = password_option(&args);
        handle_session(password);
    } else {
        if !args.file.exists() {
            print_options("Error: Can not find file, folder or session");
            return;
        }
    
        if args.options.len() == 0 {
            print_options("Error: No encryption mode chosen");
            return;
        }
        check_options(args);
    }
}

 
#[allow(unused_assignments)]
fn password_option(args: &Options) -> String {
    let mut password = String::new();
    if args.options.len() == 1 && args.options[0] == "-p" || args.options.len() == 2 && args.options[1] == "-p" || args.options.len() == 3 && args.options[2] == "-p" { 
        password = Password::new("Password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_custom_confirmation_message("Password (confirm):")
        .with_custom_confirmation_error_message("Passwords do not match")
        .prompt()
        .unwrap_or_else(|err| {
            println!("Error: {err}");
            exit(1)
        });

        if password.len() == 0 {
            
            println!("Error: Password can not be empty");
            exit(1);
        }
        println!("Password loaded");
        password = file_mod::sha512_hasher(password)
        
    } else {
        println!("Input password file");
        password = file_mod::get_password()
    }
    password
}


fn check_options(args: Options) {
    let password = password_option(&args);
    let mut files = Vec::new();
    if args.options.len() >= 2 && args.options[1] == "-r" {
        files = file_mod::read_dir(&args.file);
    } else {
        if !args.file.is_file() {
            print_options("Error: A directory can be encrypted only inside another directory");
            return;
        }
        files.push(args.file);
    }

    let mut index = 0;
    for file in &files {
        index += 1;
        if args.options[0] == "-e" {
            encrypt(file, &password, index);
        } else {
            decrypt(file, &password, index);
        }
    }
}


fn handle_session(password: String) {
    fn get_input() -> Vec<String> {
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        input.trim().split(' ').map(|x |x.to_string()).collect::<Vec<String>>()
    }

    println!("Session started - Type 'h' for help\n");
    loop {
        print!(">>:: "); 
        io::stdout().flush().unwrap(); 

        let input = get_input();
        let (input, args) = (&input[0], &input[1..]);
        if input == "exit" {
            println!("Exiting session");
            exit(1);
        } else if input == "e" || input == "encrypt" {
            let mut index = 0;
            if args.len() == 0 {
                println!("Input a file to encrypt\n");
                let file = &file_mod::get_file();
                if !file.exists() {
                    continue;
                }
                encrypt(file, &password, index);

            } else if args[0] == "-r" {
                println!("Input a folder to encrypt\n");
                let dir = file_mod::get_folder();
                if !dir.exists() {
                    continue;
                }

                let files = file_mod::read_dir(&dir);
                let send_password = password.clone();
                for file in files {
                    index += 1;
                    encrypt(&file, &send_password, index)
                } 
            
            } else {
                println!("Error: Unknown command - Type 'h' for help");
            }

        } else if input == "d" || input == "decrypt" {
            let mut index = 0;
            if args.len() == 0 {
                println!("Input a file to decrypt\n");
                let file = &file_mod::get_file();
                if !file.exists() {
                    continue;
                }
                decrypt(file, &password, index);

            } else if args[0] == "-r" {
                println!("Input a folder to decrypt\n");
                let dir = file_mod::get_folder();
                if !dir.exists() {
                    continue;
                }
                let files = file_mod::read_dir(&dir);
                let send_password = password.clone();
                for file in files {
                    index += 1;
                    decrypt(&file, &send_password, index)
                } 

            } else {
                println!("Error: Unknown command - Type 'h' for help");
            }

        } else if input == "h" || input == "help" {
            print_commands();
        } else if input == "cls" {
            for _ in 0..150 {
                // i guess
                println!();
            }
        } else {
            if input.len() == 0 {
                continue;
            }
            println!("Error: Unknown command - Type 'h' for help");
        }
        println!("")
    }
}


fn encrypt(file: &Path, password: &str, index: i32) {
    let check_file = file.to_string_lossy();
    if check_file.ends_with("lok") {
        println!("({index}) Error: File is already encrypted");
        return;
    }
    
    let contents = &file_mod::read_file(file);
    if contents.len() == 0 {
        println!("({index}) Error: No file contents found");
        return;
    }

    if !cipher_mod::cipher::encrypt_contents(file, contents, password, index){
        file_mod::write_vector(file, contents);
        // println!("DEBUG: Writing file contents back...");
        return;
    }

    encode_mod::to_base64(file);
    encode_mod::to_binary(file);
    compress_mod::compress(file);
}


fn decrypt(file: &Path, password: &str, index: i32) {
    let check_file = file.to_string_lossy();
    if !check_file.ends_with("lok") {
        println!("({index}) Error: File is not encrypted");
        return;
    }

    compress_mod::decompress(file);
    encode_mod::from_binary(file);
    encode_mod::from_base64(file);

    if !cipher_mod::cipher::decrypt_contents(file, password, index) {
        // println!("DEBUG: Compressing file again...");
        encode_mod::to_base64(file);
        encode_mod::to_binary(file);
        compress_mod::compress(file);
    }
}

