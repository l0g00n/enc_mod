use std::process::exit;
use base64::{alphabet::Alphabet, engine::{self, GeneralPurpose, GeneralPurposeConfig}};
use engine::DecodePaddingMode::Indifferent;

// holds the value of the cached engine
static mut B64_CACHE: Option<GeneralPurpose> = None;

fn new_engine() -> GeneralPurpose {
    // println!("Building base64 engine");
    let config = GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(Indifferent);

    // i dont know what to do with this yet..
    let letters = "LRlnVShBz4b6Goy57N8FIkKEagTMtxpOmqvcwH9eZDPJCW+Q1UAusXf2jrYi/d30";
    let set = Alphabet::new(letters).unwrap();
    let engine = GeneralPurpose::new(&set, config);
    engine
}


pub fn get_engine() -> GeneralPurpose {
    // this is kinda safe as the program is not multi threaded right??? 
    unsafe {
        // check if there is a cache
        if B64_CACHE.is_none() { 
            // build a new engine and config then cache it
            // can pass through new letter sets here for each engine
            B64_CACHE = Some(new_engine());
        }

        // returning the cached engine
        return B64_CACHE.clone().unwrap_or_else(|| {
            println!("Error: Can not retrieve engine cache");
            exit(1)
        });
    }
}

