use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

pub fn write_bytes(file_name: String, data: &Vec<u8>) {
    match fs::remove_file(&file_name) {
        Ok(_) => {}
        Err(err) => {
            println!(
                "The file {} could not be removed: {}",
                &file_name,
                err.to_string()
            )
        }
    }
    match File::create(file_name) {
        Ok(mut file) => match file.write_all(data) {
            Ok(_) => {}
            Err(err) => {
                println!("write_all to byte file does not work: {}", err.to_string());
            }
        },
        Err(err) => {
            println!("Creating the Byte file does not work: {}", err.to_string());
        }
    }
}

pub fn read_bytes(file_name: String) -> Option<Vec<u8>> {
    match OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .open(file_name)
    {
        Ok(mut file) => {
            let mut buffer = Vec::new();
            // read the whole file
            match file.read_to_end(&mut buffer) {
                Ok(_) => {
                    return Some(buffer);
                }
                Err(err) => {
                    eprintln!("File cannot be read: {}", err.to_string())
                }
            }
        }
        Err(err) => {
            eprintln!("File cannot be opened: {}", err.to_string())
        }
    }
    None
}
