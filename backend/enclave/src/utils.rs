use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Pair<T, U> {
    first: T,
    second: U,
}

impl<T, U> Pair<T, U> {
    pub fn first(&self) -> &T {
        &self.first
    }
    pub fn second(&self) -> &U {
        &self.second
    }
    pub fn new(first: T, second: U) -> Self {
        Pair { first, second }
    }
}

/*
pub fn read_from_console(command: &str) -> String {
    use std::io;

    println!(">>> {}:", command);
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(n) => {
            println!("Your input: {} ({} bytes)", input, n);
            input
        }
        Err(error) => {
            println!("error: {}", error);
            input
        }
    }
}
 */

/*
pub fn get_char_array(text: &String) -> Vec<u32> {
    let mut char_vec: Vec<u32> = Vec::with_capacity(text.len());
    let text_it = text.chars();
    if text.len() == 0 {
        char_vec.push(0u32);
    } else {
        for some_char in text_it {
            char_vec.push(some_char as u32);
        }
    }
    return char_vec;
}
 */
