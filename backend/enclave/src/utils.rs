use serde::{Deserialize, Serialize};
use std::string::{String};
use std::vec::Vec;

#[derive(Serialize, Deserialize, Clone)]
pub struct Pair<T, U> {
    first: T,
    second: U,
}

impl<T, U> Pair<T, U> {
    pub fn first(&self) -> &T {
        &self.first
    }
    pub fn steal_first(self) -> T {
        self.first
    }
    pub fn mut_first(&mut self) -> &mut T {
        &mut self.first
    }
    pub fn second(&self) -> &U {
        &self.second
    }
    pub fn steal_second(self) -> U {
        self.second
    }
    pub fn mut_second(&mut self) -> &mut U {
        &mut self.second
    }
    pub fn new(first: T, second: U) -> Self {
        Pair { first, second }
    }
    pub fn set_first(&mut self, first: T) {
        self.first = first;
    }
    pub fn set_second(&mut self, second: U) {
        self.second = second;
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Triple<T, U, V> {
    first: T,
    second: U,
    third: V,
}

impl<T, U, V> Triple<T, U, V> {
    pub fn first(&self) -> &T {
        &self.first
    }
    pub fn steal_first(self) -> T {
        self.first
    }
    pub fn mut_first(&mut self) -> &mut T {
        &mut self.first
    }
    pub fn second(&self) -> &U {
        &self.second
    }
    pub fn steal_second(self) -> U {
        self.second
    }
    pub fn mut_second(&mut self) -> &mut U {
        &mut self.second
    }
    pub fn new(first: T, second: U, third: V) -> Self {
        Triple {
            first,
            second,
            third,
        }
    }
    pub fn set_first(&mut self, first: T) {
        self.first = first;
    }
    pub fn set_second(&mut self, second: U) {
        self.second = second;
    }
    pub fn third(&self) -> &V {
        &self.third
    }
    pub fn mut_third(&mut self) -> &mut V {
        &mut self.third
    }
    pub fn set_third(&mut self, third: V) {
        self.third = third;
    }
}

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
