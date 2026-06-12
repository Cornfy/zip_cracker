mod cli;
mod cracker;
mod zip_ops;
mod utils;

use clap::Parser;
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::cli::{Cli, Commands};
use crate::cracker::{run_dict_attack, run_mask_attack, run_crc32_attack, run_brute_attack};
use crate::zip_ops::{check_password, run_fix_pseudo_encryption, run_show_info, run_kpa_attack, extract_archive};

const PRESET_PASSWORDS: &[&str] = &[
    "123456", "password", "12345678", "123456789", "12345", "1234567",
    "666666", "888888", "111111", "admin", "11223344", "87654321", "000000",
];

fn main() {
    let cli = Cli::parse();

    let command = if let Some(cmd) = cli.command {
        cmd
    } else if let Some(file) = cli.file {
        Commands::Info { file }
    } else {
        Cli::parse_from(["zipcracker", "--help"]);
        return;
    };

    match command {
        Commands::Check { file, password } => {
            if check_password(&file, &password) {
                crate::success!("Password correct: {}", password);
            } else {
                crate::error!("Password incorrect.");
            }
        }
        Commands::Dict { file, dictionary } => {
            let passwords: Vec<String> = if dictionary == "preset" {
                PRESET_PASSWORDS.iter().map(|&s| s.to_string()).collect()
            } else {
                let dict_file = match File::open(&dictionary) {
                    Ok(f) => f,
                    Err(_) => {
                        crate::error!("Failed to open dictionary file: {}", dictionary);
                        return;
                    }
                };
                let reader = BufReader::new(dict_file);
                reader.lines().filter_map(|l| l.ok()).collect()
            };
            run_dict_attack(file, passwords);
        }
        Commands::Mask { file, mask } => {
            run_mask_attack(file, mask);
        }
        Commands::Brute { file, min, max, charset, custom } => {
            run_brute_attack(file, min, max, charset, custom);
        }
        Commands::Crc32 { file } => {
            run_crc32_attack(file);
        }
        Commands::Fix { file, output } => {
            run_fix_pseudo_encryption(file, output);
        }
        Commands::Info { file } => {
            run_show_info(file);
        }
        Commands::Kpa { file, plaintext, cipher_entry, template, offset, recover, output } => {
            run_kpa_attack(file, plaintext, cipher_entry, template, offset, recover, output);
        }
        Commands::Extract { file, password, out_dir } => {
            extract_archive(&file, password, &out_dir);
        }
    }
}
