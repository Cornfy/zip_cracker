use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about = "ZipCracker in Rust - High Performance ZIP Password Cracker")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to the ZIP file (default to 'info' if no command provided)
    pub file: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Check a single password
    Check {
        /// Path to the ZIP file
        #[arg(short, long)]
        file: String,
        /// Password to test
        #[arg(short, long)]
        password: String,
    },
    /// Dictionary attack
    Dict {
        /// Path to the ZIP file
        #[arg(short, long)]
        file: String,
        /// Path to the dictionary file (or use "preset")
        #[arg(short, long)]
        dictionary: String,
    },
    /// Brute-force attack with common presets
    Brute {
        /// Path to the ZIP file
        #[arg(short, long)]
        file: String,
        /// Minimum password length
        #[arg(long, default_value_t = 1)]
        min: usize,
        /// Maximum password length
        #[arg(long, default_value_t = 6)]
        max: usize,
        /// Charset preset:
        ///   digits    : 0-9
        ///   lowercase : a-z
        ///   uppercase : A-Z
        ///   letters   : a-zA-Z
        ///   mix       : a-zA-Z0-9
        ///   all       : includes symbols
        #[arg(short, long, default_value = "digits")]
        charset: String,
        /// Custom charset (overrides --charset)
        #[arg(short = 'C', long)]
        custom: Option<String>,
    },
    /// Mask attack
    Mask {
        /// Path to the ZIP file
        #[arg(short, long)]
        file: String,
        /// Mask for brute-force. Placeholders:
        ///   ?d : digit (0-9)
        ///   ?l : lowercase (a-z)
        ///   ?u : uppercase (A-Z)
        ///   ?s : symbol (!@#$%^&*...)
        ///   ?? : literal '?'
        /// Example: ?d?d?d?l?d?d?d?l
        #[arg(short, long)]
        mask: String,
    },
    /// CRC32 enumeration attack for short files
    Crc32 {
        /// Path to the ZIP file
        #[arg(short, long)]
        file: String,
    },
    /// Detect and fix pseudo-encryption
    Fix {
        /// Path to the ZIP file
        #[arg(short, long)]
        file: String,
        /// Output path for fixed ZIP
        #[arg(short = 'D', long)]
        output: Option<String>,
    },
    /// View ZIP structure and entry details
    Info {
        /// Path to the ZIP file
        #[arg(short, long)]
        file: String,
    },
    /// Known-Plaintext Attack (KPA) via bkcrack
    Kpa {
        /// Path to the encrypted ZIP file
        #[arg(short, long)]
        file: String,
        /// Path to the known plaintext file or ZIP
        #[arg(short, long)]
        plaintext: Option<String>,
        /// Target file name inside the encrypted ZIP
        #[arg(short, long)]
        cipher_entry: Option<String>,
        /// Use common file templates (png, zip, exe, pcapng)
        #[arg(short, long)]
        template: Option<String>,
        /// Plaintext offset relative to ciphertext (default 0)
        #[arg(short, long, default_value_t = 0)]
        offset: i64,
        /// Recovery password after keys found
        #[arg(short, long)]
        recover: bool,
        /// Decrypt ZIP to this file if keys are found
        #[arg(short = 'D', long)]
        output: Option<String>,
    },
    /// Extract files from ZIP and sync modification times
    Extract {
        /// Path to the ZIP file
        #[arg(short, long)]
        file: String,
        /// Password for decryption
        #[arg(short, long)]
        password: Option<String>,
        /// Output directory
        #[arg(short, long, default_value = ".")]
        out_dir: String,
    },
}
