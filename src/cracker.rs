use rayon::prelude::*;
use std::fs::File;
use std::path::Path;
use zip::ZipArchive;
use indicatif::{ProgressBar, ProgressStyle};
use dialoguer::Confirm;
use crate::zip_ops::{check_password_with_archive, extract_archive};

pub fn expand_mask(mask: &str) -> Vec<Vec<char>> {
    let mut result = Vec::new();
    let chars: Vec<char> = mask.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '?' && i + 1 < chars.len() {
            match chars[i + 1] {
                'd' => result.push("0123456789".chars().collect()),
                'l' => result.push("abcdefghijklmnopqrstuvwxyz".chars().collect()),
                'u' => result.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect()),
                's' => result.push("!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/ ".chars().collect()),
                '?' => result.push(vec!['?']),
                _ => result.push(vec![chars[i+1]]),
            }
            i += 2;
        } else {
            result.push(vec![chars[i]]);
            i += 1;
        }
    }
    result
}

pub fn get_password_at_index(expanded: &[Vec<char>], mut index: u64) -> String {
    let mut res = Vec::new();
    for pos in expanded.iter().rev() {
        let len = pos.len() as u64;
        res.push(pos[(index % len) as usize]);
        index /= len;
    }
    res.into_iter().rev().collect()
}

pub fn crack_crc32(target_crc: u32, len: usize) -> Option<String> {
    const CHARSET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ";
    let charset_len = CHARSET.len() as u64;
    let total = charset_len.pow(len as u32);
    
    (0..total).into_par_iter().find_map_any(|mut index| {
        let mut combination = vec![0u8; len];
        for j in 0..len {
            combination[len - 1 - j] = CHARSET[(index % charset_len) as usize];
            index /= charset_len;
        }
        if crc32fast::hash(&combination) == target_crc {
            Some(String::from_utf8_lossy(&combination).into_owned())
        } else {
            None
        }
    })
}

pub fn run_dict_attack(file: String, passwords: Vec<String>) {
    crate::info!("Starting dictionary attack with {} passwords...", passwords.len());
    
    let pb = ProgressBar::new(passwords.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, {eta})")
        .unwrap()
        .progress_chars("#>-"));

    let file_path = file.clone();
    let found = passwords.par_iter().map_init(
        || {
            let f = File::open(&file_path).unwrap();
            ZipArchive::new(f).unwrap()
        },
        |archive, pwd| {
            let res = check_password_with_archive(archive, pwd);
            pb.inc(1);
            if res { Some(pwd.clone()) } else { None }
        }
    ).find_any(|x| x.is_some()).flatten();

    pb.finish_and_clear();

    if let Some(pwd) = found {
        crate::success!("Password found: {}", pwd);
        
        if Confirm::new()
            .with_prompt("Do you want to extract the archive now?")
            .default(true)
            .interact()
            .unwrap_or(false) 
        {
            let out_dir = format!("unzipped_{}", Path::new(&file).file_stem().unwrap().to_str().unwrap());
            extract_archive(&file, Some(pwd), &out_dir);
        }
    } else {
        crate::error!("Password not found in dictionary.");
    }
}

pub fn run_mask_attack(file: String, mask: String) {
    if !Path::new(&file).exists() {
        crate::error!("ZIP file not found: {}", file);
        return;
    }
    let expanded = expand_mask(&mask);
    let total_count: u64 = expanded.iter().map(|v| v.len() as u64).product();

    crate::info!("Starting mask attack with {} combinations...", total_count);

    let pb = ProgressBar::new(total_count);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, {eta})")
        .unwrap()
        .progress_chars("#>-"));

    let file_path = file.clone();
    let found = (0..total_count).into_par_iter().map_init(
        || {
            let f = File::open(&file_path).unwrap();
            ZipArchive::new(f).unwrap()
        },
        |archive, index| {
            let pwd = get_password_at_index(&expanded, index);
            let res = check_password_with_archive(archive, &pwd);
            pb.inc(1);
            if res { Some(pwd) } else { None }
        }
    ).find_any(|x| x.is_some()).flatten();

    pb.finish_and_clear();

    if let Some(pwd) = found {
        crate::success!("Password found: {}", pwd);

        if Confirm::new()
            .with_prompt("Do you want to extract the archive now?")
            .default(true)
            .interact()
            .unwrap_or(false) 
        {
            let out_dir = format!("unzipped_{}", Path::new(&file).file_stem().unwrap().to_str().unwrap());
            extract_archive(&file, Some(pwd), &out_dir);
        }
    } else {
        crate::error!("Password not found with this mask.");
    }
}

pub fn run_brute_attack(file: String, min: usize, max: usize, charset_type: String, custom: Option<String>) {
    if !Path::new(&file).exists() {
        crate::error!("ZIP file not found: {}", file);
        return;
    }

    let charset: Vec<char> = if let Some(c) = custom {
        c.chars().collect()
    } else {
        match charset_type.as_str() {
            "digits" => "0123456789".chars().collect(),
            "lowercase" => "abcdefghijklmnopqrstuvwxyz".chars().collect(),
            "uppercase" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect(),
            "letters" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect(),
            "mix" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect(),
            "all" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/ ".chars().collect(),
            _ => {
                crate::error!("Unknown charset preset: {}. Falling back to 'digits'.", charset_type);
                "0123456789".chars().collect()
            }
        }
    };

    let charset_len = charset.len() as u64;
    
    for len in min..=max {
        let total_count: u64 = charset_len.pow(len as u32);
        crate::info!("Brute-forcing length {} ({} combinations)...", len, total_count);

        let pb = ProgressBar::new(total_count);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"));

        let file_path = file.clone();
        let charset_ref = &charset;
        let found = (0..total_count).into_par_iter().map_init(
            || {
                let f = File::open(&file_path).unwrap();
                ZipArchive::new(f).unwrap()
            },
            |archive, mut index| {
                let mut pwd = String::with_capacity(len);
                let mut temp_chars = vec![' '; len];
                for i in (0..len).rev() {
                    temp_chars[i] = charset_ref[(index % charset_len) as usize];
                    index /= charset_len;
                }
                for c in temp_chars { pwd.push(c); }
                
                let res = check_password_with_archive(archive, &pwd);
                pb.inc(1);
                if res { Some(pwd) } else { None }
            }
        ).find_any(|x| x.is_some()).flatten();

        pb.finish_and_clear();

        if let Some(pwd) = found {
            crate::success!("Password found: {}", pwd);

            if Confirm::new()
                .with_prompt("Do you want to extract the archive now?")
                .default(true)
                .interact()
                .unwrap_or(false) 
            {
                let out_dir = format!("unzipped_{}", Path::new(&file).file_stem().unwrap().to_str().unwrap());
                extract_archive(&file, Some(pwd), &out_dir);
            }
            return;
        }
    }

    crate::error!("Password not found in brute-force range.");
}

pub fn run_crc32_attack(file: String) {
    let zip_file = match File::open(&file) {
        Ok(f) => f,
        Err(_) => {
            crate::error!("Failed to open ZIP file: {}", file);
            return;
        }
    };
    let mut archive = ZipArchive::new(zip_file).expect("Failed to read ZIP archive");

    for i in 0..archive.len() {
        let file_info = archive.by_index_raw(i).unwrap();
        let size = file_info.size();
        let crc = file_info.crc32();
        let name = file_info.name().to_string();

        if size > 0 && size <= 6 {
            crate::warn!("Found short file: {} ({} bytes, CRC32: {:08X})", name, size, crc);
            crate::info!("Attempting CRC32 enumeration...");
            
            if let Some(content) = crack_crc32(crc, size as usize) {
                crate::success!("Success! Content of {}: {}", name, content);
            } else {
                crate::error!("Failed to find content for {}.", name);
            }
        }
    }
}
