use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;
use zip::{ZipArchive, ZipWriter};
use zip::write::FileOptions;
use zip::result::ZipError;
use crate::utils::{sync_time, parse_keys};
use colored::Colorize;

pub struct KpaTemplate {
    pub name: &'static str,
    pub signature: &'static [u8],
}

pub const KPA_TEMPLATES: &[KpaTemplate] = &[
    KpaTemplate { name: "png", signature: b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" },
    KpaTemplate { name: "zip", signature: b"PK\x03\x04" },
    KpaTemplate { name: "exe", signature: b"MZ" },
    KpaTemplate { name: "pcapng", signature: b"\x0a\x0d\x0d\x0a" },
];

pub fn check_password_with_archive(archive: &mut ZipArchive<File>, pwd: &str) -> bool {
    for i in 0..archive.len() {
        let is_encrypted = match archive.by_index(i) {
            Err(ZipError::UnsupportedArchive(ZipError::PASSWORD_REQUIRED)) => true,
            _ => false,
        };

        if is_encrypted {
            let mut file = match archive.by_index_decrypt(i, pwd.as_bytes()) {
                Ok(Ok(f)) => f,
                _ => continue,
            };

            // STRICT validation: read the entire file to verify password.
            let mut buffer = Vec::new();
            match file.read_to_end(&mut buffer) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }
    false
}

pub fn check_password(path: &str, pwd: &str) -> bool {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => return false,
    };

    check_password_with_archive(&mut archive, pwd)
}

pub fn extract_archive(file_path: &str, password: Option<String>, out_dir: &str) {
    let zip_file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => {
            crate::error!("Failed to open ZIP file: {}", file_path);
            return;
        }
    };
    let mut archive = ZipArchive::new(zip_file).expect("Failed to read ZIP archive");
    let out_path = Path::new(out_dir);
    if !out_path.exists() {
        std::fs::create_dir_all(out_path).unwrap();
    }

    crate::info!("Extracting files to: {}", out_dir);
    for i in 0..archive.len() {
        let name;
        let mtime;
        let is_dir;
        let mut data_buffer = Vec::new();

        if let Some(ref pwd) = password {
            let mut file = match archive.by_index_decrypt(i, pwd.as_bytes()) {
                Ok(Ok(f)) => f,
                _ => {
                    crate::error!("Wrong password or failed to access entry {}.", i);
                    return; // Stop extraction
                }
            };
            name = file.name().to_string();
            mtime = file.last_modified();
            is_dir = file.is_dir();
            
            if let Err(e) = file.read_to_end(&mut data_buffer) {
                crate::error!("Password likely incorrect (checksum failure): {}", e);
                return; // Stop extraction
            }
        } else {
            let mut file = match archive.by_index(i) {
                Ok(f) => f,
                Err(ZipError::UnsupportedArchive(ZipError::PASSWORD_REQUIRED)) => {
                    crate::error!("Entry {} is encrypted. Please provide a password with --password.", i);
                    return;
                }
                Err(e) => {
                    crate::error!("Failed to access entry {}: {}", i, e);
                    return;
                }
            };
            name = file.name().to_string();
            mtime = file.last_modified();
            is_dir = file.is_dir();
            if !is_dir {
                if let Err(e) = file.read_to_end(&mut data_buffer) {
                    crate::error!("Failed to read entry {}: {}", name, e);
                    return;
                }
            }
        };

        let dest_path = out_path.join(&name);

        if is_dir {
            std::fs::create_dir_all(&dest_path).unwrap();
        } else {
            if let Some(p) = dest_path.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(p).ok();
                }
            }
            let mut outfile = File::create(&dest_path).expect("Failed to create file");
            outfile.write_all(&data_buffer).expect("Failed to write file");
        }
        
        // Sync Time
        sync_time(&dest_path, mtime);
        crate::success!("Extracted: {}", name);
    }
    crate::info!("Extraction complete.");
}

pub fn run_fix_pseudo_encryption(file: String, output: Option<String>) {
    let output_path = output.unwrap_or_else(|| format!("{}.fixed.zip", file));
    
    let src_file = File::open(&file).expect("Failed to open source ZIP");
    let mut archive = ZipArchive::new(src_file).expect("Failed to read source ZIP");
    
    // First pass: Verify if it's actually fixable (pseudo-encryption)
    let mut is_fixable = true;
    for i in 0..archive.len() {
        let is_encrypted = match archive.by_index(i) {
            Err(ZipError::UnsupportedArchive(ZipError::PASSWORD_REQUIRED)) => true,
            _ => false,
        };

        if is_encrypted {
            // Try empty password
            let decrypt_attempt = archive.by_index_decrypt(i, "".as_bytes());
            match decrypt_attempt {
                Ok(Ok(mut f)) => {
                    let mut buf = [0u8; 1];
                    if f.read_exact(&mut buf).is_err() {
                        is_fixable = false;
                        break;
                    }
                },
                _ => {
                    is_fixable = false;
                    break;
                }
            }
        }
    }

    if !is_fixable {
        crate::error!("ZIP is truly encrypted, cannot fix pseudo-encryption.");
        std::process::exit(1);
    }

    crate::info!("Attempting to fix pseudo-encryption for: {}", file);
    let dest_file = File::create(&output_path).expect("Failed to create fixed ZIP");
    let mut writer = ZipWriter::new(dest_file);
    
    let mut fixed_count = 0;
    for i in 0..archive.len() {
        let is_encrypted = match archive.by_index(i) {
            Err(ZipError::UnsupportedArchive(ZipError::PASSWORD_REQUIRED)) => true,
            _ => false,
        };

        let (name, compression, last_modified) = {
            let entry = archive.by_index_raw(i).unwrap();
            (entry.name().to_string(), entry.compression(), entry.last_modified())
        };
        
        let options = FileOptions::default()
            .compression_method(compression)
            .last_modified_time(last_modified);
        
        writer.start_file(name, options).unwrap();
        let mut buffer = Vec::new();
        
        if is_encrypted {
            let mut f = archive.by_index_decrypt(i, "".as_bytes()).unwrap().unwrap();
            f.read_to_end(&mut buffer).unwrap();
        } else {
            let mut f = archive.by_index_raw(i).unwrap();
            f.read_to_end(&mut buffer).unwrap();
        }
        
        writer.write_all(&buffer).unwrap();
        fixed_count += 1;
    }
    
    writer.finish().unwrap();
    crate::success!("Fixed ZIP saved to: {}", output_path);
    crate::info!("Processed {} entries.", fixed_count);
}

pub fn run_show_info(file: String) {
    let zip_file = match File::open(&file) {
        Ok(f) => f,
        Err(_) => {
            crate::error!("Failed to open ZIP file: {}", file);
            return;
        }
    };
    let mut archive = ZipArchive::new(zip_file).expect("Failed to read ZIP archive");

    println!("{:<30} {:<12} {:<12} {:<12} {:<10} {:<10}", 
        "Name".bold().cyan(), 
        "Size".bold().cyan(), 
        "Compressed".bold().cyan(), 
        "Method".bold().cyan(), 
        "Encrypted".bold().cyan(), 
        "CRC32".bold().cyan()
    );
    println!("{}", "-".repeat(95).dimmed());

    for i in 0..archive.len() {
        let entry = archive.by_index_raw(i).unwrap();
        let name = entry.name();
        let size = entry.size();
        let compressed_size = entry.compressed_size();
        let method = entry.compression();
        let crc = entry.crc32();
        let extra = entry.extra_data();
        
        let mut is_aes = false;
        let mut j = 0;
        while j + 4 <= extra.len() {
            let tag = u16::from_le_bytes([extra[j], extra[j+1]]);
            let esize = u16::from_le_bytes([extra[j+2], extra[j+3]]);
            if tag == 0x9901 {
                is_aes = true;
                break;
            }
            j += 4 + esize as usize;
        }

        let mut encrypted_str = "No".normal();
        if is_aes {
            encrypted_str = "AES".yellow().bold();
        } else {
            let f = File::open(&file).unwrap();
            let mut test_archive = ZipArchive::new(f).unwrap();
            if matches!(test_archive.by_index(i), Err(ZipError::UnsupportedArchive(ZipError::PASSWORD_REQUIRED))) {
                encrypted_str = "ZipCrypto".red().bold();
            }
        }

        println!("{:<30} {:<12} {:<12} {:<12} {:<10} {:08X}", 
            name, size, compressed_size, format!("{:?}", method), encrypted_str, crc);
    }
}

pub fn run_kpa_attack(file: String, plaintext: Option<String>, cipher_entry: Option<String>, template: Option<String>, offset: i64, recover: bool, output: Option<String>) {
    crate::info!("Known-Plaintext Attack (KPA) mode");
    
    if Command::new("bkcrack").arg("--version").output().is_err() {
        crate::error!("'bkcrack' not found in system PATH.");
        return;
    }

    let mut bk_args = vec!["-C".to_string(), file.clone()];
    
    // Find target entry if not specified
    let target = match cipher_entry {
        Some(c) => c,
        None => {
            let f = File::open(&file).unwrap();
            let mut archive = ZipArchive::new(f).unwrap();
            let mut found = None;
            for i in 0..archive.len() {
                let entry = archive.by_index_raw(i).unwrap();
                let f2 = File::open(&file).unwrap();
                let mut test_archive = ZipArchive::new(f2).unwrap();
                if matches!(test_archive.by_index(i), Err(ZipError::UnsupportedArchive(ZipError::PASSWORD_REQUIRED))) {
                    found = Some(entry.name().to_string());
                    break;
                }
            }
            match found {
                Some(f) => {
                    crate::warn!("No cipher entry specified, auto-picked: {}", f);
                    f
                },
                None => {
                    crate::error!("No encrypted ZipCrypto entries found.");
                    return;
                }
            }
        }
    };
    bk_args.push("-c".to_string());
    bk_args.push(target);

    let mut run_bk = false;
    let mut p_temp_file: Option<String> = None;

    if let Some(tmpl_name) = template {
        if let Some(tmpl) = KPA_TEMPLATES.iter().find(|t| t.name == tmpl_name) {
            crate::info!("Using template: {}", tmpl.name);
            let p_file = format!("p_{}.bin", tmpl.name);
            let mut f = File::create(&p_file).unwrap();
            f.write_all(tmpl.signature).unwrap();
            
            bk_args.push("-p".to_string());
            bk_args.push(p_file.clone());
            bk_args.push("-o".to_string());
            bk_args.push(offset.to_string());
            p_temp_file = Some(p_file);
            run_bk = true;
        }
    } else if let Some(p_path) = plaintext {
        if p_path.to_lowercase().ends_with(".zip") {
            bk_args.push("-P".to_string());
            bk_args.push(p_path);
        } else {
            bk_args.push("-p".to_string());
            bk_args.push(p_path);
        }
        bk_args.push("-o".to_string());
        bk_args.push(offset.to_string());
        run_bk = true;
    } else {
        crate::error!("Either --plaintext or --template must be specified.");
    }

    if run_bk {
        crate::info!("Running bkcrack...");
        let bk_output = Command::new("bkcrack").args(&bk_args).output().expect("Failed to execute bkcrack");
        let stdout = String::from_utf8_lossy(&bk_output.stdout);
        println!("{}", stdout);

        if let Some(keys) = parse_keys(&stdout) {
            crate::success!("Keys found: {} {} {}", keys[0].green(), keys[1].green(), keys[2].green());
            
            let out_path = output.unwrap_or_else(|| format!("{}.decrypted.zip", file));
            crate::info!("Decrypting archive to: {}", out_path);
            
            let decrypt_output = Command::new("bkcrack")
                .args(["-C", &file, "-k", &keys[0], &keys[1], &keys[2], "-D", &out_path])
                .output()
                .expect("Failed to execute bkcrack for decryption");
            
            if decrypt_output.status.success() {
                crate::success!("Success! Decrypted ZIP saved to: {}", out_path);
            } else {
                crate::error!("Decryption failed.");
            }

            if recover {
                crate::info!("Attempting password recovery from keys...");
                let recover_output = Command::new("bkcrack")
                    .args(["-k", &keys[0], &keys[1], &keys[2], "-r", "1..12", "?p"])
                    .output()
                    .expect("Failed to execute bkcrack for password recovery");
                
                let recover_stdout = String::from_utf8_lossy(&recover_output.stdout);
                if let Some(pwd_line) = recover_stdout.lines().find(|l| l.starts_with("Password: ") || l.starts_with("as text: ")) {
                    crate::success!("Original password found: {}", pwd_line.replace("Password: ", "").replace("as text: ", "").trim().bold().green());
                } else {
                    crate::warn!("Password recovery finished. Check bkcrack output for results.");
                    println!("{}", recover_stdout);
                }
            }
        } else {
            crate::error!("Keys not found.");
        }

        if let Some(p) = p_temp_file {
            std::fs::remove_file(p).ok();
        }
    }
}
