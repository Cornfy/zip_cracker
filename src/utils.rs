use std::path::Path;
use filetime::{FileTime, set_file_mtime};
use colored::Colorize;

#[macro_export]
macro_rules! success {
    ($($arg:tt)*) => {
        {
            use colored::Colorize;
            println!("{} {}", "[+]".green().bold(), format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        {
            use colored::Colorize;
            println!("{} {}", "[*]".blue().bold(), format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        {
            use colored::Colorize;
            eprintln!("{} {}", "[-]".red().bold(), format!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        {
            use colored::Colorize;
            println!("{} {}", "[!]".yellow().bold(), format!($($arg)*));
        }
    };
}

pub fn sync_time(path: &Path, mtime: zip::DateTime) {
    let year = mtime.year() as i32;
    let month = mtime.month() as u32;
    let day = mtime.day() as u32;
    let hour = mtime.hour() as u32;
    let minute = mtime.minute() as u32;
    let second = mtime.second() as u32;

    use time::{Date, Month, PrimitiveDateTime, Time};
    let month_enum = match month {
        1 => Month::January, 2 => Month::February, 3 => Month::March, 4 => Month::April,
        5 => Month::May, 6 => Month::June, 7 => Month::July, 8 => Month::August,
        9 => Month::September, 10 => Month::October, 11 => Month::November, 12 => Month::December,
        _ => Month::January,
    };

    if let Ok(date) = Date::from_calendar_date(year, month_enum, day as u8) {
        if let Ok(time) = Time::from_hms(hour as u8, minute as u8, second as u8) {
            let dt = PrimitiveDateTime::new(date, time);
            let unix = dt.assume_utc().unix_timestamp();
            let ft = FileTime::from_unix_time(unix, 0);
            if let Err(e) = set_file_mtime(path, ft) {
                eprintln!("{} Warning: Failed to sync time for {}: {}", "[-]".red().bold(), path.display(), e);
            }
        }
    }
}

pub fn parse_keys(output: &str) -> Option<Vec<String>> {
    for line in output.lines() {
        if line.contains("Keys:") || (line.contains("b1997f4e") && line.split_whitespace().count() == 3) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return Some(parts.iter().rev().take(3).rev().map(|s| s.to_string()).collect());
            }
        }
    }
    None
}
