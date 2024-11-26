use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use clap::{Parser, ValueEnum};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};

// Default wordlist of subdomains
const DEFAULT_WORDLIST: &[&str] = &[
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
    "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx", "email",
    "cloud", "1", "2", "forum", "admin", "api", "cdn", "stage", "gw", "dns",
    "download", "demo", "dashboard", "app", "beta", "auth", "cms", "testing"
];

// Potential SecLists wordlist locations
const POTENTIAL_WORDLIST_PATHS: &[&str] = &[
    "/usr/share/wordlists/seclists/Discovery/DNS/",
    "/usr/share/seclists/Discovery/DNS/",
    "/opt/seclists/Discovery/DNS/",
    "/usr/local/share/seclists/Discovery/DNS/"
];

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum WordlistType {
    /// Light wordlist with 45 predefined subdomains
    Light,
    /// Top 5000 subdomains from SecLists
    Top5000,
    /// Top 20000 subdomains from SecLists
    Top20000,
    /// Top 110000 subdomains from SecLists
    Top110000,
    /// Custom wordlist file
    Custom,
}

/// Subdomain Reconnaissance Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target domain to scan
    #[arg(index(1))]
    domain: String,

    /// Wordlist type to use
    #[arg(short, long, value_enum, default_value_t = WordlistType::Light)]
    wordlist: WordlistType,

    /// Custom path to SecLists wordlist directory
    #[arg(long, env = "SECLISTS_PATH")]
    seclists_path: Option<String>,

    /// Path to custom wordlist file (used only when wordlist type is Custom)
    #[arg(short, long, requires = "custom")]
    custom_wordlist: Option<String>,

    /// Number of threads to use
    #[arg(short, long, default_value_t = 10)]
    threads: usize,
}

/// Find the first existing SecLists wordlist directory
fn find_seclists_path(custom_path: &Option<String>) -> Option<PathBuf> {
    // First, check if a custom path was provided
    if let Some(path) = custom_path {
        let custom_pathbuf = PathBuf::from(path);
        if custom_pathbuf.exists() {
            return Some(custom_pathbuf);
        }
    }

    // If no custom path or custom path doesn't exist, try predefined paths
    for potential_path in POTENTIAL_WORDLIST_PATHS {
        let path = Path::new(potential_path);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    None
}

fn print_banner() {
    let banner = r#"
███████╗██╗   ██╗██████╗       ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗
██╔════╝██║   ██║██╔══██╗     ██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
███████╗██║   ██║██████╔╝     ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
╚════██║██║   ██║██╔══██╗     ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
███████║╚██████╔╝██████╔╝     ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚══════╝ ╚═════╝ ╚═════╝       ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
"#;
    println!("{}", banner.blue());
    println!("{}", "                 [ By Sylar ]".red());
    println!("{}", "         🔍 Subdomain Reconnaissance Tool 🎯".green());
    println!("============================================================================================");
}


fn load_wordlist(
    wordlist_type: &WordlistType,
    custom_path: &Option<String>,
    seclists_path: &Option<String>
) -> Result<Vec<String>, std::io::Error> {
    match wordlist_type {
        WordlistType::Light => {
            Ok(DEFAULT_WORDLIST.iter().map(|&s| s.to_string()).collect())
        },
        WordlistType::Top5000 |
        WordlistType::Top20000 |
        WordlistType::Top110000 => {
            // Determine the filename based on wordlist type
            let filename = match wordlist_type {
                WordlistType::Top5000 => "subdomains-top1million-5000.txt",
                WordlistType::Top20000 => "subdomains-top1million-20000.txt",
                WordlistType::Top110000 => "subdomains-top1million-110000.txt",
                _ => unreachable!()
            };

            // Find a valid SecLists path
            let seclists_base_path = find_seclists_path(seclists_path)
                .ok_or_else(|| std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Could not find SecLists wordlist directory. \
                    Please install SecLists or provide a custom path using --seclists-path"
                ))?;

            let wordlist_path = seclists_base_path.join(filename);

            // Load the wordlist
            load_wordlist_from_file(&wordlist_path.to_string_lossy())
        },
        WordlistType::Custom => {
            match custom_path {
                Some(file_path) => load_wordlist_from_file(file_path),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Custom wordlist path must be provided when using Custom wordlist type"
                ))
            }
        }
    }
}

// Helper function to load wordlist from a file
fn load_wordlist_from_file(file_path: &str) -> Result<Vec<String>, std::io::Error> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Wordlist not found at path: {}", file_path)
        ));
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let wordlist: Vec<String> = reader
        .lines()
        .filter_map(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .collect();

    Ok(wordlist)
}

// ... [rest of the previous implementation remains the same]
fn check_subdomain(subdomain: &str, domain: &str) -> Option<String> {
    let hostname = format!("{}.{}", subdomain, domain);

    // Attempt to resolve the hostname
    match format!("{}:80", hostname).to_socket_addrs() {
        Ok(_) => Some(hostname),
        Err(_) => None
    }
}

fn scan_subdomains(domain: &str, wordlist: &[String], max_threads: usize) -> Vec<String> {
    let found_domains = Arc::new(Mutex::new(HashSet::new()));
    let progress_bar = ProgressBar::new(wordlist.len() as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .expect("Invalid progress bar template")
            .progress_chars("#>-")
    );

    let mut handles = vec![];

    // Split wordlist into chunks for threading
    let chunk_size = (wordlist.len() + max_threads - 1) / max_threads;

    for chunk in wordlist.chunks(chunk_size) {
        let chunk = chunk.to_vec();
        let domain = domain.to_string();
        let found_domains = Arc::clone(&found_domains);
        let progress_bar = progress_bar.clone();

        let handle = thread::spawn(move || {
            for subdomain in chunk {
                if let Some(discovered_domain) = check_subdomain(&subdomain, &domain) {
                    let mut domains = found_domains.lock().unwrap();
                    domains.insert(discovered_domain);
                }
                progress_bar.inc(1);
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    progress_bar.finish_with_message("Scan complete!");

    // Convert Arc<Mutex<HashSet>> to sorted Vec
    let mut results: Vec<String> = found_domains.lock().unwrap().iter().cloned().collect();
    results.sort();
    results
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_banner();

    // Parse command-line arguments
    let args = Args::parse();

    // Load wordlist based on user selection
    let wordlist = load_wordlist(&args.wordlist, &args.custom_wordlist, &args.seclists_path)?;

    println!("{}", format!("Target Domain: {}", args.domain).yellow());
    println!("{}", format!("Wordlist Type: {:?}", args.wordlist).yellow());
    println!("{}", format!("Wordlist Size: {} entries", wordlist.len()).yellow());
    println!("{}", "Starting scan...".green());

    // Start timing
    let start_time = Instant::now();

    // Scan subdomains
    let found_domains = scan_subdomains(&args.domain, &wordlist, args.threads);

    // Print results
    println!("\n==================================================");
    println!("{}", "Scan Results".cyan());
    println!("{}", format!("Scan completed in {:.2} seconds", start_time.elapsed().as_secs_f64()).green());
    println!("{}", format!("Found {} subdomains:", found_domains.len()).green());

    for discovered_domain in found_domains {
        println!("{}", format!("  └─ {}", discovered_domain).magenta());
    }

    Ok(())
}

