use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use clap::Parser;
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

/// Subdomain Reconnaissance Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target domain to scan
    #[arg(index(1))]
    domain: String,

    /// Path to custom wordlist file
    #[arg(short, long)]
    wordlist: Option<String>,

    /// Number of threads to use
    #[arg(short, long, default_value_t = 10)]
    threads: usize,
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

fn load_wordlist(path: &Option<String>) -> Result<Vec<String>, std::io::Error> {
    match path {
        Some(file_path) => {
            let file = File::open(file_path)?;
            let reader = BufReader::new(file);
            
            let wordlist: Vec<String> = reader
                .lines()
                .filter_map(Result::ok)
                .filter(|line| !line.trim().is_empty())
                .collect();

            Ok(wordlist)
        },
        None => Ok(DEFAULT_WORDLIST.iter().map(|&s| s.to_string()).collect())
    }
}

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

    // Load wordlist
    let wordlist = load_wordlist(&args.wordlist)?;

    println!("{}", format!("Target Domain: {}", args.domain).yellow());
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
