use std::{
    io::{self, Write},
    env,
    time::Duration,
};
use reqwest::{Client, ClientBuilder, Error};
use colored::*;
use serde_json::Value;
use serde::Deserialize;
use semver::Version;

// Reusable function that just prints success messages to the console
fn print_info(text: &str, is_secondary: bool) {
    if is_secondary {
        println!("{}", text.green().italic().dimmed());
    } else {
        println!("{}", text.green());
    };
}

// Prints the AdGuardian ASCII art to console
fn print_ascii_art() {
    let art = r"
 █████╗ ██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
███████║██║  ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
██╔══██║██║  ██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
██║  ██║██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
";
    print_info(art, false);
    print_info("\nWelcome to AdGuardian Terminal Edition!", false);
    print_info("Terminal-based, real-time traffic monitoring and statistics for your AdGuard Home instance", true);
    print_info("For documentation and support, please visit: https://github.com/lissy93/adguardian-term", true);
}

// Print error message, along with (optional) stack trace, then exit
fn print_error(message: &str, sub_message: &str, error: Option<&Error>) {
    eprintln!(
        "{}{}{}",
        format!("{}", message).red(),
        match error {
            Some(err) => format!("\n{}", err).red().dimmed(),
            None => "".red().dimmed(),
        },
        format!("\n{}", sub_message).yellow(),
    );

    std::process::exit(1);
}

// Given a key, get the value from the environmental variables, and print it to the console
fn get_env(key: &str) -> Result<String, env::VarError> {
    env::var(key).map(|v| {
        println!(
            "{}",
            format!(
                "{} is set to {}",
                key.bold(),
                if key.contains("PASSWORD") { "******" } else { &v }
            )
            .green()
        );
        v
    })
}

// Given a possibly undefined version number, check if it's present and supported
fn check_version(version: Option<&str>) {
    let min_version = Version::parse("0.107.29").unwrap();
    
    match version {
        Some(version_str) => {
            let adguard_version = Version::parse(&version_str[1..]).unwrap();
            
            if adguard_version < min_version {
                print_error(
                    "AdGuard Home version is too old, and is now unsupported",
                    format!("You're running AdGuard {}. Please upgrade to v{} or later.", version_str, min_version.to_string()).as_str(),
                    None,
                );
            }
        },
        None => {
            print_error(
                "Unsupported AdGuard Home version",
                format!(
                    concat!(
                        "Failed to get the version number of your AdGuard Home instance.\n",
                        "This usually means you're running an old, and unsupported version.\n",
                        "Please upgrade to v{} or later."
                    ), min_version.to_string()
                ).as_str(),
                None,
            );
        }
    }
}

// With the users specified AdGuard details, verify the connection (exit on fail)
async fn verify_connection(
    client: &Client,
    ip: String,
    port: String,
    protocol: String,
    username: String,
    password: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "\nVerifying connection to your AdGuard instance...".blue());

    let auth_string = format!("{}:{}", username, password);
    let auth_header_value = format!("Basic {}", base64::encode(&auth_string));
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("Authorization", auth_header_value.parse()?);

    let url = format!("{}://{}:{}/control/status", protocol, ip, port);

    match client
        .get(&url)
        .headers(headers)
        .timeout(Duration::from_secs(2))
        .send()
        .await {
        Ok(res) if res.status().is_success() => {
            // Get version string (if present), and check if valid - exit if not
            let body: Value = res.json().await?;
            check_version(body["version"].as_str());
            // All good! Print success message :)
            let safe_version = body["version"].as_str().unwrap_or("mystery version");
            println!("{}", format!("AdGuard ({}) connection successful!\n", safe_version).green());
            Ok(())
        }
        // Connection failed to authenticate. Print error and exit
        Ok(_) => {
            print_error(
                &format!("Authentication with AdGuard at {}:{} failed", ip, port),
                "Please check your environmental variables and try again.",
                None,
            );
            Ok(())
        },
        // Connection failed to establish. Print error and exit
        Err(e) => {
            print_error(
                &format!("Failed to connect to AdGuard at: {}:{}", ip, port),
                "Please check your environmental variables and try again.",
                Some(&e),
            );
            Ok(())
        }
    }
}

#[derive(Deserialize)]
struct CratesIoResponse {
    #[serde(rename = "crate")]
    krate: Crate,
}

#[derive(Deserialize)]
struct Crate {
    max_version: String,
}

// Gets the latest version of the crate from crates.io
async fn get_latest_version(crate_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("https://crates.io/api/v1/crates/{}", crate_name);
    let client = reqwest::Client::new();
    let res = client.get(&url)
        .header(reqwest::header::USER_AGENT, "version_check (adguardian.as93.net)")
        .send()
        .await?;

    if res.status().is_success() {
        let response: CratesIoResponse = res.json().await?;
        Ok(response.krate.max_version)
    } else {
        let status = res.status();
        let body = res.text().await?;
        Err(format!("Request failed with status {}: body: {}", status, body).into())
    }
}

// Checks for updates to the crate, and prints a message if an update is available
async fn check_for_updates() {
    // Get crate name and version from Cargo.toml
    let crate_name = env!("CARGO_PKG_NAME");
    let crate_version = env!("CARGO_PKG_VERSION");
    println!("{}", "\nChecking for updates...".blue());
    // Parse the current version, and fetch and parse the latest version
    let current_version = Version::parse(crate_version).unwrap_or_else(|_| {
        Version::parse("0.0.0").unwrap()
    });
    let latest_version = Version::parse(
        &get_latest_version(crate_name).await.unwrap_or_else(|_| {
            "0.0.0".to_string()
        })
    ).unwrap();

    // Compare the current and latest versions, and print the appropriate message
    if current_version == Version::parse("0.0.0").unwrap() || latest_version == Version::parse("0.0.0").unwrap() {
        println!("{}", "Unable to check for updates".yellow());
    } else if current_version < latest_version {
        println!("{}",
            format!(
                "A new version of AdGuardian is available.\nUpdate from {} to {} for the best experience",
                current_version.to_string().bold(),
                latest_version.to_string().bold()
            ).yellow()
        );
    } else if current_version == latest_version {
        println!(
            "{}",
            format!("AdGuardian is up-to-date, running version {}", current_version.to_string().bold()).green()
        );
    } else if current_version > latest_version {
        println!(
            "{}",
            format!("Running a pre-released edition of AdGuardian, version {}", current_version.to_string().bold()).green()
        );
    } else {
        println!("{}", "Unable to check for updates".yellow());
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Construct a reqwest Client that allows invalid certificates and invalid hostnames
    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .timeout(Duration::from_secs(10))
        .build()?;
    
    // Print ascii art and welcome message
    print_ascii_art();

    // Read the user's AdGuard instance details from environment variables
    let adguard_ip = get_env("ADGUARD_IP")?;
    let adguard_port = get_env("ADGUARD_PORT")?;
    let adguard_protocol = get_env("ADGUARD_PROTOCOL")?;
    let adguard_username = get_env("ADGUARD_USERNAME")?;
    let adguard_password = get_env("ADGUARD_PASSWORD")?;

    // Verify connection to AdGuard instance
    verify_connection(&client, adguard_ip, adguard_port, adguard_protocol, adguard_username, adguard_password).await?;

    // Check for updates to AdGuardian on crates.io
    check_for_updates().await?;

    Ok(())
}
