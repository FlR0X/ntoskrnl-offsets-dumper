use std::io::stdin;

use clap::Parser;

use crate::dumper::Dumper;

mod constants;
mod dumper;
mod errors;

pub type NtoskrnlOffsetsResult<A> = core::result::Result<A, errors::OffsetDumperError>;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    ntoskrnl: Option<String>,

    #[arg(short, long)]
    pdb: Option<String>,

    #[arg(short, long)]
    json: bool,

    #[arg(short, long)]
    verbose: bool,

    #[arg(short, long)]
    all: bool,
}

fn print_error_and_exit(error: errors::OffsetDumperError, exit_code: i32) -> ! {
    eprintln!("Error: {}", error);
    std::process::exit(exit_code);
}

fn main() {
    let cli = Cli::parse();

    let ntoskrnl_path = cli
        .ntoskrnl
        .unwrap_or_else(|| constants::NTOSKRNL_DEFAULT_EXECUTABLE_FILE.to_string());

    if cli.verbose {
        eprintln!("[VERBOSE] Using ntoskrnl.exe: {}", ntoskrnl_path);
        if let Some(ref pdb) = cli.pdb {
            eprintln!("[VERBOSE] Using custom PDB: {}", pdb);
        }
        if cli.all {
            eprintln!("[VERBOSE] Dumping ALL symbols (--all enabled)");
        }
    }

    if !Dumper::is_r2_installed() {
        print_error_and_exit(errors::OffsetDumperError::Radare2NotFoundError, 127);
    }

    if !Dumper::is_r2_expected_version() {
        print_error_and_exit(errors::OffsetDumperError::Radare2VersionError, 1);
    }

    if !Dumper::is_ntoskrnl_valid(&ntoskrnl_path) {
        print_error_and_exit(errors::OffsetDumperError::NtoskrnlNotValidError, 1);
    }

    if cli.pdb.is_none() {
        match Dumper::download_ntoskrnl_pdb(&ntoskrnl_path, cli.verbose) {
            (true, message) => {
                println!("Downloading {}", message);
            }
            (false, _) => {
                eprintln!("Warning: Could not download PDB, but attempting to continue...");
            }
        }
    } else if cli.verbose {
        eprintln!("[VERBOSE] Skipping PDB download (using custom PDB)");
    }

    match Dumper::fetch_ntoskrnl_info(&ntoskrnl_path) {
        Ok(version) => {
            println!("Ntoskrnl Version: {}", version);
        }
        Err(_) => {
            print_error_and_exit(errors::OffsetDumperError::NtoskrnlVersionNotFoundError, 1);
        }
    }

    if cli.all {
        match Dumper::dump_all_symbols(&ntoskrnl_path, cli.pdb.as_deref(), cli.verbose) {
            Ok(lines) => {
                if cli.json {
                    let json_output = serde_json::to_string_pretty(&lines).unwrap();
                    println!("{}", json_output);
                } else {
                    println!("All symbols (raw radare2 output):\n");
                    for line in lines {
                        println!("{}", line);
                    }
                }
            }
            Err(e) => {
                print_error_and_exit(e, 1);
            }
        }
    } else {
        match Dumper::dump_ntoskrnl_symbols(&ntoskrnl_path, cli.pdb.as_deref(), cli.verbose) {
            Ok(offset_dump) => {
                if cli.json {
                    let json_output = serde_json::to_string_pretty(&offset_dump).unwrap();
                    println!("{}", json_output);
                } else {
                    println!("Offsets:");
                    for item in offset_dump {
                        println!("{}", item);
                    }
                }
            }
            Err(e) => {
                print_error_and_exit(e, 1);
            }
        }
    }

    if !cli.json {
        println!("\nPress ENTER to exit.");
        stdin().read_line(&mut String::new()).unwrap();
    }
}