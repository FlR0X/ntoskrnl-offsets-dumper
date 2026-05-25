use std::{
    collections::HashSet,
    fmt::{Display, Formatter, Result},
    path::Path,
    process::{Command, Output, Stdio},
};

use regex::Regex;

use crate::{constants, errors};

#[derive(Debug, serde::Serialize, Hash, Eq, PartialEq, Clone)]
pub struct OffsetsDump {
    pub kind: String,
    pub name: String,
    pub offset: String,
}

impl Display for OffsetsDump {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "[+] {} {} {}", self.kind, self.name, self.offset)
    }
}

pub struct Dumper;

impl Dumper {
    pub fn is_r2_installed() -> bool {
        Command::new(constants::RADARE_EXECUTABLE_NAME)
            .stdout(Stdio::null())
            .spawn()
            .is_ok()
    }

    pub fn is_r2_expected_version() -> bool {
        let radare_version: Output = Command::new(constants::RADARE_EXECUTABLE_NAME)
            .arg("-V")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();

        let stderr = String::from_utf8(radare_version.stderr).unwrap();

        if !stderr.is_empty() {
            return false;
        }

        let radare_output_version = Regex::new(constants::SEMANTIC_VERSIONING_REGEX)
            .unwrap()
            .captures_iter(&String::from_utf8(radare_version.stdout).unwrap())
            .filter_map(|cap| {
                match (cap.get(1), cap.get(2), cap.get(3)) {
                    (Some(major), Some(minor), Some(patch)) => Some((
                        major.as_str().parse::<i8>().unwrap(),
                        minor.as_str().parse::<i8>().unwrap(),
                        patch.as_str().parse::<i8>().unwrap(),
                    )),
                    _ => None,
                }
            })
            .next()
            .unwrap();

        let (major, minor, patch) = radare_output_version;

        println!("Radare2 Version: {}.{}.{}", major, minor, patch);

        major >= constants::EXPECTED_RADARE_MAJOR_VERSION
    }

    pub fn is_ntoskrnl_valid(ntoskrnl_path: &str) -> bool {
        let path = Path::new(ntoskrnl_path);
        path.exists() && path.is_file()
    }

    pub fn download_ntoskrnl_pdb(ntoskrnl_path: &str, verbose: bool) -> (bool, String) {
        let extracted_pdb: Output = Command::new(constants::RADARE_EXECUTABLE_NAME)
            .arg("-c idpd")
            .arg("-qq")
            .arg(ntoskrnl_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();

        let stderr = String::from_utf8_lossy(&extracted_pdb.stderr).to_string();
        let stdout = String::from_utf8_lossy(&extracted_pdb.stdout).to_string();

        if verbose && !stderr.is_empty() {
            eprintln!("[VERBOSE] radare2 idpd stderr:\n{}", stderr);
        }

        if stderr.contains("File already downloaded") {
            return (true, stdout.trim().to_string());
        }

        if !stderr.is_empty() {
            eprintln!("[WARN] Radare2 PDB download stderr: {}", stderr);
            return (true, stdout.trim().to_string());
        }

        (true, stdout.trim().to_string())
    }

    pub fn fetch_ntoskrnl_info(
        ntoskrnl_path: &str,
    ) -> core::result::Result<String, errors::OffsetDumperError> {
        let radare_ntoskrnl_file_version: Output = Command::new(constants::RADARE_EXECUTABLE_NAME)
            .arg("-c iV")
            .arg("-qq")
            .arg(ntoskrnl_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();

        let stderr = String::from_utf8(radare_ntoskrnl_file_version.stderr).unwrap();

        if !stderr.is_empty() {
            return Err(errors::OffsetDumperError::NtoskrnlDownloadingPdbError);
        }

        let stdout = String::from_utf8(radare_ntoskrnl_file_version.stdout).unwrap();

        let extracted_ntoskrnl_file_version = stdout
            .lines()
            .filter(|&line| line.trim().starts_with(constants::EXPECTED_FILE_VERSION_INFO))
            .collect::<Vec<&str>>();

        if extracted_ntoskrnl_file_version.is_empty() {
            return Err(errors::OffsetDumperError::NtoskrnlVersionNotFoundError);
        }

        Ok(extracted_ntoskrnl_file_version
            .last()
            .unwrap()
            .replace(constants::EXPECTED_FILE_VERSION_INFO, "")
            .trim()
            .to_string())
    }

    pub fn dump_ntoskrnl_symbols(
        ntoskrnl_path: &str,
        custom_pdb: Option<&str>,
        verbose: bool,
    ) -> core::result::Result<Vec<OffsetsDump>, errors::OffsetDumperError> {
        let mut cmd = Command::new(constants::RADARE_EXECUTABLE_NAME);
        cmd.arg("-qq").arg("-B 0");

        if let Some(pdb_path) = custom_pdb {
            let pdb_file = Path::new(pdb_path);
            if !pdb_file.exists() {
                return Err(errors::OffsetDumperError::PdbFileNotFoundError);
            }
            cmd.arg("-c").arg(format!("idp {}", pdb_path));
            if verbose {
                eprintln!("[VERBOSE] Loading custom PDB: {}", pdb_path);
            }
        }

        cmd.arg("-c").arg("idpi");
        cmd.arg(ntoskrnl_path);

        if verbose {
            eprintln!("[VERBOSE] Running radare2 command: {:?}", cmd);
        }

        let extracted_pdb: Output = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();

        let stderr = String::from_utf8(extracted_pdb.stderr).unwrap();
        if verbose && !stderr.is_empty() {
            eprintln!("[VERBOSE] radare2 stderr:\n{}", stderr);
        }

        if !stderr.is_empty() && !stderr.contains("invalid type") {
            return Err(errors::OffsetDumperError::NtoskrnlDumpingOffsetsError);
        }

        let mut last_parsed_struct: &str = "";
        let mut unique_offsets = HashSet::new();
        let mut result = Vec::new();

        for line in String::from_utf8(extracted_pdb.stdout)
            .unwrap()
            .lines()
            .filter(|&line| {
                if line.contains("struct _") && !line.contains(" struct") {
                    last_parsed_struct = line;
                }
                constants::EXPECTED_SYMBOLS
                    .iter()
                    .any(|&s| line.contains(s[0]) && last_parsed_struct.contains(s[1]))
            })
        {
            let offsets = Regex::new(constants::OFFSETS_REGEX)
                .unwrap()
                .captures(line)
                .unwrap();
            let offset = offsets[0].to_string();
            let index_element = constants::EXPECTED_SYMBOLS
                .iter()
                .position(|&i| line.contains(i[0]))
                .unwrap();
            let splitted_line: Vec<&str> =
                constants::EXPECTED_SYMBOLS[index_element][0].split(" ").collect();

            let kind: String = splitted_line[0..splitted_line.len() - 1].join(" ");
            let name: String =
                splitted_line[splitted_line.len() - 1..splitted_line.len()][0].to_string();

            let entry = OffsetsDump { kind, name, offset };

            if unique_offsets.insert(entry.clone()) {
                result.push(entry);
            }
        }

        if result.is_empty() {
            return Err(errors::OffsetDumperError::NtoskrnlDumpingOffsetsError);
        }

        if verbose && result.len() != constants::EXPECTED_SYMBOLS.len() {
            eprintln!(
                "[VERBOSE] Warning: Expected {} unique offsets, got {}",
                constants::EXPECTED_SYMBOLS.len(),
                result.len()
            );
        }

        Ok(result)
    }

    pub fn dump_all_symbols(
        ntoskrnl_path: &str,
        custom_pdb: Option<&str>,
        verbose: bool,
    ) -> core::result::Result<Vec<String>, errors::OffsetDumperError> {
        let mut cmd = Command::new(constants::RADARE_EXECUTABLE_NAME);
        cmd.arg("-qq").arg("-B 0");

        if let Some(pdb_path) = custom_pdb {
            let pdb_file = Path::new(pdb_path);
            if !pdb_file.exists() {
                return Err(errors::OffsetDumperError::PdbFileNotFoundError);
            }
            cmd.arg("-c").arg(format!("idp {}", pdb_path));
            if verbose {
                eprintln!("[VERBOSE] Loading custom PDB: {}", pdb_path);
            }
        }

        cmd.arg("-c").arg("idpi");
        cmd.arg(ntoskrnl_path);

        if verbose {
            eprintln!("[VERBOSE] Running radare2 command (all symbols): {:?}", cmd);
        }

        let extracted_pdb: Output = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();

        let stderr = String::from_utf8(extracted_pdb.stderr).unwrap();
        if verbose && !stderr.is_empty() {
            eprintln!("[VERBOSE] radare2 stderr:\n{}", stderr);
        }

        if !stderr.is_empty() && !stderr.contains("invalid type") {
            return Err(errors::OffsetDumperError::NtoskrnlDumpingOffsetsError);
        }

        let stdout = String::from_utf8(extracted_pdb.stdout).unwrap();
        let lines: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();

        if lines.is_empty() {
            return Err(errors::OffsetDumperError::NtoskrnlDumpingOffsetsError);
        }

        Ok(lines)
    }
}