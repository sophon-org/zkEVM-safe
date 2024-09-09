use clap::{Arg, Command};
use evm_disassembler::{disassemble_bytes, Operation};
use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use walkdir::WalkDir;
use reqwest::blocking::Client;

fn silent_disassemble_bytes(bytes: Vec<u8>, verbose: bool) -> Result<(Vec<Operation>, String), Box<dyn Error>> {
    if verbose {
        let operations = disassemble_bytes(bytes)?;
        return Ok((operations, String::new()));
    }

    let stdout = io::stdout();
    let stdout_fd = stdout.as_raw_fd();
    let mut pipe = [0; 2];
    unsafe {
        libc::pipe(pipe.as_mut_ptr());
        let old_stdout = libc::dup(stdout_fd);
        libc::dup2(pipe[1], stdout_fd);

        let result = disassemble_bytes(bytes);

        libc::dup2(old_stdout, stdout_fd);
        libc::close(old_stdout);
        libc::close(pipe[1]);

        let mut output = String::new();
        let mut reader = File::from_raw_fd(pipe[0]);
        reader.read_to_string(&mut output)?;

        match result {
            Ok(operations) => Ok((operations, output)),
            Err(e) => Err(e.into()),
        }
    }
}

fn fetch_bytecode_from_chain(rpc_url: &str, address: &str, verbose: bool) -> Result<String, Box<dyn Error>> {
    let client = Client::new();
    let params = format!(
        r#"{{"jsonrpc":"2.0","method":"eth_getCode","params":["{}", "latest"],"id":1}}"#,
        address
    );

    let response = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .body(params)
        .send()?;

    let response_json: Value = response.json()?;

    if let Some(bytecode) = response_json.get("result").and_then(Value::as_str) {
        if bytecode == "0x" {
            return Err("Contract not found at this address".into());
        }
        if verbose {
            println!("Fetched bytecode for address {}: {}", address, bytecode);
        }
        Ok(bytecode.to_string())
    } else {
        Err("Failed to fetch bytecode or unexpected response format".into())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = Command::new("bytecode_checker")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("Checks bytecode for incompatible opcodes")
        .arg(
            Arg::new("artifacts")
                .short('a')
                .long("artifacts")
                .value_name("TYPE")
                .help("Specify the project type: foundry or hardhat")
                .default_value("foundry"),
        )
        .arg(
            Arg::new("folder")
                .short('f')
                .long("folder")
                .value_name("FOLDER")
                .help("Specify the folder to scan [default: out for foundry, artifacts for hardhat]"),
        )
        .arg(
            Arg::new("json_path")
                .short('j')
                .long("json-path")
                .value_name("JSON_PATH")
                .help("Specify the JSON path to the bytecode object. [default: deployedBytecode.object]"),
        )
        .arg(
            Arg::new("address")
                .long("address")
                .value_name("ADDRESS")
                .help("Specify the contract address to fetch bytecode from"),
        )
        .arg(
            Arg::new("rpc_url")
                .long("rpc-url")
                .value_name("RPC_URL")
                .help("Specify the RPC URL to fetch bytecode [default: https://rpc.flashbots.net]")
                .default_value("https://rpc.flashbots.net")
                .requires("address"),
        )
        .arg(
            Arg::new("add_opcode")
                .short('A')
                .long("add-opcode")
                .value_name("OPCODE")
                .num_args(1..)
                .help("Add custom opcodes to the list of unsupported opcodes"),
        )
        .arg(
            Arg::new("remove_opcode")
                .short('R')
                .long("remove-opcode")
                .value_name("OPCODE")
                .num_args(1..)
                .help("Remove specific opcodes from the list of unsupported opcodes"),
        )
        .arg(
            Arg::new("info")
                .short('i')
                .long("info")
                .help("Display general information, including the list of unsupported opcodes")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose mode to print detailed error messages to the console")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    // Base unsupported opcodes
    let mut unsupported_opcodes = vec!["SELFDESTRUCT", "CALLCODE", "PC", "EXTCODECOPY"];

    // Add custom opcodes
    if let Some(opcodes) = matches.get_many::<String>("add_opcode") {
        for opcode in opcodes {
            unsupported_opcodes.push(opcode.as_str());
        }
    }

    // Remove specified opcodes
    if let Some(opcodes) = matches.get_many::<String>("remove_opcode") {
        let opcodes_vec: Vec<_> = opcodes.collect();
        unsupported_opcodes.retain(|op| !opcodes_vec.iter().any(|x| x == op));
    }

    // Display general info and exit if --info flag is used
    if matches.get_flag("info") {
        println!("General Info:\n");
        println!("Unsupported opcodes: {:?}\n", unsupported_opcodes);
        println!("Foundry folder: out");
        println!("Foundry JSON path: deployedBytecode.object\n");
        println!("Hardhat folder: artifacts");
        println!("Hardhat JSON path: deployedBytecode\n");
        return Ok(());
    }

    let project_type = matches.get_one::<String>("artifacts").unwrap();
    let folder = matches
        .get_one::<String>("folder")
        .map(String::as_str)
        .unwrap_or_else(|| match project_type.as_str() {
            "hardhat" => "artifacts",
            _ => "out",
        });
    let json_path = matches
        .get_one::<String>("json_path")
        .map(String::as_str)
        .unwrap_or_else(|| match project_type.as_str() {
            "hardhat" => "deployedBytecode",           // Example path for Hardhat
            "foundry" => "deployedBytecode.object",    // Example path for Foundry
            _ => "deployedBytecode.object",            // Default fallback
        });

    let verbose = matches.get_flag("verbose");
    let mut log_file = File::create("incompatible_opcodes.log")?;
    let mut error_log = String::new();
    let mut opcode_file_index = 1;
    let mut output_file_index = 1;
    let mut disassembler_logs = Vec::new();
    let mut is_zkevm_safe = true;
    let mut contracts_with_unsupported_opcodes = 0;

    // Check if fetching from blockchain (address provided)
    if let Some(address) = matches.get_one::<String>("address") {
        let rpc_url = matches.get_one::<String>("rpc_url").unwrap();
        let bytecode = match fetch_bytecode_from_chain(rpc_url, address, verbose) {
            Ok(code) => code,
            Err(e) => {
                error_log.push_str(&format!("Error fetching bytecode for address {}: {}\n", address, e));
                if verbose {
                    eprintln!("Error fetching bytecode for address {}: {}", address, e);
                }
                return Ok(());
            }
        };

        // Process fetched bytecode
        let bytecode_without_prefix = bytecode.trim_start_matches("0x");
        let bytes = match hex::decode(bytecode_without_prefix) {
            Ok(b) => b,
            Err(e) => {
                error_log.push_str(&format!("Error decoding bytecode for address {}: {}\n", address, e));
                if verbose {
                    eprintln!("Error decoding bytecode for address {}: {}", address, e);
                }
                return Ok(());
            }
        };

        // Disassemble and process opcodes
        let (instructions, disassembler_output) = match silent_disassemble_bytes(bytes, verbose) {
            Ok((i, output)) => (i, output),
            Err(e) => {
                error_log.push_str(&format!("Error disassembling bytecode for address {}: {}\n", address, e));
                if verbose {
                    eprintln!("Error disassembling bytecode for address {}: {}", address, e);
                }
                return Ok(());
            }
        };

        // Check for incompatible opcodes
        let mut found_incompatible = HashSet::new();
        for instruction in &instructions {
            if unsupported_opcodes.contains(&format!("{:?}", instruction.opcode).as_str()) {
                found_incompatible.insert(format!("{:?}", instruction.opcode));
            }
        }

        // Log incompatible opcodes
        if !found_incompatible.is_empty() {
            is_zkevm_safe = false;
            let opcode_string = found_incompatible.iter().cloned().collect::<Vec<_>>().join(" | ");
            let log_entry = format!("Bytecode from {}: {}\n", address, opcode_string);
            log_file.write_all(log_entry.as_bytes())?;
            if verbose {
                println!("{}", log_entry);
            }
        }

        // Log disassembler output
        if !disassembler_output.is_empty() {
            let error_string = disassembler_output
                .lines()
                .filter(|line| line.starts_with("Stop decoding"))
                .collect::<Vec<_>>()
                .join(" - Error: ");

            if !error_string.is_empty() {
                let output_log_entry = format!("Bytecode from {}: Error: {}\n", address, error_string);
                disassembler_logs.push(output_log_entry.clone());
                if verbose {
                    println!("{}", output_log_entry);
                }
            }
        }

        // Log the bytecode at the end
        log_file.write_all(b"\n--- Bytecode ---\n")?;
        log_file.write_all(format!("Bytecode: 0x{}\n", bytecode.trim_start_matches("0x")).as_bytes())?;        

        // Final results
        if is_zkevm_safe {
            println!("zkEVM safe!");
            println!("No unsupported opcodes found.");
        } else {
            println!("Not zkEVM safe!");
            println!("See logs for details: incompatible_opcodes.log");
        }

        return Ok(());
    }

    for entry in WalkDir::new(folder).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let mut found_incompatible = HashSet::new();
        let mut disassembler_output = String::new();

        if path.extension().map_or(false, |ext| ext == "json") {
            let file_content = fs::read_to_string(path)?;
            let json_value: Value = serde_json::from_str(&file_content)?;

            let mut bytecode_obj = &json_value;
            for key in json_path.split('.') {
                bytecode_obj = bytecode_obj.get(key).unwrap_or(&Value::Null);
            }

            if let Some(bytecode_str) = bytecode_obj.as_str() {
                let bytecode_without_prefix = bytecode_str.trim_start_matches("0x");
                let bytes = match hex::decode(bytecode_without_prefix) {
                    Ok(b) => b,
                    Err(e) => {
                        error_log.push_str(&format!(
                            "Error decoding hex in file {}: {}\n",
                            path.display(),
                            e
                        ));
                        if verbose {
                            eprintln!("Error decoding hex in file {}: {}", path.display(), e);
                        }
                        is_zkevm_safe = false;
                        continue;
                    }
                };

                let (instructions, output) = match silent_disassemble_bytes(bytes, verbose) {
                    Ok((i, output)) => (i, output),
                    Err(e) => {
                        error_log.push_str(&format!(
                            "Error disassembling bytecode in file {}: {}\n",
                            path.display(),
                            e
                        ));
                        if verbose {
                            eprintln!(
                                "Error disassembling bytecode in file {}: {}",
                                path.display(),
                                e
                            );
                        }
                        is_zkevm_safe = false;
                        continue;
                    }
                };

                disassembler_output = output;

                for instruction in &instructions {
                    if unsupported_opcodes.contains(&format!("{:?}", instruction.opcode).as_str()) {
                        found_incompatible.insert(format!("{:?}", instruction.opcode));
                    }
                }
            }

            if !found_incompatible.is_empty() {
                is_zkevm_safe = false;
                contracts_with_unsupported_opcodes += 1;
                let opcode_string = found_incompatible
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" | ");
                let log_entry = format!(
                    "{}. \"{}\": {}\n",
                    opcode_file_index,
                    path.display(),
                    opcode_string
                );

                log_file.write_all(log_entry.as_bytes())?;

                if verbose {
                    println!("{}", log_entry);
                }

                opcode_file_index += 1;
            }

            if !disassembler_output.is_empty() {
                let error_string = disassembler_output
                    .lines()
                    .filter(|line| line.starts_with("Stop decoding"))
                    .collect::<Vec<_>>()
                    .join(" - Error: ");

                if !error_string.is_empty() {
                    let output_log_entry = format!(
                        "{}. \"{}\": Error: {}\n",
                        output_file_index,
                        path.display(),
                        error_string
                    );

                    disassembler_logs.push(output_log_entry);
                    output_file_index += 1;
                    is_zkevm_safe = false;
                }
            }
        }
    }

    if !disassembler_logs.is_empty() {
        log_file.write_all(b"\n--- Disassembler Messages ---\n\n")?;
        for log in disassembler_logs {
            log_file.write_all(log.as_bytes())?;
            if verbose {
                println!("{}", log);
            }
        }
    }

    if !error_log.is_empty() {
        log_file.write_all(b"\n--- Errors Encountered ---\n\n")?;
        log_file.write_all(error_log.as_bytes())?;
    }

    if is_zkevm_safe {
        println!("zkEVM safe!");
        println!("No unsuported opcodes found: {:?}", unsupported_opcodes);
    } else {
        println!("Not zkEVM safe!");
        println!("{} contracts with unsupported opcodes in ./{}.", contracts_with_unsupported_opcodes, folder);
        println!("See logs for details: incompatible_opcodes.log");
    }

    Ok(())
}
