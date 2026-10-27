use clap::{Args, Parser, Subcommand, ValueEnum};
use std::process::Command as ProcessCommand;
use std::process::Stdio;
use url::Url;
use std::fs;

// define Parser
#[derive(Debug, Parser)]
#[command(no_binary_name = true, bin_name = "")]
pub struct Cli {
    #[command(subcommand)]
    instruction: Instruction,
}

// base instructions
#[derive(Debug, Subcommand)]
enum Instruction {
    Scan(ScanArgs),
    Show(ShowArgs),

    Set {
        #[command(subcommand)]
        instruction: SetInstruction,
    },
}

#[derive(Debug, Args)]
struct ScanArgs {
    target: String,
    mode: ScanMode,
}

#[derive(Debug, Clone, ValueEnum)]
enum ScanMode {
    Files,
    Dirs,
    Subs,
    Nmap,
    Endpoint,
    Recon,
}

#[derive(Debug, Args)]
struct ShowArgs {
    target: String,
    mode: DisplayMode,
}

#[derive(Debug, Clone, ValueEnum)]
enum DisplayMode {
    Files,
    Dirs,
    Subs,
    Nmap,
    All,
}

#[derive(Debug, Subcommand)]
enum SetInstruction {
    New {
        #[command(subcommand)]
        instruction: SetNewInstruction,
    },
}

#[derive(Debug, Subcommand)]
enum SetNewInstruction {
    Scan {
        scan: String,
    },
}

fn parse_target(target: &str) -> Result<Url, url::ParseError> {
    let input = if target.contains("://") {
        target.to_owned()
    } else {
        format!("http://{target}")
    };

    let url = Url::parse(&input)?;

    if matches!(url.scheme(), "http" | "https") {
        Ok(url)
    } else {
        Err(url::ParseError::RelativeUrlWithoutBase)
    }
}

struct Parameters<'a> {
    target: &'a str,
    hostname: &'a str,
    wordlist: &'a str,
    scan_type: &'a str,
}

impl<'a> Default for Parameters<'a>{
    fn default() -> Self {
        Self{
            target: "{target-not-specified}",
            hostname: "{hostname-not-specified}",
            wordlist: "{wordlist-not-specified}",
            scan_type: "{type-not-specified}",
        }
    }
}

fn process_command(command: &str, args: &Vec<&str>, outfile_path: String, params: Parameters){
    let evaluated_outfile_path = outfile_path.replace("{type}", params.scan_type);
    let evaluated_args: Vec<String> = args.iter()
        .map(|string| {
            string.replace("{target}", params.target)
                .replace("{hostname}", params.hostname)
                .replace("{wordlist}", params.wordlist)
                .replace("{outfile}", &evaluated_outfile_path[..])
        })
        .collect();
    let _result = ProcessCommand::new(command)
        .args(evaluated_args)
        .stderr(Stdio::null())
        //.stdout(Stdio::null())
        .spawn()
        .expect("Command failed");
}

fn display_file(file_path: String, params: Parameters){
    let evaluated_file_path = file_path.replace("{type}", params.scan_type);
    let file_content = match fs::read_to_string(evaluated_file_path){
        Ok(handle) => handle,
        Err(error) => {
            println!("Could not open file: {error}.");
            return
        }
    };
    println!("Content of the file:\n{}", file_content);
}

impl Cli {
    pub fn execute(&self) {
        // Variables common to all commands
        let outfile_path = "{root}/{scans_folder}/{scheme}_{host}{path}/{type}";
        let scans_folder = ".scans";

        let root_directory = match project_root::get_project_root() {
            Ok(root) => root,
            Err(error) => {
                println!("Problem while finding project root: {error}.");
                return
            }
        };
        let root_directory_str = match root_directory.to_str() {
            Some(root_str) => root_str,
            None => {
                println!("Problem while finding project root, could not find any.");
                return
            }
        };

        // Variables used for scans
        let command_scan= "echo";
        let args_scan_files_dirs = vec!["ffuf","-mc","all","-u","{target}FUZZ","-w","{wordlist}","-o","{outfile}","-of","json"];
        let wordlist_scan_files = "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt";

        // Variables used for display

        match &self.instruction {
            Instruction::Scan(args) => {
                let target_url = match parse_target(&args.target) {
                    Ok(url) => url,
                    Err(error) => {
                        println!("Error while parsing URL: {error}.");
                        return
                    }
                };
                let host_str = match target_url.host_str() {
                    Some(str) => str,
                    None => {
                        println!("Error while parsing Url, no host found.");
                        return
                    }
                };
                let evaluated_outfile_path = outfile_path.replace("{root}", root_directory_str)
                    .replace("{scans_folder}", scans_folder)
                    .replace("{scheme}", target_url.scheme())
                    .replace("{host}", &host_str.replace(".", "-")[..])
                    .replace("{path}", &target_url.path()[..]);

                match &args.mode {
                    ScanMode::Files => process_command(&command_scan, &args_scan_files_dirs, evaluated_outfile_path, Parameters {
                        target: target_url.as_str(),
                        hostname: host_str,
                        wordlist: wordlist_scan_files,
                        scan_type: "files",
                        ..Default::default()
                    }),
                    // After this point, nothing is being done, everything is just left as it is to
                    // complete later.
                    ScanMode::Dirs => println!("Dirs scan"),
                    ScanMode::Subs => println!("Subs scan"),
                    ScanMode::Nmap => println!("Nmap scan"),
                    ScanMode::Endpoint => println!("Endpoint scan"),
                    ScanMode::Recon => println!("Recon scan"),
                }
            }

            Instruction::Show(args) => {
                let target_url = match parse_target(&args.target) {
                    Ok(url) => url,
                    Err(error) => {
                        println!("Error while parsing: {error}.");
                        return;
                    }
                };
                let host_str = match target_url.host_str() {
                    Some(str) => str,
                    None => {
                        println!("Error while parsing Url, no host found.");
                        return
                    }
                };
                let evaluated_outfile_path = outfile_path.replace("{root}", root_directory_str)
                    .replace("{scans_folder}", scans_folder)
                    .replace("{scheme}", target_url.scheme())
                    .replace("{host}", host_str)
                    .replace("{path}", &target_url.path()[..]);

                match &args.mode {
                    DisplayMode::Files => display_file(evaluated_outfile_path, Parameters {
                        scan_type: "files",
                        ..Default::default()
                    }),
                    DisplayMode::Dirs => println!("Not implemented yet."),
                    DisplayMode::Subs => println!("Not implemented yet."),
                    DisplayMode::Nmap => println!("Not implemented yet."),
                    DisplayMode::All => println!("Not implemented yet."),
                }
            }

            Instruction::Set { instruction } => match instruction {
                SetInstruction::New { instruction } => match instruction {
                    SetNewInstruction::Scan { scan } => {
                        println!("Creating scan: {scan}");
                    }
                },
            },
        }
    }
}
