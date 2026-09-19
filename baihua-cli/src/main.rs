//! The unified command-line entry point for the Baihua client, executable name is `baihua` (package name `baihua-cli`).
//!
//! The three ends' division of labor:
//! - Command line end (this program): the only end with command-line responsibilities,
//!   handling installation, uninstallation, updates, version reports,
//!   and directing users to the two interfaces;
//! - Graphical version `baihua-gui` (package `baihua-client-gui`) and terminal version `baihua-tui` (package `baihua-client-tui`):
//!   only start their respective interfaces, and each retains a read-only `version` subcommand
//!   (this program uses it to aggregate the versions of all installed ends);
//!   all other command-line responsibilities are absent.
//!
//! Running without any arguments (also applies when double-clicking the executable after download):
//! - If not all three ends are installed → directly enter the installation flow, installing
//!   the command line, graphical, and terminal ends at once;
//! - If all three ends are installed → print version information and prompt to start the
//!   interface with `baihua gui` / `baihua tui`.

use baihua_core::installer::{
    self, InstallReport, InstallRequest, current_prefix, default_prefix, extract_archive, install,
    install_from_command_line, uninstall_from_command_line,
};
use baihua_core::paths;
use baihua_core::update::{
    ReleaseChannel, ReleasePackage, UpdateCheck, check_for_update, download_package,
};
use std::path::PathBuf;
use std::process::Command;

/// The three ends of the client: command line (this program), graphical, terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientEnd {
    /// The command line end, which is this very program (`baihua`).
    CommandLine,
    /// The graphical end (`baihua-gui`).
    Graphical,
    /// The terminal end (`baihua-tui`).
    Terminal,
}

impl ClientEnd {
    /// The executable file name of this end after installation (Windows adds `.exe`).
    fn executable_name(self) -> String {
        match self {
            ClientEnd::CommandLine => installer::command_line_executable_name(),
            ClientEnd::Graphical => installer::graphical_executable_name(),
            ClientEnd::Terminal => installer::terminal_executable_name(),
        }
    }

    /// The release channel corresponding to this end: version reporting and update checks both follow the channel, each end checks independently.
    fn release_channel(self) -> ReleaseChannel {
        match self {
            ClientEnd::CommandLine => ReleaseChannel::CommandLine,
            ClientEnd::Graphical => ReleaseChannel::Graphical,
            ClientEnd::Terminal => ReleaseChannel::Terminal,
        }
    }

    /// The name used when displaying this end in the command line.
    fn display_name(self) -> &'static str {
        match self {
            ClientEnd::CommandLine => "command line",
            ClientEnd::Graphical => "graphical",
            ClientEnd::Terminal => "terminal",
        }
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(run_command_line(&arguments));
}

/// Dispatch subcommands. All command-line responsibilities for the three ends are collected in this one program, so every operation here is done only once.
fn run_command_line(arguments: &[String]) -> i32 {
    let Some(first_argument) = arguments.first() else {
        return run_without_arguments();
    };
    match first_argument.as_str() {
        "client" | "tui" => launch_interface(ClientEnd::Terminal),
        "gui" => launch_interface(ClientEnd::Graphical),
        "help" | "--help" | "-h" => {
            print_help();
            0
        }
        "version" | "--version" | "-V" => {
            print_version_report();
            0
        }
        "update" => run_update_command(&arguments[1..]),
        "install" => run_install_command(),
        "uninstall" => run_uninstall_command(),
        other => {
            eprintln!("unknown option: {other}");
            print_help();
            2
        }
    }
}

/// Behavior when run without arguments (double-click after download): if not fully installed, install directly; if installed, print the version and point the way.
fn run_without_arguments() -> i32 {
    if every_end_is_installed() {
        print_version_report();
        println!();
        println!("Start the graphical client with: baihua gui");
        println!("Start the terminal client with:  baihua tui");
        return 0;
    }
    println!("no complete client installation found; entering the installation flow");
    run_install_command()
}

/// Whether all three ends are installed in the default prefix. The release package is split by end, so after installation there may be only one or two ends present;
/// missing any end counts as "not fully installed", and running `baihua` again will fill in the gaps.
fn every_end_is_installed() -> bool {
    installed_executable_path(ClientEnd::CommandLine).is_some()
        && installed_executable_path(ClientEnd::Graphical).is_some()
        && installed_executable_path(ClientEnd::Terminal).is_some()
}

/// The path of this end in the default installation prefix; returns None if not installed.
fn installed_executable_path(end: ClientEnd) -> Option<PathBuf> {
    let prefix = default_prefix()?;
    let candidate = prefix.join("bin").join(end.executable_name());
    candidate.is_file().then_some(candidate)
}

/// Launch the interface of this end: prefer the one in the default installation prefix, then check the directory of this program (in the source tree all three ends are in the same directory),
/// finally check PATH. The exit code of the interface process is passed through unchanged.
fn launch_interface(end: ClientEnd) -> i32 {
    let executable_name = end.executable_name();
    let Some(executable_path) = locate_executable(end) else {
        eprintln!(
            "the {} client ({executable_name}) is not installed; run `baihua install` first",
            end.display_name()
        );
        return 1;
    };
    match Command::new(&executable_path).status() {
        Ok(status) => status.code().unwrap_or(0),
        Err(error) => {
            eprintln!("failed to start {}: {error}", executable_path.display());
            1
        }
    }
}

/// Find the executable of this end: the `bin/` of the default installation prefix, this program's directory and its parent's `bin/`, PATH.
fn locate_executable(end: ClientEnd) -> Option<PathBuf> {
    let file_name = end.executable_name();
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(prefix) = default_prefix() {
        candidates.push(prefix.join("bin").join(&file_name));
    }
    if let Ok(current_executable) = std::env::current_exe()
        && let Some(directory) = current_executable.parent()
    {
        candidates.push(directory.join(&file_name));
        if let Some(parent) = directory.parent() {
            candidates.push(parent.join("bin").join(&file_name));
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|directory| directory.join(&file_name)));
    }
    candidates.into_iter().find(|candidate| candidate.is_file())
}

/// Version report: this program's own version, core library version, installation location, and the versions reported by the two interface ends.
/// The interface end's version is obtained by running the installed executable and reading its `version` subcommand output,
/// without maintaining a separate version manifest file, so after replacing the binary the report reflects the currently installed version.
fn print_version_report() {
    println!("baihua {} (command line)", env!("CARGO_PKG_VERSION"));
    println!("baihua-core {}", baihua_core::core_version());
    match default_prefix() {
        Some(prefix) => println!("installation prefix: {}", prefix.display()),
        None => println!("installation prefix: unavailable (BAIHUA_DIR and HOME are both unset)"),
    }
    for end in [ClientEnd::Graphical, ClientEnd::Terminal] {
        match installed_end_version(end) {
            Some(version) => println!(
                "{} {} {}",
                end.display_name(),
                end.executable_name(),
                version
            ),
            None => println!(
                "{} {} not installed",
                end.display_name(),
                end.executable_name()
            ),
        }
    }
}

/// Run the installed end and take the last whitespace-separated field from the first line of its `version` output.
/// Both ends' first line is `<executable_name> <version>` (see their respective main.rs), so the last field is the version number.
fn installed_end_version(end: ClientEnd) -> Option<String> {
    let executable_path = installed_executable_path(end)?;
    let output = Command::new(&executable_path)
        .arg("version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let standard_output = String::from_utf8_lossy(&output.stdout);
    standard_output
        .lines()
        .next()?
        .split_whitespace()
        .last()
        .map(str::to_string)
}

/// Print all available subcommands and their descriptions.
fn print_help() {
    println!("baihua {} (command line)", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Usage: baihua [subcommand]");
    println!();
    println!("Running without a subcommand installs all three ends when the client is not");
    println!("installed yet; when it is installed it prints the version report and the way to");
    println!("start each interface. Subcommands:");
    let command_lines: Vec<(&str, &str)> = vec![
        ("gui", "Start the graphical interface (baihua-gui)"),
        ("tui", "Start the terminal interface (baihua-tui)"),
        ("client", "Same as tui"),
        ("help", "Print this help"),
        (
            "version",
            "Print the command line, graphical, terminal and core versions",
        ),
        (
            "update",
            "Check the three release channels separately and install what is newer; --check only reports",
        ),
        (
            "install",
            "Install the command line, graphical and terminal ends into the default prefix",
        ),
        (
            "uninstall",
            "Remove the three ends, asking about the configuration files",
        ),
    ];
    for (name, description) in command_lines {
        println!("  {name:<16} {description}");
    }
}

/// `install`: install every end found in this program's directory into the default prefix; for the ends not already installed, fetch them from the release page.
fn run_install_command() -> i32 {
    match install_from_command_line() {
        Ok(report) => {
            print_install_report(&report);
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

/// Installation report: which ends were installed, where the configuration was copied, and what else was done (PATH, the ends that were back-filled).
fn print_install_report(report: &InstallReport) {
    for executable_path in &report.executable_paths {
        println!("client executable: {}", executable_path.display());
    }
    println!(
        "configuration directory: {} ({} file(s) copied)",
        report.config_directory.display(),
        report.copied_file_count
    );
    for note in &report.notes {
        println!("{note}");
    }
}

/// `uninstall`: remove the three installed ends' executables, then ask whether to also remove the configuration and cache.
fn run_uninstall_command() -> i32 {
    match uninstall_from_command_line() {
        Ok(notes) => {
            for note in &notes {
                println!("{note}");
            }
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

/// `update`: each end checks its own channel; whoever has a newer version gets installed; `--check` only reports without installing.
/// The order is command line, graphical, terminal: if the command line package happens to include another end, the subsequent checks for the other two ends
/// will immediately upgrade them to their latest versions, rather than staying at the old version bundled in the package.
fn run_update_command(arguments: &[String]) -> i32 {
    let only_check = arguments.iter().any(|argument| argument == "--check");
    let mut exit_code = 0;
    for end in [
        ClientEnd::CommandLine,
        ClientEnd::Graphical,
        ClientEnd::Terminal,
    ] {
        exit_code = exit_code.max(update_one_end(end, only_check));
    }
    exit_code
}

/// Update one end: the current version comes from this program itself (for the command line end) or from the installed executable; ends that have never been installed only prompt to install first.
fn update_one_end(end: ClientEnd, only_check: bool) -> i32 {
    let current_version = match current_version_of(end) {
        Some(version) => version,
        None => {
            println!(
                "{} {} is not installed; run `baihua install` first",
                end.display_name(),
                end.executable_name()
            );
            return 0;
        }
    };
    match check_for_update(&current_version, end.release_channel()) {
        UpdateCheck::UpToDate {
            newest_tag,
            newest_assets,
        } => {
            println!(
                "{}: already up to date (current {current_version}, newest tag {newest_tag})",
                end.display_name()
            );
            if newest_assets.is_empty() {
                println!("  that tag has no published package");
            }
            0
        }
        UpdateCheck::Unavailable(reason) => {
            println!("{}: update check failed: {reason}", end.display_name());
            1
        }
        UpdateCheck::Available(package) => {
            println!(
                "{}: new version {} (package {})",
                end.display_name(),
                package.version,
                package.file_name
            );
            if only_check {
                return 0;
            }
            match download_and_install(end, &package) {
                Ok(report) => {
                    for executable_path in &report.executable_paths {
                        println!("  installed {}", executable_path.display());
                    }
                    for note in &report.notes {
                        println!("  {note}");
                    }
                    0
                }
                Err(error) => {
                    eprintln!("{}: update failed: {error}", end.display_name());
                    1
                }
            }
        }
    }
}

/// The version currently installed for this end: the command line end is this program's version; the two interface ends are obtained by running the installed executable.
/// Returns None if the interface end is not installed (`update` only prompts to run `baihua install` first).
fn current_version_of(end: ClientEnd) -> Option<String> {
    match end {
        ClientEnd::CommandLine => Some(env!("CARGO_PKG_VERSION").to_string()),
        ClientEnd::Graphical | ClientEnd::Terminal => installed_end_version(end),
    }
}

/// Installation prefix: if the default prefix already has the command line end, use it (all three ends are installed under the same prefix);
/// otherwise fall back to "the prefix where this process is" (in the source tree it is target/debug, in the download directory it is the download directory),
/// consistent with the command line end's own update behavior.
fn installation_prefix() -> Option<PathBuf> {
    if let Some(prefix) = default_prefix()
        && prefix
            .join("bin")
            .join(installer::command_line_executable_name())
            .is_file()
    {
        return Some(prefix);
    }
    current_prefix().or_else(default_prefix)
}

/// Download and immediately install a new version of this end: extract to the update directory and then install into the prefix.
/// The command line end has no interface to exit, so after installation it can proceed to the next end, and thus does not take the "spawn and wait for process" path.
fn download_and_install(end: ClientEnd, package: &ReleasePackage) -> Result<InstallReport, String> {
    let archive_path = download_package(package)?;
    let staging_root = paths::update_directory()
        .ok_or_else(|| "cannot locate the update directory".to_string())?;
    let staged_directory = staging_root.join(format!(
        "staged-{}-{}",
        end.executable_name(),
        package.version
    ));
    extract_archive(&archive_path, &staged_directory)?;
    let prefix = installation_prefix()
        .ok_or_else(|| "cannot determine the installation prefix".to_string())?;
    install(&InstallRequest {
        source_directory: staged_directory,
        prefix,
        wait_for_process: None,
    })
}
