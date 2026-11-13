//! Local, synthetic cost probe for the current Bitwarden master-key derivation.
//! It cannot establish full-provider latency or security assurance.

use std::{env, error::Error, fs, hint::black_box, str::FromStr, time::Instant};

use bweso_bitwarden::{derive_master_key, KdfConfig};
use serde_json::{json, Value};

const PASSWORD: &str = "synthetic-kdf-benchmark-password-not-a-real-secret";
const SALT: &str = "synthetic-benchmark@example.invalid";
const MAX_ROUNDS: usize = 20;
const MAX_ARGON2_MEMORY_MIB: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Pbkdf2,
    Argon2id,
    Both,
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "pbkdf2" => Ok(Self::Pbkdf2),
            "argon2id" => Ok(Self::Argon2id),
            "both" => Ok(Self::Both),
            _ => Err("mode must be pbkdf2, argon2id or both".to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Options {
    mode: Mode,
    rounds: usize,
    pbkdf2_iterations: u32,
    argon2_memory_mib: u32,
    argon2_iterations: u32,
    argon2_parallelism: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            mode: Mode::Both,
            rounds: 5,
            pbkdf2_iterations: 600_000,
            argon2_memory_mib: 64,
            argon2_iterations: 3,
            argon2_parallelism: 2,
        }
    }
}

impl Options {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut parsed = Self::default();
        let mut args = args.into_iter();
        while let Some(name) = args.next() {
            let value = args.next().ok_or_else(|| format!("{name} needs a value"))?;
            match name.as_str() {
                "--mode" => parsed.mode = value.parse()?,
                "--rounds" => parsed.rounds = parse_number(&value, &name)?,
                "--pbkdf2-iterations" => {
                    parsed.pbkdf2_iterations = parse_number(&value, &name)?;
                }
                "--argon2-memory-mib" => {
                    parsed.argon2_memory_mib = parse_number(&value, &name)?;
                }
                "--argon2-iterations" => {
                    parsed.argon2_iterations = parse_number(&value, &name)?;
                }
                "--argon2-parallelism" => {
                    parsed.argon2_parallelism = parse_number(&value, &name)?;
                }
                _ => return Err(format!("unrecognized option {name}")),
            }
        }
        if !(1..=MAX_ROUNDS).contains(&parsed.rounds) {
            return Err(format!("rounds must be between 1 and {MAX_ROUNDS}"));
        }
        if parsed.argon2_memory_mib > MAX_ARGON2_MEMORY_MIB {
            return Err(format!(
                "synthetic probe caps Argon2 memory at {MAX_ARGON2_MEMORY_MIB} MiB"
            ));
        }
        // Validate all supplied settings, even for the inactive algorithm:
        // the JSON report must never advertise an invalid configuration.
        KdfConfig::Pbkdf2Sha256 {
            iterations: parsed.pbkdf2_iterations,
        }
        .validate_for_prelogin()
        .map_err(|_| "PBKDF2 iterations outside supported prelogin bounds".to_string())?;
        KdfConfig::Argon2id {
            iterations: parsed.argon2_iterations,
            memory_mib: parsed.argon2_memory_mib,
            parallelism: parsed.argon2_parallelism,
        }
        .validate_for_prelogin()
        .map_err(|_| "Argon2 parameters outside supported prelogin bounds".to_string())?;
        Ok(parsed)
    }
}

fn parse_number<T: FromStr>(raw: &str, name: &str) -> Result<T, String> {
    raw.parse()
        .map_err(|_| format!("{name} requires a decimal integer"))
}

// Linux-only high-water RSS, in KiB. A missing or unsupported procfs field is
// null; no arbitrary estimate is substituted. Includes the whole probe process.
fn peak_rss_kib() -> Option<u64> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
}

fn kdf_sample(name: &str, config: &KdfConfig, rounds: usize) -> Result<Value, Box<dyn Error>> {
    let mut milliseconds = Vec::with_capacity(rounds);
    let rss_before = peak_rss_kib();
    for _ in 0..rounds {
        let started = Instant::now();
        let key = derive_master_key(PASSWORD, SALT, config)?;
        black_box(key.as_bytes());
        milliseconds.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    milliseconds.sort_by(f64::total_cmp);
    let n = milliseconds.len();
    // Nearest-rank estimate. Small n is explicitly disclosed to consumers.
    let p95_index = (n * 95).div_ceil(100) - 1;
    Ok(json!({
        "algorithm": name,
        "rounds": n,
        "unit": "milliseconds",
        "sampleMs": milliseconds,
        "medianMs": if n % 2 == 0 {
            (milliseconds[n / 2 - 1] + milliseconds[n / 2]) / 2.0
        } else {
            milliseconds[n / 2]
        },
        "p95NearestRankMs": milliseconds[p95_index],
        "peakProcessRssKiB": peak_rss_kib(),
        "peakProcessRssBeforeKiB": rss_before
    }))
}

fn run(args: impl IntoIterator<Item = String>) -> Result<Value, Box<dyn Error>> {
    let options = Options::parse(args)?;
    let mut measurements = Vec::new();
    if matches!(options.mode, Mode::Pbkdf2 | Mode::Both) {
        measurements.push(kdf_sample(
            "pbkdf2-sha256",
            &KdfConfig::Pbkdf2Sha256 {
                iterations: options.pbkdf2_iterations,
            },
            options.rounds,
        )?);
    }
    if matches!(options.mode, Mode::Argon2id | Mode::Both) {
        measurements.push(kdf_sample(
            "argon2id",
            &KdfConfig::Argon2id {
                iterations: options.argon2_iterations,
                memory_mib: options.argon2_memory_mib,
                parallelism: options.argon2_parallelism,
            },
            options.rounds,
        )?);
    }
    Ok(json!({
        "schemaVersion": 1,
        "scope": "synthetic master-key derivation only; excludes HTTP, vault refresh, cache, ESO and restart",
        "inputs": {
            "syntheticCredentials": true,
            "pbkdf2Iterations": options.pbkdf2_iterations,
            "argon2Iterations": options.argon2_iterations,
            "argon2MemoryMiB": options.argon2_memory_mib,
            "argon2Parallelism": options.argon2_parallelism
        },
        "runtime": {
            "os": env::consts::OS,
            "architecture": env::consts::ARCH,
            "parallelism": std::thread::available_parallelism().ok().map(|n| n.get()),
            "linuxCgroupCpuMax": fs::read_to_string("/sys/fs/cgroup/cpu.max")
                .ok().map(|text| text.trim().to_string()),
            "linuxCgroupMemoryMax": fs::read_to_string("/sys/fs/cgroup/memory.max")
                .ok().map(|text| text.trim().to_string())
        },
        "measurements": measurements,
        "caveats": [
            "Single-process wall-clock samples, not statistically reliable percentiles",
            "RSS is process high-water mark, not per-operation allocated bytes",
            "Operating-system scheduling and host load are uncontrolled unless caller constrains them",
            "No real account secrets or vault items were used"
        ]
    }))
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help") {
        println!(
            "Synthetic KDF timing evidence (JSON)\n\
Usage: cargo run --release --locked -p bweso-bitwarden --example kdf-cost -- \
[--mode pbkdf2|argon2id|both] [--rounds 1..20] \
[--pbkdf2-iterations 5000..2000000] \
[--argon2-memory-mib 16..64] [--argon2-iterations 2..10] \
[--argon2-parallelism 1..16]\n\
No real vault credentials; benchmark is not provider or cryptographic assurance."
        );
        return Ok(());
    }
    let report = run(args)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_probe_before_expensive_kdf() {
        assert!(Options::parse(["--rounds", "0"].map(str::to_string)).is_err());
        assert!(Options::parse(["--rounds", "21"].map(str::to_string)).is_err());
        assert!(Options::parse(["--argon2-memory-mib", "65"].map(str::to_string)).is_err());
        assert!(Options::parse(["--pbkdf2-iterations", "4999"].map(str::to_string)).is_err());
        assert!(Options::parse(["--argon2-parallelism", "0"].map(str::to_string)).is_err());
        assert!(Options::parse(["--argon2-iterations", "11"].map(str::to_string)).is_err());
    }

    #[test]
    fn parse_mode_keeps_other_algorithm_out_of_scope() {
        let input = [
            "--mode",
            "pbkdf2",
            "--rounds",
            "2",
            "--argon2-memory-mib",
            "64",
        ];
        let parsed = Options::parse(input.map(str::to_string));
        assert!(matches!(
            parsed,
            Ok(Options {
                mode: Mode::Pbkdf2,
                rounds: 2,
                ..
            })
        ));
    }

    #[test]
    fn parse_rejects_malformed_and_unrecognized_flags() {
        assert!(Options::parse(["--mode", "other"].map(str::to_string)).is_err());
        assert!(Options::parse(["--rounds", "x"].map(str::to_string)).is_err());
        assert!(Options::parse(["--unknown", "1"].map(str::to_string)).is_err());
        assert!(Options::parse(["--mode"].map(str::to_string)).is_err());
    }
}
