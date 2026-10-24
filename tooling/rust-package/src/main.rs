use sbxr::records::sha256_hex;
use sbxr::release_identity::{Architecture, MAX_EXECUTABLE_BYTES, rust_artifact_metadata};
use sbxr_rust_package::{
    PackageError, Result, build_index, package_executable, read_input, unpack_archive,
    verify_package, write_exclusive,
};
use std::collections::BTreeMap;
use std::path::Path;

fn value<'a>(options: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    options
        .get(key)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(PackageError("arguments"))
}
fn architecture(options: &BTreeMap<String, String>) -> Result<Architecture> {
    match value(options, "architecture")? {
        "amd64" => Ok(Architecture::Amd64),
        "arm64" => Ok(Architecture::Arm64),
        _ => Err(PackageError("architecture")),
    }
}
fn run() -> Result<serde_json::Value> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().ok_or(PackageError("arguments"))?;
    let allowed: &[&str] = match command.as_str() {
        "package" => &[
            "tag",
            "commit",
            "sequence",
            "architecture",
            "executable",
            "output",
        ],
        "index" => &["tag", "commit", "sequence", "directory", "output"],
        "verify-package" => &["directory", "architecture"],
        "metadata" => &["commit", "architecture", "output"],
        _ => return Err(PackageError("arguments")),
    };
    let mut options = BTreeMap::new();
    while let Some(flag) = arguments.next() {
        let key = flag
            .strip_prefix("--")
            .or_else(|| flag.strip_prefix('-'))
            .filter(|key| allowed.contains(key))
            .ok_or(PackageError("arguments"))?;
        let val = arguments.next().ok_or(PackageError("arguments"))?;
        if val.is_empty() || options.insert(key.to_string(), val).is_some() {
            return Err(PackageError("arguments"));
        }
    }
    if options.len() != allowed.len() {
        return Err(PackageError("arguments"));
    }
    let sequence = || {
        value(&options, "sequence")?
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or(PackageError("sequence"))
    };
    match command.as_str() {
        "package" => {
            let arch = architecture(&options)?;
            let output = Path::new(value(&options, "output")?);
            let name = format!("sbxr-linux-{}.tar.gz", arch.as_str());
            if output.file_name().is_none_or(|n| n != name.as_str()) {
                return Err(PackageError("archive-name"));
            }
            let payload = read_input(
                Path::new(value(&options, "executable")?),
                MAX_EXECUTABLE_BYTES,
            )?;
            let archive = package_executable(
                &payload,
                value(&options, "tag")?,
                value(&options, "commit")?,
                sequence()?,
                arch,
            )?;
            let digest = sha256_hex(&unpack_archive(&archive)?);
            write_exclusive(output, &archive)?;
            Ok(
                serde_json::json!({"outcome":"packaged-local", "architecture":arch.as_str(),
                "executable_sha256":digest, "archive_sha256":sha256_hex(&archive)}),
            )
        }
        "index" => {
            let output = Path::new(value(&options, "output")?);
            if output.file_name().is_none_or(|n| n != "release-index.json") {
                return Err(PackageError("index-name"));
            }
            let index = build_index(
                Path::new(value(&options, "directory")?),
                value(&options, "tag")?,
                value(&options, "commit")?,
                sequence()?,
            )?;
            write_exclusive(output, &index)?;
            Ok(
                serde_json::json!({"outcome":"indexed-local", "release_index_sha256":sha256_hex(&index)}),
            )
        }
        "metadata" => {
            let metadata =
                rust_artifact_metadata(value(&options, "commit")?, architecture(&options)?)
                    .map_err(|_| PackageError("metadata"))?;
            write_exclusive(Path::new(value(&options, "output")?), &metadata)?;
            Ok(serde_json::json!({"outcome":"metadata-local"}))
        }
        "verify-package" => {
            let index = verify_package(
                Path::new(value(&options, "directory")?),
                architecture(&options)?,
            )?;
            Ok(
                serde_json::json!({"outcome":"consistent-local", "sequence":index.sequence(),
                "release_identity":{"repository":index.identity().repository(),
                "tag":index.identity().tag(), "commit":index.identity().commit(),
                "release_index_sha256":index.identity().index_sha256()}}),
            )
        }
        _ => Err(PackageError("arguments")),
    }
}
fn main() {
    match run() {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
