use std::path::Path;

use anyhow::anyhow;

use crate::{Result, fs};

pub struct Filesystem;

pub enum FilesystemCheckResult {
    IsOk,
    IsNotInstalled,
    HasErrors(Vec<String>),
}

impl FilesystemCheckResult {
    pub fn new_ok() -> FilesystemCheckResult {
        FilesystemCheckResult::IsOk
    }

    pub fn new_is_not_installed() -> FilesystemCheckResult {
        FilesystemCheckResult::IsNotInstalled
    }

    pub fn new_error(errors: Vec<String>) -> FilesystemCheckResult {
        FilesystemCheckResult::HasErrors(errors)
    }
}

impl Filesystem {
    pub fn directory_exists<P: AsRef<Path>>(path: P) -> bool {
        match fs::metadata(path) {
            Err(_) => false,
            Ok(metadata) => metadata.is_dir(),
        }
    }

    fn basic_directories() -> Vec<String> {
        vec![
            ".vault/keys".to_string(),
            ".vault/private_keys".to_string(),
            ".vault/secrets".to_string(),
        ]
    }

    pub fn check_filesystem() -> FilesystemCheckResult {
        if !Self::directory_exists("./.vault") {
            return FilesystemCheckResult::new_is_not_installed();
        }

        for directory in Self::basic_directories().iter() {
            if !Self::directory_exists(directory) {
                let cwd = std::env::current_dir()
                    .map_or_else(|_| "".to_string(), |x| x.to_string_lossy().to_string());
                return FilesystemCheckResult::new_error(vec![format!(
                    "directory {cwd}/{directory} must exist, but is not present",
                )]);
            }
        }

        FilesystemCheckResult::new_ok()
    }

    pub fn create_basic_directory_structure() -> Result<()> {
        for dir in Self::basic_directories().iter() {
            fs::create_dir_all(dir)
                .map_err(|error| anyhow!("could not create directory {dir}, {error}"))?
        }

        Ok(())
    }
}
