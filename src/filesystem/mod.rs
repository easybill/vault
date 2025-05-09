use crate::Result;
use crate::fs;
use anyhow::anyhow;
use std::path::Path;

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

    fn get_basic_directories() -> Vec<String> {
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

        for expected_directory in Self::get_basic_directories().iter() {
            if !Self::directory_exists(expected_directory) {
                return FilesystemCheckResult::new_error(vec![format!(
                    "Directory {}/{} must exist, but is not present.",
                    std::env::current_dir()
                        .map_or_else(|_| "".to_string(), |x| x.to_string_lossy().to_string()),
                    expected_directory
                )]);
            }
        }

        FilesystemCheckResult::new_ok()
    }

    pub fn create_basic_directory_structure() -> Result<()> {
        for dir in Self::get_basic_directories().iter() {
            fs::create_dir_all(dir)
                .map_err(|error| anyhow!("could not create directory {dir}, {error}"))?
        }

        Ok(())
    }
}
