#[cfg(test)]
mod tests {
    use serial_test::serial;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};

    static TEST_DIR: &str = "vault_integration_test";

    fn cmd(
        dir: impl AsRef<Path>,
        command: impl AsRef<str>,
        args: &[&str],
        capture_output: bool,
    ) -> Vec<u8> {
        let command_str = command.as_ref().to_string();

        let mut cmd = Command::new(&command_str);
        let cmd = cmd
            .args(args)
            .env("VAULT_FORCE_YES", "1")
            .current_dir(dir)
            .stdin(Stdio::null());

        if !capture_output {
            let _cmd = cmd.stdout(Stdio::inherit());
        }

        let output = cmd
            .output()
            .unwrap_or_else(|_| panic!("Failed to execute #1 {} {:?}", &command_str, args));

        if !output.status.success() {
            println!(
                "Command with invalid Status Code: {} {:?}\n{:?}",
                &command_str, args, output
            );
        }

        assert!(output.status.success());

        output.stdout
    }

    fn test_prepare() {
        cmd(".", "cargo", &["build"], false);

        cmd(".", "rm", &["-rf", TEST_DIR], false);
        cmd(".", "mkdir", &["-p", TEST_DIR], false);

        let vault_dir = &format!("{}/vault", TEST_DIR);
        cmd(".", "cp", &["./target/debug/vault", vault_dir], false);
        cmd(".", "cp", &["-r", "./fixtures", TEST_DIR], false);
        cmd(TEST_DIR, "mv", &["./fixtures", ".vault"], false);

        cmd(TEST_DIR, "ls", &["-lah"], false);
        cmd(TEST_DIR, "ls", &["-lah", "./.vault"], false);
    }

    #[test]
    #[serial]
    fn test_integration_decode_old_version() {
        test_prepare();

        // check if we could extract VERSION_1_0_0_SECRET

        let valid_secrets = vec!["VERSION_1_0_0_SECRET"];

        for valid_secret in &valid_secrets {
            println!("checking {}", valid_secret);
            let content = cmd(TEST_DIR, "./vault", &["get", valid_secret], true);
            assert_eq!(format!("{}_CONTENT", valid_secret).into_bytes(), content);
        }

        // Generate a template with all keys ...
        let template = valid_secrets
            .iter()
            .map(|x| format!("some othe{{{{r cont}}}}ent {{vault{{{}}}vault}}", x))
            .collect::<Vec<_>>()
            .join(",");

        let expected_template = valid_secrets
            .iter()
            .map(|x| format!("some othe{{{{r cont}}}}ent {}_CONTENT", x))
            .collect::<Vec<_>>()
            .join(",");

        let mut file = File::create(format!("{}/example_template.vault", TEST_DIR))
            .expect("could not create template");
        file.write_all(template.as_bytes())
            .expect("could not write template");

        let template_output = cmd(
            TEST_DIR,
            "./vault",
            &["template", "example_template.vault"],
            true,
        );
        // println!("Template1: {}", String::from_utf8_lossy(&template_output));
        // println!("Template2: {}", &expected_template);
        assert_eq!(expected_template.into_bytes(), template_output);
    }

    fn assert_secret() {
        assert_eq!(
            "VERSION_1_0_0_SECRET_CONTENT",
            String::from_utf8_lossy(&cmd(
                TEST_DIR,
                "./vault",
                &["get", "VERSION_1_0_0_SECRET"],
                true
            ))
        )
    }

    #[test]
    #[serial]
    fn test_integration_multi_key() {
        test_prepare();

        let content = cmd(
            TEST_DIR,
            "./vault",
            &[
                "get_multi",
                r#"{"secrets": [{"secret": "VERSION_1_0_0_SECRET"}], "templates": [{"template": "{vault{ VERSION_1_0_0_SECRET }vault}TEST"}]}"#,
            ],
            true,
        );

        assert_eq!(
            String::from_utf8(content).expect("must be valid utf8"),
            r#"{"secrets":{"VERSION_1_0_0_SECRET":{"name":"VERSION_1_0_0_SECRET","value":"VERSION_1_0_0_SECRET_CONTENT"}},"templates":{"{vault{ VERSION_1_0_0_SECRET }vault}TEST":{"name":"{vault{ VERSION_1_0_0_SECRET }vault}TEST","value":"VERSION_1_0_0_SECRET_CONTENTTEST"}}}"#
        );
    }

    #[test]
    #[serial]
    fn test_integration_rotate_key_and_decode_content() {
        test_prepare();

        let content = cmd(TEST_DIR, "./vault", &["rotate"], true);
        println!("output: {}", String::from_utf8_lossy(&content));

        // delete backup files
        {
            for entry in fs::read_dir("./vault_integration_test/.vault/private_keys")
                .expect("could not readdir")
            {
                let entry = entry.expect("dir entry");
                let path = entry.path();

                if path.is_file() && path.to_string_lossy().contains("_backup_") {
                    fs::remove_file(path).expect("remove");
                }
            }
        }

        assert_secret();
    }

    #[test]
    #[serial]
    fn test_integration_rotate_key_and_read_old_file() {
        test_prepare();
        cmd(TEST_DIR, "./vault", &["rotate"], true);

        cmd(TEST_DIR, "rm", &["-rf", "./.vault/secrets"], false);

        cmd(
            ".",
            "cp",
            &[
                "-r",
                "./fixtures/secrets",
                &format!("{}/.vault/secrets", TEST_DIR),
            ],
            false,
        );

        assert_secret();
    }
}
