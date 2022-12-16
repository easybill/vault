use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};


static VAULT_INTEGRATION_TEST_DIR : &'static str = "vault_integration_test";

fn cmd<T>(dir: T, command: T, args : &[&str], capture_output: bool) -> Vec<u8> where T: AsRef<str> {

    let command_str = command.as_ref().to_string();

    let mut cmd = Command::new(&command_str);
    let mut cmd = cmd
        .args(args)
        .current_dir(&dir.as_ref().to_string())
        .stdin(Stdio::null())
        ;

    if !capture_output {
        let cmd = cmd.stdout(Stdio::inherit());
    }

    let output = cmd
        .output()
        .expect(&format!("Failed to execute #1 {} {:?}", &command_str, args))
        ;

    assert_eq!(true, output.status.success());

    output.stdout
}

#[test]
fn test_integration_decode_old_version() {

    // cmd(".", "cargo", &["build"], false);

    cmd(".", "rm", &["-rf", VAULT_INTEGRATION_TEST_DIR], false);
    cmd(".", "mkdir", &["-p", &format!("{}/.vault", VAULT_INTEGRATION_TEST_DIR)], false);

    let self_path = {
        let current_exe = ::std::env::current_exe();
        let current_exe = current_exe.expect("could not get self ...");
        let str = current_exe.to_str().expect("invalid path");
        str.to_string()
    };

    cmd(".", "cp", &[&self_path, &format!("{}/vault", VAULT_INTEGRATION_TEST_DIR)], false);
    cmd(".", "cp", &["-r", "./fixtures/", &format!("{}/.vault", VAULT_INTEGRATION_TEST_DIR)], false);

    cmd(VAULT_INTEGRATION_TEST_DIR, "ls", &["-lah"], false);

    // check if we could extract VERSION_1_0_0_SECRET

    let valid_secrets = vec![
        "VERSION_1_0_0_SECRET"
    ];

    for valid_secret in &valid_secrets {
        println!("checking {}", valid_secret);
        let content = cmd(VAULT_INTEGRATION_TEST_DIR, "vault", &["get", valid_secret], true);
        assert_eq!(format!("{}_CONTENT", valid_secret).into_bytes(), content);
    }

    // Generate a template with all keys ...
    let template = valid_secrets
        .iter()
        .map(|x| format!("some othe{{{{r cont}}}}ent {{vault{{{}}}vault}}", x))
        .collect::<Vec<_>>()
        .join(",");

    let expected_template  = valid_secrets
        .iter()
        .map(|x| format!("some othe{{{{r cont}}}}ent {}_CONTENT", x))
        .collect::<Vec<_>>()
        .join(",");

    let mut file = File::create(format!("{}/example_template.vault", VAULT_INTEGRATION_TEST_DIR)).expect("could not create template");
    file.write_all(template.as_bytes()).expect("could not write template");

    let template_output = cmd(VAULT_INTEGRATION_TEST_DIR, "vault", &["template", "example_template.vault"], true);
    // println!("Template1: {}", String::from_utf8_lossy(&template_output));
    // println!("Template2: {}", &expected_template);
    assert_eq!(expected_template.into_bytes(), template_output);
}