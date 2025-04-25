use std::io::Write;
use std::io::stdin;
use std::io::stdout;

pub struct Question;

impl Question {
    pub fn ask(question: &str) -> String {
        println!("{}", question);

        let _ = stdout().flush();

        let mut s = String::new();
        stdin()
            .read_line(&mut s)
            .expect("Did not enter a valid string");

        if let Some('\n') = s.chars().next_back() {
            s.pop();
        }

        if let Some('\r') = s.chars().next_back() {
            s.pop();
        }

        s
    }

    pub fn confirm(question: &str) -> bool {
        if std::env::vars().any(|(ref key, ref value)| key == "VAULT_FORCE_YES" && value == "1") {
            return true;
        }

        loop {
            match Self::ask(&format!("{} (y/n)", question))
                .trim()
                .to_lowercase()
                .as_ref()
            {
                "y" | "j" => return true,
                "n" => return false,
                c => {
                    eprintln!("unecpected char \"{}\" - reask.", c);
                    continue;
                }
            };
        }
    }
}
