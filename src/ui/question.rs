use std::io::{Write, stdin, stdout};
use std::sync::atomic::{AtomicBool, Ordering};

static YES: AtomicBool = AtomicBool::new(false);

pub struct Question;

impl Question {
    pub fn set_yes(always_yes: bool) {
        YES.store(always_yes, Ordering::Relaxed);
    }

    pub fn ask(question: &str) -> String {
        println!("{question}");

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
        if YES.load(Ordering::Relaxed) {
            return true;
        }

        if std::env::vars().any(|(ref key, ref value)| key == "VAULT_FORCE_YES" && value == "1") {
            return true;
        }

        loop {
            match Self::ask(&format!("{question} (y/n)"))
                .trim()
                .to_lowercase()
                .as_ref()
            {
                "y" | "j" => return true,
                "n" => return false,
                chars => {
                    eprintln!("unexpected char \"{chars}\" - reask.");
                    continue;
                }
            };
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn set_yes() {
        Question::set_yes(true);
        let result = Question::confirm("a_question");
        assert!(result);
    }
}
