use std::io::{Write, stdin, stdout};
use std::sync::atomic::{AtomicBool, Ordering};

static YES: AtomicBool = AtomicBool::new(false);

#[derive(Debug, PartialEq, Eq)]
pub enum BatchAnswer {
    All,
    None,
    Each,
}

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

    fn always_yes() -> bool {
        YES.load(Ordering::Relaxed)
            || std::env::vars().any(|(ref key, ref value)| key == "VAULT_FORCE_YES" && value == "1")
    }

    /// Asks once for a whole batch: apply all, skip all, or decide item by item.
    pub fn confirm_batch(question: &str) -> BatchAnswer {
        if Self::always_yes() {
            return BatchAnswer::All;
        }

        loop {
            match Self::ask(&format!(
                "{question} (y)es to all / (n)o to all / (c)ase by case"
            ))
            .trim()
            .to_lowercase()
            .as_ref()
            {
                "y" | "j" | "a" => return BatchAnswer::All,
                "n" => return BatchAnswer::None,
                "c" => return BatchAnswer::Each,
                chars => {
                    eprintln!("unexpected char \"{chars}\" - reask.");
                    continue;
                }
            };
        }
    }

    /// Lists all planned changes, asks once, and returns the items the user accepted.
    /// Choosing "each" falls back to asking per item.
    pub fn select<T>(
        heading: &str,
        items: Vec<T>,
        describe: impl Fn(&T) -> String,
        per_item_question: impl Fn(&T) -> String,
    ) -> Vec<T> {
        if items.is_empty() {
            return items;
        }

        println!();
        println!("{heading} ({}):", items.len());
        for item in &items {
            println!("  - {}", describe(item));
        }
        println!();

        match Self::confirm_batch(&format!("apply these {} change(s)?", items.len())) {
            BatchAnswer::All => items,
            BatchAnswer::None => {
                println!("maybe later");
                Vec::new()
            }
            BatchAnswer::Each => items
                .into_iter()
                .filter(|item| Self::confirm(&per_item_question(item)))
                .collect(),
        }
    }

    pub fn confirm(question: &str) -> bool {
        if Self::always_yes() {
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
        assert_eq!(Question::confirm_batch("a_batch"), BatchAnswer::All);
        let selected =
            Question::select("items", vec![1, 2, 3], |i| i.to_string(), |i| i.to_string());
        assert_eq!(selected, vec![1, 2, 3]);
    }
}
