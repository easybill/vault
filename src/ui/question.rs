use std::io::{Write, stdin, stdout};
use std::sync::atomic::{AtomicBool, Ordering};

static YES: AtomicBool = AtomicBool::new(false);

/// The user's answer to a batch prompt from [`Question::confirm_batch`].
///
/// Only one prompt is shown for the whole batch, instead of one per item.
#[derive(Debug, PartialEq, Eq)]
pub enum BatchAnswer {
    /// Reject every item in the batch ("no to all").
    None,
    /// Ask about each item separately ("case by case").
    Each,
    /// Accept every item in the batch ("yes to all").
    /// Also returned without asking when `-y` or `VAULT_FORCE_YES=1` is set.
    All,
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

    /// Asked once for a whole batch: apply all, skip all, or decide item by item.
    ///
    /// Accepts `y`/`j`/`a` for [`BatchAnswer::All`], `n` for [`BatchAnswer::None`]
    /// and `c` for [`BatchAnswer::Each`] (case-insensitive) and asks again on any other input.
    /// Returns [`BatchAnswer::All`] without asking when `-y` or `VAULT_FORCE_YES=1` is set.
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
    ///
    /// - `heading` is printed above the list, followed by the item count.
    /// - `describe` renders one line per item in that list.
    /// - `per_item_question` builds the prompt for each item when the user picks "case by case".
    ///
    /// Returns an empty list without asking if `items` is empty, and every item
    /// without asking when `-y` or `VAULT_FORCE_YES=1` is set.
    /// Accepted items keep their original order.
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

    /// Asks a yes/no question and returns `true` for yes.
    ///
    /// Accepts `y`/`j` for yes and `n` for no (case-insensitive) and asks again on any other input.
    /// Returns `true` without asking when `-y` or `VAULT_FORCE_YES=1` is set.
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
