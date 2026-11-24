//! Pins the current behavior of vault against committed fixtures in `tests/fixtures/v1/`, which
//! were written by vault 1.0.31 (see `tests/fixtures/v1/generate.sh`).

#[path = "../common/mod.rs"]
mod common;

mod cli;
mod create_key;
mod format;
mod get;
mod get_multi;
mod keys;
mod rotate;
mod subscriptions;
mod support;
mod template;
