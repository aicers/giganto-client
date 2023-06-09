pub mod connection;
pub mod frame;
pub mod ingest;
pub mod publish;
#[cfg(test)]
mod test;

use anyhow::{bail, Result};
use std::{fs::File, path::Path};
use tracing::metadata::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

/// Init operation log with tracing
///
/// This function has parameter `pkg_name` with `env!("CARGO_PKG_NAME")`
///
/// # Errors
///
/// * Path not exist
/// * Invalid path
///
pub fn init_tracing(path: &Path, pkg_name: &str) -> Result<WorkerGuard> {
    if !path.exists() {
        tracing_subscriber::fmt::init();
        bail!("Path not found {path:?}");
    }
    let file_name = format!("{pkg_name}.log");
    if File::create(path.join(file_name.clone())).is_err() {
        tracing_subscriber::fmt::init();
        bail!("Cannot create file. {}/{file_name}", path.display());
    }
    let file_appender = tracing_appender::rolling::never(path, file_name);
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let layer_file = fmt::Layer::default()
        .with_ansi(false)
        .with_target(false)
        .with_writer(file_writer)
        .with_filter(EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into()));
    let layer_stdout = fmt::Layer::default()
        .with_ansi(true)
        .with_filter(EnvFilter::from_default_env());
    tracing_subscriber::registry()
        .with(layer_file)
        .with(layer_stdout)
        .init();
    Ok(guard)
}
