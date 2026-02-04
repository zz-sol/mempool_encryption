//! Tracing subscriber initialization helpers.

use tracing_subscriber::{EnvFilter, fmt};

/// Initialize a global tracing subscriber using `RUST_LOG` (or `filter` if provided).
///
/// Safe to call multiple times; subsequent calls will no-op.
pub fn init_tracing(filter: Option<&str>) {
    let filter = if let Some(f) = filter {
        EnvFilter::new(f)
    } else if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        // Default to info if RUST_LOG is not set.
        EnvFilter::new("info")
    };

    let subscriber = fmt().with_env_filter(filter).with_target(false).finish();

    let _ = tracing::subscriber::set_global_default(subscriber);
}
