//! Browser module: CDP client, process manager, sessions, cookies.
//! SEG-05 lands the CDP client; SEG-06/SEG-07 build on it.

// Consumed by SEG-06 (process manager) and SEG-10 (executor); until those
// wire it into the binary, the typed API is intentionally unused in this
// crate. Remove the allow once a caller lands.
#[allow(dead_code)]
pub mod cdp;
pub mod cookies;
pub mod manager;
pub mod sessions;
