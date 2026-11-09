//! Browser module: CDP client, process manager, sessions, cookies.
//! SEG-05 landed the CDP client; SEG-06 adds the process manager.
//! SEG-07 adds the profile lifecycle, encrypted cookie jars and UA presets.

pub mod cookies;
// Typed CDP API consumed by SEG-10 (visit executor); the manager itself only
// uses `cdp::connect` for its readiness verification.
#[allow(dead_code)]
pub mod cdp;
pub mod manager;
pub mod sessions;
