//! Concrete data plane; stable framework/contracts remain pinned independently
//! so transport upgrades do not change the proof guest's dependency graph.
pub use trusted_data_router::{Error, Result};
pub mod authorization;
pub mod control;
pub mod edge;
pub mod grants;
mod keys;
pub mod relay;
pub mod sync;
pub mod transport;
