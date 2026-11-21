//! Concrete data plane; stable framework/contracts remain pinned independently
//! so transport upgrades do not change the proof guest's dependency graph.
pub use trusted_data_router::{Error, Result};
pub mod edge;
pub mod grants;
pub mod relay;
pub mod transport;
