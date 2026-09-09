//! Device Profile
//!
//! The ZigBee Device Profile operates like any ZigBee profile by defining
//! clusters. Unlike application specific profiles, the clusters within the
//! ZigBee Device Profile define capabilities supported in all ZigBee devices.
//!
//! The Device Profile supports four key inter-device communication functions
//! within the ZigBee protocol. These functions are explained in the following
//! sections:
//! * Device and Service Discovery Overview
//! * End Device Bind Overview
//! * Bind and Unbind Overview
//! * Binding Table Management Overview
//! * Network Management Overview

use crate::apl::aps::types::ApsEndpoint;

pub mod service;
pub mod types;

pub const ZDP_PROFILE: u16 = 0;
pub const ZDP_ENDPOINT: ApsEndpoint = ApsEndpoint::new(0).unwrap();
