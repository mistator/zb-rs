use byte_derive::TryRead;
use byte_derive::TryWrite;
use embassy_time::Duration;

use crate::common::security::frame::SecurityLevel;

#[derive(Clone, Copy, Debug, Default, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum StackProfile {
    #[default]
    Zigbee = 0x01,
    ZigbeePro = 0x02,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum AddrAllocMethod {
    Distributed = 0,
    #[default]
    Stochastic = 1,
}

impl StackProfile {
    pub fn get_params(&self) -> &StackProfileParams {
        match self {
            StackProfile::Zigbee => &ZIGBEE_STACK_PROFILE,
            StackProfile::ZigbeePro => &ZIGBEE_PRO_STACK_PROFILE,
        }
    }
}

pub struct StackProfileParams {
    pub nwk_transaction_persistence_time: u16,
    pub nwk_report_constant_cost: bool,
    pub nwk_security_level: SecurityLevel,
    pub nwk_addr_alloc: AddrAllocMethod,
    pub nwk_use_tree_routing: bool,
    pub nwk_max_depth: u8,
    pub nwk_max_children: u8,
    pub nwk_max_routers: u8,
    pub nwk_sym_link: bool,
    pub nwk_unique_addr: bool,
    pub nwk_broadcast_delivery_time: u32,
    pub nwk_passive_ack_timeout: u32,
    pub nwk_max_broadcast_retries: u8,
    pub nwk_secure_all_frames: bool,
    pub config_nwk_leave_remove_children: bool,
    pub aps_security_timeout_period: Duration,
}

pub const ZIGBEE_STACK_PROFILE: StackProfileParams = StackProfileParams {
    nwk_transaction_persistence_time: 0x01f4,
    nwk_report_constant_cost: false,
    nwk_security_level: SecurityLevel::EncMic32,
    nwk_addr_alloc: AddrAllocMethod::Distributed,
    nwk_use_tree_routing: true,
    nwk_max_depth: 5,
    nwk_max_children: 20,
    nwk_max_routers: 6,
    nwk_sym_link: false,
    nwk_unique_addr: true,
    nwk_broadcast_delivery_time: 9,
    nwk_passive_ack_timeout: 1,
    nwk_max_broadcast_retries: 2,
    nwk_secure_all_frames: true,
    config_nwk_leave_remove_children: false,
    aps_security_timeout_period: Duration::from_millis(700),
};

pub const ZIGBEE_PRO_STACK_PROFILE: StackProfileParams = StackProfileParams {
    nwk_transaction_persistence_time: 0x01f4,
    nwk_report_constant_cost: false,
    nwk_security_level: SecurityLevel::EncMic32,
    nwk_addr_alloc: AddrAllocMethod::Stochastic,
    nwk_use_tree_routing: false,
    nwk_max_depth: 15,
    nwk_max_children: 64, // implementation specific, not restricted by stack profile
    nwk_max_routers: 0,   // not used with stochastic addressing
    nwk_sym_link: true,
    nwk_unique_addr: false,
    nwk_broadcast_delivery_time: 9,
    nwk_passive_ack_timeout: 1,
    nwk_max_broadcast_retries: 2,
    nwk_secure_all_frames: true,
    config_nwk_leave_remove_children: false,
    aps_security_timeout_period: Duration::from_millis(1700),
};
