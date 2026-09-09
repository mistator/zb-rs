pub mod binding;
pub mod discovery;
pub mod network;
pub mod descriptors;

use byte::TryRead;
use byte_derive::TryRead;
use byte_derive::TryWrite;

use crate::apl::aps::apsme::{BindStatus, Binding, UnbindStatus};
use crate::apl::zdp::types::discovery::ActiveEpReq;
use crate::apl::zdp::types::discovery::ActiveEpRsp;
use crate::apl::zdp::types::discovery::AddrRsp;
use crate::apl::zdp::types::discovery::DeviceAnnce;
use crate::apl::zdp::types::discovery::IeeeAddrReq;
use crate::apl::zdp::types::discovery::MatchDescReq;
use crate::apl::zdp::types::discovery::MatchDescRsp;
use crate::apl::zdp::types::discovery::NodeDescReq;
use crate::apl::zdp::types::discovery::NodeDescRsp;
use crate::apl::zdp::types::discovery::NwkAddrReq;
use crate::apl::zdp::types::discovery::ParentAnnce;
use crate::apl::zdp::types::discovery::ParentAnnceRsp;
use crate::apl::zdp::types::discovery::PowerDescReq;
use crate::apl::zdp::types::discovery::PowerDescRsp;
use crate::apl::zdp::types::discovery::SimpleDescReq;
use crate::apl::zdp::types::discovery::SimpleDescRsp;
use crate::apl::zdp::types::discovery::SystemServerDiscoveryReq;
use crate::apl::zdp::types::discovery::SystemServerDiscoveryRsp;
use crate::apl::zdp::types::network::MgmtPermitJoiningReq;
use crate::apl::zdp::types::network::MgmtPermitJoiningRsp;

#[derive(Clone, Debug, Default, TryWrite)]
pub struct ZdpCommand {
    pub transaction_sequence_number: u8,
    pub transaction_data: TransactionData,
}

impl TryRead<'_, u16> for ZdpCommand {
    fn try_read(bytes: &'_ [u8], cluster_id: u16) -> byte::Result<(Self, usize)> {
        let transaction_sequence_number = bytes[0];
        let (data, length) = TransactionData::try_read(&bytes[1..], cluster_id)?;

        Ok((
            Self {
                transaction_sequence_number,
                transaction_data: data,
            },
            length,
        ))
    }
}

pub struct ZdpClusterIds;
impl ZdpClusterIds {
    pub const DEVICE_ANNCE: u16 = 0x0013;
    pub const MGMT_PERMIT_JOINING_RSP: u16 = 0x8036;
    pub const NODE_DESC_REQ: u16 = 0x0002;
    pub const NODE_DESC_RSP: u16 = 0x8002;
}

#[derive(Clone, Debug, TryRead, TryWrite)]
#[byte(no_tag = true)]
#[repr(u16)]
pub enum TransactionData {
    NwkAddrReq(NwkAddrReq) = 0x0000,
    IeeeAddrReq(IeeeAddrReq) = 0x0001,
    NodeDescReq(NodeDescReq) = 0x0002,
    PowerDescReq(PowerDescReq) = 0x0003,
    SimpleDescReq(SimpleDescReq) = 0x0004,
    ActiveEpReq(ActiveEpReq) = 0x0005,
    MatchDescReq(MatchDescReq) = 0x0006,
    // ComplexDescReq(ComplexDescReq) = 0x0010, // Deprecated
    // UserDescReq(UserDescReq) = 0x0011, // Deprecated
    // DiscoveryCacheReq(DiscoveryCacheReq) = 0x0012, // Deprecated
    DeviceAnnce(DeviceAnnce) = 0x0013,
    ParentAnnce(ParentAnnce) = 0x001f,
    // UserDescSet(UserDescSet) = 0x0014, // Deprecated
    SystemServerDiscoveryReq(SystemServerDiscoveryReq) = 0x0015,
    // DiscoveryStoreReq(DiscoveryStoreReq) = 0x0016, // Deprecated
    // NodeDescStoreReq(NodeDescStoreReq) = 0x0017, // Deprecated
    // PowerDescStoreReq(PowerDescStoreReq) = 0x0018, // Deprecated
    // ActiveEpStoreReq(ActiveEpStoreReq) = 0x0019, // Deprecated
    // SimpleDescStoreReq(SimpleDescStoreReq) = 0x001a, // Deprecated
    // RemoveNodeCacheReq(RemoveNodeCacheReq) = 0x001b, // Deprecated
    // FindNodeCacheReq(FindNodeCacheReq) = 0x001c, // Deprecated
    // ExtendedSimpleDescReq(ExtendedSimpleDescReq) = 0x001d, // Deprecated
    // ExtendedActiveEpReq(ExtendedActiveEpReq) = 0x001e, // Deprecated

    // EndDeviceBindReq(EndDeviceBindReq) = 0x0020, // Deprecated
    BindReq(Binding) = 0x0021,
    UnbindReq(Binding) = 0x0022,
    // BindRegisterReq(BindRegisterReq) = 0x0023, // Deprecated
    // ReplaceDeviceReq(ReplaceDeviceReq) = 0x0024, // Deprecated
    // StoreBackupBindEntrySeq(StoreBackupBindEntrySeq) = 0x0025, // Deprecated
    // RemoveBackupBindEntrySeq(RemoveBackupBindEntrySeq) = 0x0026, // Deprecated
    // BackupBindTableReq(BackupBindTableReq) = 0x0027, // Deprecated
    // RecoverBindTableReq(RecoverBindTableReq) = 0x0028, // Deprecated
    // BackupSourceBindReq(BackupSourceBindReq) = 0x0029, // Deprecated
    // RecoverSourceBindReq(RecoverSourceBindReq) = 0x002a, // Deprecated

    // MgmtNwkDiscReq(MgmtNwkDiscReq) = 0x0030,
    // MgmtLqiReq(MgmtLqiReq) = 0x0031,
    // MgmtRtgReq(MgmtRtgReq) = 0x0032,
    // MgmtBindReq(MgmtBindReq) = 0x0033,
    // MgmtLeaveReq(MgmtLeaveReq) = 0x0034,
    // MgmtDirectJoinReq(MgmtDirectJoinReq) = 0x0035,
    MgmtPermitJoiningReq(MgmtPermitJoiningReq) = 0x0036,
    // MgmtCacheReq(MgmtCacheReq) = 0x0037,
    // MgmtNwkUpdateReq(MgmtNwkUpdateReq) = 0x0038,
    NwkAddrRsp(AddrRsp) = 0x8000,
    IeeeAddrRsp(AddrRsp) = 0x8001,
    NodeDescRsp(NodeDescRsp) = 0x8002,
    PowerDescRsp(PowerDescRsp) = 0x8003,
    SimpleDescRsp(SimpleDescRsp) = 0x8004,
    ActiveEpRsp(ActiveEpRsp) = 0x8005,
    MatchDescRsp(MatchDescRsp) = 0x8006,
    // ComplexDescRsp(ComplexDescRsp) = 0x8010,
    // UserDescRsp(UserDescRsp) = 0x8011,
    // UserDescConf(UserDescConf) = 0x8014,
    ParentAnnceRsp(ParentAnnceRsp) = 0x801f,
    SystemServerDiscoveryRsp(SystemServerDiscoveryRsp) = 0x8015,
    // DiscoveryStoreRsp(DiscoveryStoreRsp) = 0x8016,
    // NodeDescStoreRsp(NodeDescStoreRsp<'a>) = 0x8017,
    // PowerDescStoreRsp(PowerDescStoreRsp) = 0x8018,
    // ActiveEpStoreRsp(ActiveEpStoreRsp) = 0x8019,
    // SimpleDescStoreRsp(SimpleDescStoreRsp) = 0x801a,
    // RemoveNodeCacheRsp(RemoveNodeCacheRsp) = 0x801b,
    // FindNodeCacheRsp(FindNodeCacheRsp) = 0x801c,
    // ExtendedSimpleDescRsp(ExtendedSimpleDescRsp) = 0x801d,
    // ExtendedActiveEpRsp(ExtendedActiveEpRsp) = 0x801e,

    // EndDeviceBindRsp(EndDeviceBindRsp) = 0x8020,
    BindRsp(BindStatus) = 0x8021,
    UnbindRsp(UnbindStatus) = 0x8022,
    // BindRegisterRsp(BindRegisterRsp) = 0x8023,
    // ReplaceDeviceRsp(ReplaceDeviceRsp) = 0x8024,
    // StoreBackupBindEntrySeq(StoreBackupBindEntrySeq) = 0x8025,
    // RemoveBackupBindEntrySeq(RemoveBackupBindEntrySeq) = 0x8026,
    // BackupBindTableRsp(BackupBindTableRsp) = 0x8027,
    // RecoverBindTableRsp(RecoverBindTableRsp) = 0x8028,
    // BackupSourceBindRsp(BackupSourceBindRsp) = 0x8029,
    // RecoverSourceBindRsp(RecoverSourceBindRsp) = 0x802a,

    // MgmtNwkDiscRsp(MgmtNwkDiscRsp) = 0x8030,
    // MgmtLqiRsp(MgmtLqiRsp) = 0x8031,
    // MgmtRtgRsp(MgmtRtgRsp) = 0x8032,
    // MgmtBindRsp(MgmtBindRsp) = 0x8033,
    // MgmtLeaveRsp(MgmtLeaveRsp) = 0x8034,
    // MgmtDirectJoinRsp(MgmtDirectJoinRsp) = 0x8035,
    MgmtPermitJoiningRsp(MgmtPermitJoiningRsp) = 0x8036,
    // MgmtCacheRsp(MgmtCacheRsp) = 0x8037,
    // MgmtNwkUpdateRsp(MgmtNwkUpdateRsp) = 0x8038,
}

impl TransactionData {
    pub fn discriminant(&self) -> u16 { unsafe { *<*const _>::from(self).cast::<u16>() } }
}

impl Default for TransactionData {
    fn default() -> Self { TransactionData::NwkAddrReq(NwkAddrReq::default()) }
}

#[cfg(test)]
mod tests {
    use byte::TryWrite;

    use crate::apl::zdp::types::TransactionData;
    use crate::apl::zdp::types::ZdpCommand;
    use crate::apl::zdp::types::discovery::NodeDescReq;
    use zb_types::common::NwkAddress;

    #[test]
    fn encode_zdp_command() {
        let command = ZdpCommand {
            transaction_sequence_number: 1,
            transaction_data: TransactionData::NodeDescReq(NodeDescReq {
                nwk_addr_of_interest: NwkAddress(0x1234),
            }),
        };

        let mut buffer = [0u8; 127];
        let size = command.try_write(&mut buffer, byte::LE).unwrap();

        assert_eq!(size, 3);
        assert_eq!(&buffer[..3], &[0x1, 0x34, 0x12]);
    }
}
