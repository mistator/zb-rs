use zb_macros::{zcl_attr, zcl_cluster};
use zigbee::zcl::cluster::types::{AttributeAccess, ClusterType};

#[zcl_attr(identifier = 0x0, access = AttributeAccess::READ_REPORT, reported = (0x0, 0xffff, None))]
pub struct MeasuredValue(i16);

#[zcl_attr(identifier = 0x1, range = (-27315, 32766))]
pub struct MinMeasuredValue(i16);

#[zcl_attr(identifier = 0x2, range = (-27315, 32766))]
pub struct MaxMeasuredValue(i16);

#[zcl_attr(identifier = 0x4, access = AttributeAccess::READ_REPORT, range = (0x0, 0x8000), reported = (0x0, 0xffff, None))]
pub struct Tolerance(u16);

#[zcl_cluster(
    identifier = 0x0402,
    cluster_type = ClusterType::Server,
)]
pub struct Temperature {
    #[R] pub measured_value: MeasuredValue,
    pub min_measured_value: MinMeasuredValue,
    pub max_measured_value: MaxMeasuredValue,
    #[R] pub tolerance: Tolerance,
}
