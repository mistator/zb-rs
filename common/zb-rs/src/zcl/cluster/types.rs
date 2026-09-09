use core::fmt::Debug;
use embassy_time::Instant;

use crate::zcl::command::global::AttributeReportingConfigurationDirection;
use crate::zcl::command::global::AttributeStatusRecord;
use crate::zcl::command::global::DiscoverAttributeRecord;
use crate::zcl::command::global::ReadAttributesStatusRecord;
use crate::zcl::command::global::WriteAttributeStatusRecord;
use crate::zcl::command::global::{AttributeReadReportingConfigurationRecord, ConfigureReportingCommand, MAX_COMMAND_ITEMS, ReadAttributesCommand, ReadReportingConfigurationCommand, WriteAttributesCommand};
use crate::zcl::frame::SpecificZclCommand;
use crate::zcl::frame::ZclFrameCommand;
use crate::zcl::types::ZclData;
use crate::zcl::types::ZclStatus;
use zb_types::HashMap;

#[derive(Clone, Copy, Default)]
pub struct AttributeAccess {
    read: bool,
    write: bool,
    report: bool,
    scene: bool,
}

impl AttributeAccess {
    pub const ALL: AttributeAccess = AttributeAccess {
        read: true,
        write: true,
        report: true,
        scene: true,
    };
    pub const READ_ONLY: AttributeAccess = AttributeAccess {
        read: true,
        write: false,
        report: false,
        scene: false,
    };
    pub const READ_REPORT: AttributeAccess = AttributeAccess {
        read: true,
        write: false,
        report: true,
        scene: false,
    };
    pub const READ_WRITE: AttributeAccess = AttributeAccess {
        read: true,
        write: true,
        report: false,
        scene: false,
    };
    pub const READ_WRITE_REPORT: AttributeAccess = AttributeAccess {
        read: true,
        write: true,
        report: true,
        scene: false,
    };
}

pub trait BaseAttribute {
    fn get_identifier(&self) -> u16;
    fn get_zcl_data_identifier(&self) -> u8;

    fn get_zcl_data(&self) -> ZclData;
    fn set_from_zcl_data(&mut self, data: &ZclData) -> Result<(), ZclStatus>;
    fn validate_from_zcl_data(&self, data: &ZclData) -> Result<(), ZclStatus>;
    fn validate_zcl_data_id(&self, id: u8) -> Result<(), ZclStatus>;

    fn get_access(&self) -> AttributeAccess;
    fn can_read(&self) -> bool { self.get_access().read }
    fn can_write(&self) -> bool { self.get_access().write }
    fn can_report(&self) -> bool { self.get_access().report }
    fn can_scene(&self) -> bool { self.get_access().scene }
}

pub trait BaseReportableAttribute: BaseAttribute {
    fn set_reporting_config(
        &mut self,
        min: u16,
        max: u16,
        reportable_change: Option<&ZclData>,
    ) -> Result<(), ZclStatus>;
    fn should_report(&mut self) -> bool;
    fn get_reporting_config(&self) -> (u16, u16, Option<ZclData>);
}

pub trait Attribute<T: Default>: BaseAttribute {
    fn get_value(&self) -> T;
    fn set_value(&mut self, value: T) -> Result<(), ZclStatus>;
    fn validate_value(&self, value: &T) -> Result<(), ZclStatus>;
}

pub trait ReportedAttribute<T: Default>: Attribute<T> + BaseReportableAttribute {
    fn set_reporting_config(
        &mut self,
        min: u16,
        max: u16,
        reportable_change: Option<T>,
    ) -> Result<(), ZclStatus>;
}

#[derive(Clone, Debug)]
pub struct ReportedAttributeIntervalsConfig<T: Debug + Default> {
    pub default: (u16, u16),
    pub current: (u16, u16),
    pub reportable_change: Option<T>,
    last_reported_on: Instant,
    last_reported_value: T,
}

impl<T: Debug + Default> ReportedAttributeIntervalsConfig<T> {
    pub fn new(default: (u16, u16), reportable_change: Option<T>) -> Self {
        Self {
            default,
            current: default.clone(),
            reportable_change,
            last_reported_on: Instant::MIN,
            last_reported_value: Default::default(),
        }
    }

    pub fn set_values(
        &mut self,
        min: u16,
        max: u16,
        reportable_change: Option<T>,
    ) -> Result<(), ZclStatus> {
        if max == 0x0 && min == 0xffff {
            self.current = self.default.clone();
        } else if min > max {
            return Err(ZclStatus::InvalidValue);
        }

        self.current = (min, max);
        self.reportable_change = reportable_change;

        Ok(())
    }

    pub fn should_report(&mut self) -> bool {
        if self.current.1 == 0xffff {
            return false;
        }

        if self.last_reported_on == Instant::MIN {
            self.last_reported_on = Instant::now();
            return true;
        }

        let duration = Instant::now().duration_since(self.last_reported_on);
        if duration.as_secs() > self.current.0 as u64 {
            self.last_reported_on = Instant::now();
            return true;
        }

        false
    }
}

#[derive(PartialEq)]
pub enum ClusterType {
    Server,
    Client,
}

pub const MAX_CLUSTERS_PER_APPLICATION: usize = 8;
pub const MAX_ATTRIBUTES_PER_CLUSTER: usize = 32;

pub trait ZclCluster {
    fn get_identifier(&self) -> u16;
    fn get_type(&self) -> ClusterType;

    fn get_attributes(&self) -> HashMap<u16, &dyn BaseAttribute, MAX_ATTRIBUTES_PER_CLUSTER>;
    fn get_attributes_mut(&mut self) -> HashMap<u16, &mut dyn BaseAttribute, MAX_ATTRIBUTES_PER_CLUSTER>;

    fn get_reportable_attributes(&self) -> HashMap<u16, &dyn BaseReportableAttribute, MAX_ATTRIBUTES_PER_CLUSTER>;
    fn get_reportable_attributes_mut(&mut self) -> HashMap<u16, &mut dyn BaseReportableAttribute, MAX_ATTRIBUTES_PER_CLUSTER>;

    fn handle_custom_command(&mut self, _cmd: &SpecificZclCommand) -> Option<ZclFrameCommand> {
        None
    }

    fn update_frequency(&self) -> u8 { 1 }
    fn update(&mut self) -> () {}

    fn read_with(&mut self, offset: &mut usize, bytes: &[u8]) -> byte::Result<()>;
    fn write_with(&self, offset: &mut usize, bytes: &mut [u8]) -> byte::Result<usize>;

    fn read_attributes(&self, cmd: &ReadAttributesCommand) -> zb_types::Vec<ReadAttributesStatusRecord, MAX_COMMAND_ITEMS> {
        let mut vec = zb_types::Vec::new();

        let attributes = self.get_attributes();
        for identifier in cmd.attributes.iter() {
            let attr = match attributes.get(identifier) {
                Some(attr) => attr,
                None => {
                    vec.push(ReadAttributesStatusRecord {
                        identifier: *identifier,
                        status: ZclStatus::UnsupportedAttribute,
                        data: None,
                    }).unwrap();
                    continue;
                }
            };

            let (status, data) = match attr.can_read() {
                true => (ZclStatus::Success, Some(attr.get_zcl_data())),
                false => (ZclStatus::Failure, None),
            };

            vec.push(ReadAttributesStatusRecord {
                identifier: *identifier,
                status,
                data,
            }).unwrap();
        }

        vec
    }

    fn write_attributes(
        &mut self,
        cmd: &WriteAttributesCommand,
    ) -> zb_types::Vec<WriteAttributeStatusRecord, MAX_COMMAND_ITEMS> {
        let mut vec = zb_types::Vec::new();

        let mut attributes = self.get_attributes_mut();
        for value in cmd.attributes.iter() {
            let attr = match attributes.get_mut(&value.identifier) {
                Some(attr) => attr,
                None => {
                    vec.push(WriteAttributeStatusRecord {
                        identifier: value.identifier,
                        status: ZclStatus::UnsupportedAttribute,
                    }).unwrap();
                    continue;
                }
            };

            let status = match attr.can_write() {
                false => ZclStatus::ReadOnly,
                true => match attr.set_from_zcl_data(&value.data) {
                    Ok(_) => ZclStatus::Success,
                    Err(err) => err,
                },
            };

            vec.push(WriteAttributeStatusRecord {
                status,
                identifier: value.identifier,
            }).unwrap();
        }

        vec
    }

    fn write_attributes_undivided(
        &mut self,
        cmd: &WriteAttributesCommand,
    ) -> zb_types::Vec<WriteAttributeStatusRecord, MAX_COMMAND_ITEMS> {
        let mut vec = zb_types::Vec::new();
        let mut should_write = true;

        let mut attributes = self.get_attributes_mut();
        for value in cmd.attributes.iter() {
            let attr = match attributes.get(&value.identifier) {
                Some(attr) => attr,
                None => {
                    vec.push(WriteAttributeStatusRecord {
                        identifier: value.identifier,
                        status: ZclStatus::UnsupportedAttribute,
                    }).unwrap();
                    should_write = false;
                    continue;
                }
            };

            let status = match attr.can_write() {
                false => {
                    should_write = false;
                    ZclStatus::ReadOnly
                }
                true => match attr.validate_from_zcl_data(&value.data) {
                    Ok(_) => ZclStatus::Success,
                    Err(err) => {
                        should_write = false;
                        err
                    }
                },
            };

            vec.push(WriteAttributeStatusRecord {
                status,
                identifier: value.identifier,
            }).unwrap();
        }

        if should_write {
            for value in cmd.attributes.iter() {
                attributes
                    .get_mut(&value.identifier)
                    .unwrap()
                    .set_from_zcl_data(&value.data)
                    .unwrap();
            }
        }

        vec
    }

    fn configure_reporting(
        &mut self,
        cmd: &ConfigureReportingCommand,
    ) -> zb_types::Vec<AttributeStatusRecord, MAX_COMMAND_ITEMS> {
        let mut vec = zb_types::Vec::new();

        for value in cmd.configuration_records.iter() {
            if value.direction != AttributeReportingConfigurationDirection::Report {
                vec.push(AttributeStatusRecord {
                    identifier: value.identifier,
                    direction: value.direction,
                    status: ZclStatus::UnsupportedAttribute,
                }).unwrap();

                continue;
            }

            let mut attributes = self.get_reportable_attributes_mut();
            let status = {
                if let Some(attr) = attributes.get_mut(&value.identifier) {
                    match attr.set_reporting_config(
                        value.minimum_reporting_interval.unwrap(),
                        value.maximum_reporting_interval.unwrap(),
                        value.reportable_change.as_ref(),
                    ) {
                        Ok(_) => ZclStatus::Success,
                        Err(err) => err,
                    }
                } else {
                    ZclStatus::UnreportableAttribute
                }
            };

            vec.push(AttributeStatusRecord {
                status,
                identifier: value.identifier,
                direction: value.direction,
            }).unwrap();
        }

        vec
    }

    fn read_reporting_config(
        &self,
        cmd: &ReadReportingConfigurationCommand
    ) -> zb_types::Vec<AttributeReadReportingConfigurationRecord, MAX_COMMAND_ITEMS> {
        let mut vec = zb_types::Vec::new();

        let reportable_attrs = self.get_reportable_attributes();

        for value in cmd.attributes.iter() {
            if value.direction != AttributeReportingConfigurationDirection::Report {
                vec.push(AttributeReadReportingConfigurationRecord {
                    status: ZclStatus::UnsupportedAttribute,
                    direction: value.direction,
                    identifier: value.identifier,
                    ..Default::default()
                }).unwrap();

                continue;
            }

            if let Some(attr) = reportable_attrs.get(&value.identifier) {
                let reporting_config = attr.get_reporting_config();

                vec.push(AttributeReadReportingConfigurationRecord {
                    status: ZclStatus::Success,
                    direction: value.direction,
                    identifier: value.identifier,
                    data_type: Some(attr.get_zcl_data_identifier() as u8),
                    minimum_reporting_interval: Some(reporting_config.0),
                    maximum_reporting_interval: Some(reporting_config.1),
                    reportable_change: None,
                    timeout_period: None,
                }).unwrap();
            } else {
                vec.push(AttributeReadReportingConfigurationRecord {
                    status: ZclStatus::UnsupportedAttribute,
                    direction: value.direction,
                    identifier: value.identifier,
                    ..Default::default()
                }).unwrap();
            }
        }

        vec
    }

    fn discover_attributes(&self, start: u16, maximum: u8) -> zb_types::Vec<DiscoverAttributeRecord, MAX_COMMAND_ITEMS> {
        let mut vec = zb_types::Vec::new();

        let attributes = self.get_attributes();
        let mut keys = attributes.keys().collect::<zb_types::Vec<_, MAX_COMMAND_ITEMS>>();
        keys.sort();

        for key in keys
            .into_iter()
            .filter(|key| **key >= start)
            .take(maximum as usize)
        {
            let attr = attributes.get(key).unwrap();
            vec.push(DiscoverAttributeRecord {
                identifier: attr.get_identifier(),
                data_type: attr.get_zcl_data_identifier() as u8,
            }).unwrap();
        }

        vec
    }
}

#[cfg(test)]
mod tests {
    use crate::zcl::command::global::{ReadAttributesCommand, WriteAttributesCommand};
    use crate::zcl::cluster::types::ZclCluster;
    use crate::zcl::cluster::types::Attribute;
    use crate::zcl::command::global::AttributeRecord;
    use crate::zcl::types::ZclStatus;
    use crate::zcl::types::ZclData;
    use alloc::vec;
    use zb_macros::{zcl_attr, zcl_cluster};
    use zb_types::Vec;
    use crate::zcl::cluster::types::{AttributeAccess, ClusterType};

    #[zcl_attr(identifier = 0x2, range = (-27316, 32767), crate = crate)]
    pub struct ReadOnlyAttr(i16);

    #[zcl_attr(
        identifier = 0x3,
        access = AttributeAccess::READ_WRITE,
        range = (-27316, 32767),
        crate = crate
    )]
    pub struct ReadWriteAttr(i16);

    #[zcl_cluster(identifier = 0x1, cluster_type = ClusterType::Server, crate = crate)]
    pub struct Cluster {
        pub read_only: ReadOnlyAttr,
        pub read_write: ReadWriteAttr,
    }

    #[test]
    fn test_attribute_value_change() {
        let mut attribute = ReadOnlyAttr::new(18);
        attribute.set_value(14).unwrap();
        assert_eq!(attribute.value, 14);

        let result = attribute.set_value(-30000);
        assert!(result.is_err());
        assert_eq!(attribute.value, 14);
    }

    #[test]
    fn test_attribute_value_out_of_range() {
        let mut attribute = ReadOnlyAttr::new(18);
        let result = attribute.set_value(-30000);
        assert!(result.is_err());
        assert_eq!(attribute.value, 18);
    }

    #[test]
    fn test_cluster_read_single_attribute() {
        let cluster = Cluster::new();

        let result = cluster.read_attributes(&ReadAttributesCommand {
            attributes: Vec::from_iter(vec![0x2])
        });
        assert_eq!(result.len(), 1);

        let result = &result[0];
        assert_eq!(result.identifier, 0x2);
        assert_eq!(result.status, ZclStatus::Success);
        assert_eq!(result.data, Some(ZclData::Int16(0)));
    }

    #[test]
    fn test_cluster_read_multiple_attributes() {
        let cluster = Cluster::new();

        let result = cluster.read_attributes(&ReadAttributesCommand {
            attributes: Vec::from_iter(vec![0x2, 0x3])
        });
        assert_eq!(result.len(), 2);

        assert_eq!(result[0].identifier, 0x2);
        assert_eq!(result[0].status, ZclStatus::Success);
        assert_eq!(result[0].data, Some(ZclData::Int16(0)));

        assert_eq!(result[1].identifier, 0x3);
        assert_eq!(result[1].status, ZclStatus::Success);
        assert_eq!(result[1].data, Some(ZclData::Int16(0)));
    }

    #[test]
    fn test_write_attribute() {
        let mut cluster = Cluster::new();

        let results = cluster.write_attributes(&WriteAttributesCommand {
            attributes: Vec::from_iter(vec![AttributeRecord {
                identifier: 0x3,
                data: ZclData::Int16(14),
            }])
        });
        assert_eq!(results.len(), 1);

        let result = &results[0];
        assert_eq!(result.identifier, 0x3);
        assert_eq!(result.status, ZclStatus::Success);

        let results = cluster.read_attributes(&ReadAttributesCommand {
            attributes: Vec::from_iter(vec![0x3])
        });

        let result = &results[0];
        assert_eq!(result.identifier, 0x3);
        assert_eq!(result.status, ZclStatus::Success);
        assert_eq!(result.data, Some(ZclData::Int16(14)));
    }

    #[test]
    fn test_write_readonly_attribute_fails() {
        let mut cluster = Cluster::new();

        let results = cluster.write_attributes(&WriteAttributesCommand {
            attributes: Vec::from_iter(vec![AttributeRecord {
                identifier: 0x2,
                data: ZclData::Int16(14),
            }])
        });

        assert_eq!(results.len(), 1);

        let result = &results[0];
        assert_eq!(result.identifier, 0x2);
        assert_eq!(result.status, ZclStatus::ReadOnly);

        let results = cluster.read_attributes(&ReadAttributesCommand {
            attributes: Vec::from_iter(vec![0x2])
        });

        let result = &results[0];
        assert_eq!(result.identifier, 0x2);
        assert_eq!(result.status, ZclStatus::Success);
        assert_eq!(result.data, Some(ZclData::Int16(0)));
    }

    #[test]
    fn test_write_multiple_attributes() {
        let mut cluster = Cluster::new();

        let result = cluster.write_attributes(&WriteAttributesCommand {
            attributes: Vec::from_iter(vec![
                AttributeRecord {
                    identifier: 0x2,
                    data: ZclData::Int16(14),
                },
                AttributeRecord {
                    identifier: 0x3,
                    data: ZclData::Int16(14),
                },
            ])
        });

        assert_eq!(result.len(), 2);

        assert_eq!(result[0].identifier, 0x2);
        assert_eq!(result[0].status, ZclStatus::ReadOnly);

        assert_eq!(result[1].identifier, 0x3);
        assert_eq!(result[1].status, ZclStatus::Success);

        let result = cluster.read_attributes(&ReadAttributesCommand {
            attributes: Vec::from_iter(vec![0x2, 0x3])
        });

        assert_eq!(result[0].identifier, 0x2);
        assert_eq!(result[0].status, ZclStatus::Success);
        assert_eq!(result[0].data, Some(ZclData::Int16(0)));

        assert_eq!(result[1].identifier, 0x3);
        assert_eq!(result[1].status, ZclStatus::Success);
        assert_eq!(result[1].data, Some(ZclData::Int16(14)));
    }

    #[test]
    fn test_write_multiple_attributes_undivided() {
        let mut cluster = Cluster::new();

        let result = cluster.write_attributes_undivided(&WriteAttributesCommand {
            attributes: Vec::from_iter(vec![
                AttributeRecord {
                    identifier: 0x2,
                    data: ZclData::Int16(14),
                },
                AttributeRecord {
                    identifier: 0x3,
                    data: ZclData::Int16(14),
                },
            ])
        });

        assert_eq!(result.len(), 2);

        assert_eq!(result[0].identifier, 0x2);
        assert_eq!(result[0].status, ZclStatus::ReadOnly);

        assert_eq!(result[1].identifier, 0x3);
        assert_eq!(result[1].status, ZclStatus::Success);

        let result = cluster.read_attributes(&ReadAttributesCommand {
            attributes: Vec::from_iter(vec![0x2, 0x3])
        });

        assert_eq!(result[0].identifier, 0x2);
        assert_eq!(result[0].status, ZclStatus::Success);
        assert_eq!(result[0].data, Some(ZclData::Int16(0)));

        assert_eq!(result[1].identifier, 0x3);
        assert_eq!(result[1].status, ZclStatus::Success);
        assert_eq!(result[1].data, Some(ZclData::Int16(0)));
    }

    #[test]
    fn test_discover_single() {
        let cluster = Cluster::new();

        let result = cluster.discover_attributes(0, 1);
        assert_eq!(result.len(), 1);

        assert_eq!(result[0].identifier, 0x2);
        assert_eq!(result[0].data_type, 0x29);
    }

    #[test]
    fn test_discover_multiple() {
        let cluster = Cluster::new();

        let result = cluster.discover_attributes(0, 10);
        assert_eq!(result.len(), 2);

        assert_eq!(result[0].identifier, 0x2);
        assert_eq!(result[0].data_type, 0x29);

        assert_eq!(result[1].identifier, 0x3);
        assert_eq!(result[1].data_type, 0x29);
    }

    #[test]
    fn test_discover_multiple_range() {
        let cluster = Cluster::new();

        let result = cluster.discover_attributes(3, 10);
        assert_eq!(result.len(), 1);

        assert_eq!(result[0].identifier, 0x3);
        assert_eq!(result[0].data_type, 0x29);
    }
}
