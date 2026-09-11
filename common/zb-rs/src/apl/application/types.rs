use crate::zcl::cluster::types::ZclCluster;
use core::any::Any;
use core::fmt::Debug;

const ZB_PROFILE_PLANT_MONITORING: u16 = 0x0101;
const ZB_PROFILE_HOME_AUTOMATION: u16 = 0x0104;
const ZB_PROFILE_COMMERCIAL_BUILDING_AUTOMATION: u16 = 0x0105;
const ZB_PROFILE_TELECOM_APPLICATIONS: u16 = 0x0107;
const ZB_PROFILE_PERSONAL_HOME_AND_HOSPITAL_CARE: u16 = 0x0108;
const ZB_PROFILE_ADVANCED_METERING_INITIATIVE: u16 = 0x0109;

#[repr(u16)]
pub enum ZbDevice {
    IndustrialPlantMonitoring(u16) = ZB_PROFILE_PLANT_MONITORING,
    HomeAutomation(HomeAutomationDeviceIds) = ZB_PROFILE_HOME_AUTOMATION,
    CommercialBuildingAutomation(u16) = ZB_PROFILE_COMMERCIAL_BUILDING_AUTOMATION,
    TelecomApplications(u16) = ZB_PROFILE_TELECOM_APPLICATIONS,
    PersonalHomeAndHospitalCare(u16) = ZB_PROFILE_PERSONAL_HOME_AND_HOSPITAL_CARE,
    AdvancedMeteringInitiative(u16) = ZB_PROFILE_ADVANCED_METERING_INITIATIVE,
    ManufacturerSpecific(u16, u16),
}

impl ZbDevice {
    pub fn get_profile_and_device_ids(&self) -> (u16, u16) {
        match self {
            ZbDevice::IndustrialPlantMonitoring(device_id) => {
                (ZB_PROFILE_PLANT_MONITORING, *device_id)
            }
            ZbDevice::HomeAutomation(device_id) => (ZB_PROFILE_HOME_AUTOMATION, *device_id as u16),
            ZbDevice::CommercialBuildingAutomation(device_id) => {
                (ZB_PROFILE_COMMERCIAL_BUILDING_AUTOMATION, *device_id)
            }
            ZbDevice::TelecomApplications(device_id) => {
                (ZB_PROFILE_TELECOM_APPLICATIONS, *device_id)
            }
            ZbDevice::PersonalHomeAndHospitalCare(device_id) => {
                (ZB_PROFILE_PERSONAL_HOME_AND_HOSPITAL_CARE, *device_id)
            }
            ZbDevice::AdvancedMeteringInitiative(device_id) => {
                (ZB_PROFILE_ADVANCED_METERING_INITIATIVE, *device_id)
            }
            ZbDevice::ManufacturerSpecific(profile_id, device_id) => (*profile_id, *device_id),
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum HomeAutomationDeviceIds {
    OnOffSwitch = 0x0000,
    LevelControlSwitch = 0x0001,
    OnOffOutput = 0x0002,
    LevelControllableOutput = 0x0003,
    SceneSelector = 0x0004,
    ConfigurationTool = 0x0005,
    RemoteControl = 0x0006,
    CombinedInterface = 0x0007,
    RangeExtender = 0x0008,
    MainsPowerOutlet = 0x0009,
    OnOffLight = 0x0100,
    DimmableLight = 0x0101,
    ColorDimmableLight = 0x0102,
    OnOffLightSwitch = 0x0103,
    DimmerSwitch = 0x0104,
    ColorDimmerSwitch = 0x0105,
    LightSensor = 0x0106,
    OccupancySensor = 0x0107,
    Shade = 0x0200,
    ShadeController = 0x0201,
    HeatingCoolingUnit = 0x0300,
    Thermostat = 0x0301,
    TemperatureSensor = 0x0302,
    Pump = 0x0303,
    PumpController = 0x0304,
    PressureSensor = 0x0305,
    FlowSensor = 0x0306,
    IASControlAndIndicatingEquipment = 0x0400,
    IASAncillaryControlEquipment = 0x0401,
    IASZone = 0x0402,
    IASWarningDevice = 0x0403,
}

pub const MAX_CLUSTERS_PER_APP: usize = 8;

pub trait BaseApplication {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn get_device(&self) -> ZbDevice;
    fn get_version(&self) -> u8;
    fn get_clusters(&self) -> zb_types::Vec<&dyn ZclCluster, MAX_CLUSTERS_PER_APP>;
    fn get_clusters_mut(&mut self) -> zb_types::Vec<&mut dyn ZclCluster, MAX_CLUSTERS_PER_APP>;

    fn get_cluster_by_id(&self, cluster_id: u16) -> Option<&dyn ZclCluster> {
        self.get_clusters()
            .into_iter()
            .find(|item| item.get_identifier() == cluster_id)
    }

    fn get_cluster_by_id_mut(&mut self, cluster_id: u16) -> Option<&mut dyn ZclCluster> {
        self.get_clusters_mut()
            .into_iter()
            .find(|item| item.get_identifier() == cluster_id)
    }

    fn get_profile(&self) -> u16 { self.get_device().get_profile_and_device_ids().0 }

    fn get_update_interval(&self) -> u8 { 1 }

    fn load(&mut self, bytes: &[u8]) -> byte::Result<()>;
    fn try_write(&self, bytes: &mut [u8]) -> byte::Result<usize>;

    fn update_frequency(&self) -> u8 { 1 }
    fn update(&mut self, counter: u64) -> ();
}

#[macro_export]
macro_rules! define_application {
    (
        #[device($device:expr)]
        $(#[version($version:literal)])?
        $(#[$m:meta])*
        $vi:vis struct $name:ident$(<$lifetime:lifetime>)? {
            $(
                $(#[doc = $doc:literal])*
                pub $cluster_name:ident: $cluster_ty:ty,
            )+
            $(#[ctx] pub $ctx_name:ident:  $ctx_ty:ty,)?
        }
    ) => {
        $(#[$m])*
        $vi struct $name$(<$lifetime>)? {
            $(
                $(#[doc = $doc])*
                pub $cluster_name: $cluster_ty,
            )+
            $(pub $ctx_name: $ctx_ty,)?
        }

        impl$(<$lifetime>)? $name$(<$lifetime>)? {
            pub const DEVICE: zigbee::apl::application::types::ZbDevice = $device;
            pub const VERSION: u8 = 0x0 $(+ $version)?;
        }

        impl$(<$lifetime>)? zigbee::apl::application::types::BaseApplication for $name$(<$lifetime>)? {
            fn as_any(&self) -> &dyn core::any::Any {
                self
            }

            fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
                self
            }

            fn get_device(&self) -> zigbee::apl::application::types::ZbDevice {
                <$name>::DEVICE
            }

            fn get_version(&self) -> u8 {
                <$name>::VERSION
            }

            fn get_clusters(&self) -> zb_types::Vec<&dyn zigbee::zcl::cluster::types::ZclCluster, 8> {
                let mut clusters = zb_types::Vec::new();

                $(
                    clusters.push(&self.$cluster_name as &dyn zigbee::zcl::cluster::types::ZclCluster).unwrap();
                )+

                clusters
            }

            fn get_clusters_mut(&mut self) -> zb_types::Vec<&mut dyn zigbee::zcl::cluster::types::ZclCluster, 8> {
                let mut clusters = zb_types::Vec::new();

                $(
                    clusters.push(&mut self.$cluster_name as &mut dyn zigbee::zcl::cluster::types::ZclCluster).unwrap();
                )+

                clusters
            }

            fn load(&mut self, bytes: &[u8]) -> byte::Result<()> {
                use byte::BytesExt;

                let offset = &mut 0;

                $(
                    self.$cluster_name.read_with(offset, bytes)?;
                )+

                Ok(())
            }

            fn try_write(&self, bytes: &mut [u8]) -> byte::Result<usize> {
                use byte::BytesExt;

                let offset = &mut 0;

                $(
                    let _ = self.$cluster_name.write_with(offset, bytes)?;
                )+

                Ok(*offset)
            }

            fn update(&mut self, counter: u64) -> () {
                $(
                    if (counter % (self.$cluster_name.update_frequency() as u64) == 0) {
                        self.$cluster_name.update();
                    }
                )+

                self.ctx_update();
            }
        }
    };
}
