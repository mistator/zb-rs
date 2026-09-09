use byte::TryRead;
use alloc::string::String;
use zb_macros::{zcl_attr, zcl_cluster, BitStruct};
use zigbee::zcl::cluster::types::{AttributeAccess, ClusterType};
use zigbee::zcl::frame::{SpecificZclCommand, ZclFrameCommand};

#[repr(u8)]
#[derive(Clone, Debug, Default)]
pub enum PowerSources {
    #[default]
    Unknown = 0,
    MainsSinglePhase = 1,
    MainsThreePhase = 2,
    Battery = 3,
    DCSource = 4,
    EmergencyMainsConstantlyPowered = 5,
    EmergencyMainsAndTransferSwitch = 6,
}

impl From<PowerSources> for u8 {
    fn from(value: PowerSources) -> Self { value as u8 }
}

impl TryFrom<u8> for PowerSources {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PowerSources::Unknown),
            1 => Ok(PowerSources::MainsSinglePhase),
            2 => Ok(PowerSources::MainsThreePhase),
            3 => Ok(PowerSources::Battery),
            4 => Ok(PowerSources::DCSource),
            5 => Ok(PowerSources::EmergencyMainsConstantlyPowered),
            6 => Ok(PowerSources::EmergencyMainsAndTransferSwitch),
            _ => Err(()),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Debug, Default)]
pub enum PhysicalEnvironments {
    #[default]
    UnspecifiedEnvironment = 0x00,
    Atrium = 0x01,
    Bar = 0x02,
    Courtyard = 0x03,
    Bathroom = 0x04,
    Bedroom = 0x05,
    BilliardRoom = 0x06,
    UtilityRoom = 0x07,
    Cellar = 0x08,
    StorageCloset = 0x09,
    Theater = 0x0a,
    Office = 0x0b,
    Deck = 0x0c,
    Den = 0x0d,
    DiningRoom = 0x0e,
    ElectricalRoom = 0x0f,
    Elevator = 0x10,
    Entry = 0x11,
    FamilyRoom = 0x12,
    MainFloor = 0x13,
    Upstairs = 0x14,
    Downstairs = 0x15,
    BasementLowerLevel = 0x16,
    Gallery = 0x17,
    GameRoom = 0x18,
    Garage = 0x19,
    Gym = 0x1a,
    Hallway = 0x1b,
    House = 0x1c,
    Kitchen = 0x1d,
    LaundryRoom = 0x1e,
    Library = 0x1f,
    MasterBedroom = 0x20,
    MudRoom = 0x21,
    Nursery = 0x22,
    Pantry = 0x23,
    Office2 = 0x24,
    Outside = 0x25,
    Pool = 0x26,
    Porch = 0x27,
    SewingRoom = 0x28,
    SittingRoom = 0x29,
    Stairway = 0x2a,
    Yard = 0x2b,
    Attic = 0x2c,
    HotTub = 0x2d,
    LivingRoom = 0x2e,
    Sauna = 0x2f,
    Workshop = 0x30,
    GuestBedroom = 0x31,
    GuestBath = 0x32,
    PowderRoom = 0x33,
    BackYard = 0x34,
    FrontYard = 0x35,
    Patio = 0x36,
    Driveway = 0x37,
    SunRoom = 0x38,
    LivingRoom2 = 0x39,
    Spa = 0x3a,
    Whirlpool = 0x3b,
    Shed = 0x3c,
    EquipmentStorage = 0x3d,
    CraftRoom = 0x3e,
    Fountain = 0x3f,
    Pond = 0x40,
    ReceptionRoom = 0x41,
    BreakfastRoom = 0x42,
    Nook = 0x43,
    Garden = 0x44,
    Balcony = 0x45,
    PanicRoom = 0x46,
    Terrace = 0x47,
    Roof = 0x48,
    Toilet = 0x49,
    ToiletMain = 0x4a,
    OutsideToilet = 0x4b,
    ShowerRoom = 0x4c,
    Study = 0x4d,
    FrontGarden = 0x4e,
    BackGarden = 0x4f,
    Kettle = 0x50,
    Television = 0x51,
    Stove = 0x52,
    Microwave = 0x53,
    Toaster = 0x54,
    Vacuum = 0x55,
    Appliance = 0x56,
    FrontDoor = 0x57,
    BackDoor = 0x58,
    FridgeDoor = 0x59,
    MedicationCabinetDoor = 0x60,
    WardrobeDoor = 0x61,
    FrontCupboardDoor = 0x62,
    OtherDoor = 0x63,
    WaitingRoom = 0x64,
    TriageRoom = 0x65,
    DoctorsOffice = 0x66,
    PatientsPrivateRoom = 0x67,
    ConsultationRoom = 0x68,
    NurseStation = 0x69,
    Ward = 0x6a,
    Corridor = 0x6b,
    OperatingTheatre = 0x6c,
    DentalSurgeryRoom = 0x6d,
    MedicalImagingRoom = 0x6e,
    DecontaminationRoom = 0x6f,
    UnknownEnvironment = 0xff,
}

impl From<PhysicalEnvironments> for u8 {
    fn from(value: PhysicalEnvironments) -> Self { value as u8 }
}

impl TryFrom<u8> for PhysicalEnvironments {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(PhysicalEnvironments::UnspecifiedEnvironment),
            0x01 => Ok(PhysicalEnvironments::Atrium),
            0x02 => Ok(PhysicalEnvironments::Bar),
            0x03 => Ok(PhysicalEnvironments::Courtyard),
            0x04 => Ok(PhysicalEnvironments::Bathroom),
            0x05 => Ok(PhysicalEnvironments::Bedroom),
            0x06 => Ok(PhysicalEnvironments::BilliardRoom),
            0x07 => Ok(PhysicalEnvironments::UtilityRoom),
            0x08 => Ok(PhysicalEnvironments::Cellar),
            0x09 => Ok(PhysicalEnvironments::StorageCloset),
            0x0a => Ok(PhysicalEnvironments::Theater),
            0x0b => Ok(PhysicalEnvironments::Office),
            0x0c => Ok(PhysicalEnvironments::Deck),
            0x0d => Ok(PhysicalEnvironments::Den),
            0x0e => Ok(PhysicalEnvironments::DiningRoom),
            0x0f => Ok(PhysicalEnvironments::ElectricalRoom),
            0x10 => Ok(PhysicalEnvironments::Elevator),
            0x11 => Ok(PhysicalEnvironments::Entry),
            0x12 => Ok(PhysicalEnvironments::FamilyRoom),
            0x13 => Ok(PhysicalEnvironments::MainFloor),
            0x14 => Ok(PhysicalEnvironments::Upstairs),
            0x15 => Ok(PhysicalEnvironments::Downstairs),
            0x16 => Ok(PhysicalEnvironments::BasementLowerLevel),
            0x17 => Ok(PhysicalEnvironments::Gallery),
            0x18 => Ok(PhysicalEnvironments::GameRoom),
            0x19 => Ok(PhysicalEnvironments::Garage),
            0x1a => Ok(PhysicalEnvironments::Gym),
            0x1b => Ok(PhysicalEnvironments::Hallway),
            0x1c => Ok(PhysicalEnvironments::House),
            0x1d => Ok(PhysicalEnvironments::Kitchen),
            0x1e => Ok(PhysicalEnvironments::LaundryRoom),
            0x1f => Ok(PhysicalEnvironments::Library),
            0x20 => Ok(PhysicalEnvironments::MasterBedroom),
            0x21 => Ok(PhysicalEnvironments::MudRoom),
            0x22 => Ok(PhysicalEnvironments::Nursery),
            0x23 => Ok(PhysicalEnvironments::Pantry),
            0x24 => Ok(PhysicalEnvironments::Office2),
            0x25 => Ok(PhysicalEnvironments::Outside),
            0x26 => Ok(PhysicalEnvironments::Pool),
            0x27 => Ok(PhysicalEnvironments::Porch),
            0x28 => Ok(PhysicalEnvironments::SewingRoom),
            0x29 => Ok(PhysicalEnvironments::SittingRoom),
            0x2a => Ok(PhysicalEnvironments::Stairway),
            0x2b => Ok(PhysicalEnvironments::Yard),
            0x2c => Ok(PhysicalEnvironments::Attic),
            0x2d => Ok(PhysicalEnvironments::HotTub),
            0x2e => Ok(PhysicalEnvironments::LivingRoom),
            0x2f => Ok(PhysicalEnvironments::Sauna),
            0x30 => Ok(PhysicalEnvironments::Workshop),
            0x31 => Ok(PhysicalEnvironments::GuestBedroom),
            0x32 => Ok(PhysicalEnvironments::GuestBath),
            0x33 => Ok(PhysicalEnvironments::PowderRoom),
            0x34 => Ok(PhysicalEnvironments::BackYard),
            0x35 => Ok(PhysicalEnvironments::FrontYard),
            0x36 => Ok(PhysicalEnvironments::Patio),
            0x37 => Ok(PhysicalEnvironments::Driveway),
            0x38 => Ok(PhysicalEnvironments::SunRoom),
            0x39 => Ok(PhysicalEnvironments::LivingRoom2),
            0x3a => Ok(PhysicalEnvironments::Spa),
            0x3b => Ok(PhysicalEnvironments::Whirlpool),
            0x3c => Ok(PhysicalEnvironments::Shed),
            0x3d => Ok(PhysicalEnvironments::EquipmentStorage),
            0x3e => Ok(PhysicalEnvironments::CraftRoom),
            0x3f => Ok(PhysicalEnvironments::Fountain),
            0x40 => Ok(PhysicalEnvironments::Pond),
            0x41 => Ok(PhysicalEnvironments::ReceptionRoom),
            0x42 => Ok(PhysicalEnvironments::BreakfastRoom),
            0x43 => Ok(PhysicalEnvironments::Nook),
            0x44 => Ok(PhysicalEnvironments::Garden),
            0x45 => Ok(PhysicalEnvironments::Balcony),
            0x46 => Ok(PhysicalEnvironments::PanicRoom),
            0x47 => Ok(PhysicalEnvironments::Terrace),
            0x48 => Ok(PhysicalEnvironments::Roof),
            0x49 => Ok(PhysicalEnvironments::Toilet),
            0x4a => Ok(PhysicalEnvironments::ToiletMain),
            0x4b => Ok(PhysicalEnvironments::OutsideToilet),
            0x4c => Ok(PhysicalEnvironments::ShowerRoom),
            0x4d => Ok(PhysicalEnvironments::Study),
            0x4e => Ok(PhysicalEnvironments::FrontGarden),
            0x4f => Ok(PhysicalEnvironments::BackGarden),
            0x50 => Ok(PhysicalEnvironments::Kettle),
            0x51 => Ok(PhysicalEnvironments::Television),
            0x52 => Ok(PhysicalEnvironments::Stove),
            0x53 => Ok(PhysicalEnvironments::Microwave),
            0x54 => Ok(PhysicalEnvironments::Toaster),
            0x55 => Ok(PhysicalEnvironments::Vacuum),
            0x56 => Ok(PhysicalEnvironments::Appliance),
            0x57 => Ok(PhysicalEnvironments::FrontDoor),
            0x58 => Ok(PhysicalEnvironments::BackDoor),
            0x59 => Ok(PhysicalEnvironments::FridgeDoor),
            0x60 => Ok(PhysicalEnvironments::MedicationCabinetDoor),
            0x61 => Ok(PhysicalEnvironments::WardrobeDoor),
            0x62 => Ok(PhysicalEnvironments::FrontCupboardDoor),
            0x63 => Ok(PhysicalEnvironments::OtherDoor),
            0x64 => Ok(PhysicalEnvironments::WaitingRoom),
            0x65 => Ok(PhysicalEnvironments::TriageRoom),
            0x66 => Ok(PhysicalEnvironments::DoctorsOffice),
            0x67 => Ok(PhysicalEnvironments::PatientsPrivateRoom),
            0x68 => Ok(PhysicalEnvironments::ConsultationRoom),
            0x69 => Ok(PhysicalEnvironments::NurseStation),
            0x6a => Ok(PhysicalEnvironments::Ward),
            0x6b => Ok(PhysicalEnvironments::Corridor),
            0x6c => Ok(PhysicalEnvironments::OperatingTheatre),
            0x6d => Ok(PhysicalEnvironments::DentalSurgeryRoom),
            0x6e => Ok(PhysicalEnvironments::MedicalImagingRoom),
            0x6f => Ok(PhysicalEnvironments::DecontaminationRoom),
            0xff => Ok(PhysicalEnvironments::UnknownEnvironment),
            _ => Err(()),
        }
    }
}

#[derive(BitStruct, Clone, Copy, Debug, Default)]
#[bit_struct(repr = u8)]
pub struct AlarmMask {
    pub general_hardware_fault: bool,
    pub general_software_fault: bool,
}

#[derive(BitStruct, Clone, Copy, Debug, Default)]
#[bit_struct(repr = u8)]
pub struct DisableLocalConfigMask {
    pub reset_to_factory_defaults_disabled: bool,
    pub device_configuration_disabled: bool,
}

#[zcl_attr(identifier = 0x0000, default = 0x02)] pub struct ZclVersion(u8);
#[zcl_attr(identifier = 0x0001)] pub struct ApplicationVersion(u8);
#[zcl_attr(identifier = 0x0002)] pub struct StackVersion(u8);
#[zcl_attr(identifier = 0x0003)] pub struct HwVersion(u8);
#[zcl_attr(identifier = 0x0004)] pub struct ManufacturerName(String);
#[zcl_attr(identifier = 0x0005)] pub struct ModelIdentifier(String);
#[zcl_attr(identifier = 0x0006)] pub struct DateCode(String);
#[zcl_attr(identifier = 0x0007, variant = ZclData::Enum8)] pub struct PowerSource(PowerSources);
#[zcl_attr(identifier = 0x0010)] pub struct LocationDescription(String);
#[zcl_attr(identifier = 0x0011, variant = ZclData::Enum8)] pub struct PhysicalEnvironment(PhysicalEnvironments);
#[zcl_attr(identifier = 0x0012, access = AttributeAccess::READ_WRITE, default = true)] pub struct DeviceEnabled(bool);
#[zcl_attr(identifier = 0x0013, access = AttributeAccess::READ_WRITE, variant = ZclData::Bitmap8)] pub struct Alarm(AlarmMask);
#[zcl_attr(identifier = 0x0014, access = AttributeAccess::READ_WRITE, variant = ZclData::Bitmap8)] pub struct DisableLocalConfig(DisableLocalConfigMask);
#[zcl_attr(identifier = 0x0015)] pub struct SwBuildId(String);

#[zcl_cluster(
    identifier = 0x0000,
    cluster_type = ClusterType::Client,
    cmd_handler = basic_cmd_handler
)]
pub struct BasicCluster {
    pub version: ZclVersion,
    pub application_version: ApplicationVersion,
    pub stack_version: StackVersion,
    pub hw_version: HwVersion,
    pub manufacturer_name: ManufacturerName,
    pub model_identifier: ModelIdentifier,
    pub date_code: DateCode,
    pub power_source: PowerSource,
    pub location: LocationDescription,
    pub physical_environment: PhysicalEnvironment,
    pub device_enabled: DeviceEnabled,
    pub alarm: Alarm,
    pub disable_local_config: DisableLocalConfig,
    pub sw_build_id: SwBuildId,
}

#[derive(Default)]
pub struct BasicClusterConfig {
    pub application_version: u8,
    pub stack_version: u8,
    pub hw_version: u8,
    pub manufacturer_name: String,
    pub model_identifier: String,
    pub date_code: String,
    pub power_source: PowerSources,
    pub sw_build_id: String,
}

impl BasicCluster {
    pub fn with_config(config: BasicClusterConfig) -> Self {
        Self {
            version: ZclVersion::default(),
            application_version: ApplicationVersion::new(config.application_version),
            stack_version: StackVersion::new(config.stack_version),
            hw_version: HwVersion::new(config.hw_version),
            manufacturer_name: ManufacturerName::new(config.manufacturer_name),
            model_identifier: ModelIdentifier::new(config.model_identifier),
            date_code: DateCode::new(config.date_code),
            power_source: PowerSource::new(config.power_source),
            location: LocationDescription::default(),
            physical_environment: PhysicalEnvironment::default(),
            device_enabled: DeviceEnabled::default(),
            alarm: Alarm::default(),
            disable_local_config: DisableLocalConfig::default(),
            sw_build_id: SwBuildId::new(config.sw_build_id),
        }
    }
}

fn basic_cmd_handler(_: &mut BasicCluster, cmd: &SpecificZclCommand) -> Option<ZclFrameCommand> {
    let (cmd, _) = BasicZclCommand::try_read(cmd.data.as_slice(), cmd.identifier).ok()?;
    match cmd {
        BasicZclCommand::ResetToFactoryDefaults => {
            todo!()
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum BasicZclCommand {
    ResetToFactoryDefaults = 0x0,
}

impl TryRead<'_, u8> for BasicZclCommand {
    fn try_read(_: &[u8], cmd_id: u8) -> byte::Result<(Self, usize)> {
        match cmd_id {
            0x0 => Ok((BasicZclCommand::ResetToFactoryDefaults, 0)),
            _ => Err(byte::Error::BadInput {
                err: "invalid command id for Basic cluster",
            }),
        }
    }
}
