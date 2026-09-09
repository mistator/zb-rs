use bon::bon;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use zb_hal::{NwkMac, StorageRegion};
use zb_macros::BitStruct;
use zb_types::common::{ExtendedAddress, NwkAddress};


use crate::nwk::ctx::{BaseNwk};
use crate::nwk::ctx::{Initialized, InitializedState, Nwk};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, TryRead, TryWrite)]
#[repr(u8)]
pub enum FrameType {
    #[default]
    Data = 0b00,
    NwkCommand = 0b01,
    Reserved = 0b10,
    InterPan = 0b11,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, TryRead, TryWrite)]
#[repr(u8)]
pub enum DiscoverRoute {
    #[default]
    Suppress = 0x0,
    Enable = 0x1,
}

#[derive(BitStruct, Clone, Copy, Debug, Eq, PartialEq)]
#[bit_struct(repr = u8)]
pub struct MulticastControl {
    #[bit_struct(len = 2)]
    pub multicast_mode: MulticastMode,
    #[bit_struct(len = 3)]
    pub non_member_radius: u8,
    #[bit_struct(len = 3)]
    pub max_non_member_radius: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, TryRead, TryWrite)]
#[repr(u8)]
pub enum MulticastMode {
    NonMember = 0x0,
    Member = 0x1,
}

#[derive(Clone, Debug, TryRead, TryWrite)]
pub struct SourceRouteSubframe {
    pub relay_count: u8,
    pub relay_index: u8,
    pub relay_list: zb_types::Vec<u16, 32>,
}

#[derive(BitStruct, Clone, Copy, Default, Eq, PartialEq, Debug)]
#[bit_struct(repr = u16)]
pub struct FrameControl {
    #[bit_struct(len = 2)]
    pub frame_type: FrameType,
    #[bit_struct(len = 4)]
    pub version: u8,
    #[bit_struct(len = 2)]
    pub route_discovery: DiscoverRoute,
    pub multicast: bool,
    pub security: bool,
    pub source_route: bool,
    pub dst_ext_addr: bool,
    pub src_ext_addr: bool,
    pub end_device_initiator: bool,
}

#[derive(Clone, Debug, Default, TryRead, TryWrite)]
pub struct NwkHeader {
    pub(crate) control: FrameControl,
    pub destination: NwkAddress,
    pub source: NwkAddress,
    pub radius: u8,
    pub sequence_number: u8,
    #[byte(parse_if = control.dst_ext_addr)]
    pub destination_ieee: Option<ExtendedAddress>,
    #[byte(parse_if = control.src_ext_addr)]
    pub source_ieee: Option<ExtendedAddress>,
    #[byte(parse_if = control.multicast)]
    pub multicast_control: Option<MulticastControl>,
    #[byte(parse_if = control.source_route)]
    pub source_route_subframe: Option<SourceRouteSubframe>,
}


#[bon]
impl NwkHeader {
    #[builder]
    pub fn cmd<T: InitializedState, D: NwkMac, S: StorageRegion>(
        #[builder(start_fn)] ctx: &mut Nwk<Initialized<T>, D, S>,
        #[builder(default = true)] security: bool,
        destination: NwkAddress,
        destination_ieee: Option<ExtendedAddress>,
        // multicast_control: Option<MulticastControl>, Deprecated
        source_route_subframe: Option<SourceRouteSubframe>,
        sequence_number: Option<u8>,
        radius: Option<u8>,
    ) -> Self {
        let ext_addr = ctx.get_ext_addr().into();

        Self::builder(ctx)
            .frame_type(FrameType::NwkCommand)
            .security(security)
            .route_discovery(false)
            .destination(destination)
            .maybe_destination_ieee(destination_ieee)
            .source_ieee(ext_addr)
            .maybe_source_route_subframe(source_route_subframe)
            .maybe_sequence_number(sequence_number)
            .maybe_radius(radius)
            .build()
    }

    #[builder]
    pub fn new<T: InitializedState, D: NwkMac, S: StorageRegion>(
        #[builder(start_fn)] ctx: &mut Nwk<Initialized<T>, D, S>,
        frame_type: FrameType,
        #[builder(default = true)] security: bool,
        #[builder(default = false)] route_discovery: bool,
        destination: NwkAddress,
        destination_ieee: Option<ExtendedAddress>,
        source_ieee: Option<ExtendedAddress>,
        // pub multicast_control: Option<MulticastControl>, Deprecated
        source_route_subframe: Option<SourceRouteSubframe>,
        source: Option<NwkAddress>,
        sequence_number: Option<u8>,
        radius: Option<u8>,
    ) -> Self {
        let control = FrameControl {
            frame_type,
            version: 2,
            route_discovery: if route_discovery {
                DiscoverRoute::Enable
            } else {
                DiscoverRoute::Suppress
            },
            multicast: false,
            security,
            source_route: source_route_subframe.is_some(),
            dst_ext_addr: destination_ieee.is_some(),
            src_ext_addr: source_ieee.is_some(),
            //end_device_initiator: !ctx.is_router() && *ctx.get_parent_information() != ParentInformation::default(),
            end_device_initiator: false // TODO
        };

        Self {
            destination,
            source: source.unwrap_or_else(|| ctx.ctx.addr),
            radius: radius.unwrap_or_else(|| ctx.ctx.get_profile().nwk_max_depth * 2),
            sequence_number: sequence_number.unwrap_or_else(|| ctx.get_seq_number()),
            destination_ieee,
            source_ieee,
            multicast_control: None,
            source_route_subframe,
            control,
        }
    }
}
