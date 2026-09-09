use zigbee::zcl::cluster::types::Attribute;
use byte::BytesExt;
use byte::TryRead;
use core::fmt::Debug;
use zb_macros::{zcl_attr, zcl_cluster};
use zigbee::zcl::cluster::types::{AttributeAccess, ClusterType};
use byte_derive::{TryRead, TryWrite};
use zigbee::zcl::frame::{SpecificZclCommand, ZclFrameCommand};

#[zcl_attr(identifier = 0x0000, access = AttributeAccess::READ_WRITE)]
pub struct IdentifyTime(u16);

#[derive(Copy, Clone, Debug, TryRead, TryWrite)]
#[repr(u8)]
pub enum EffectIdentifier {
    Blink = 0x00,
    Breathe = 0x01,
    Okay = 0x02,
    ChannelChange = 0x0b,
    Finish = 0xfe,
    Stop = 0xff,
}

#[derive(Copy, Clone, Debug, TryRead, TryWrite)]
#[repr(u8)]
pub enum EffectVariant {
    Default = 0x00,
}

pub trait IdentifyClusterHandler: Debug {
    fn identify_start(&mut self, seconds: u16);
    fn identify_stop(&mut self);
    fn identify_effect(&mut self, identifier: EffectIdentifier, _variant: EffectVariant);
}

#[zcl_cluster(
    identifier = 0x0003,
    cluster_type = ClusterType::Server,
    cmd_handler = identify_custom_command_handler,
    update_handler = identify_update_handler,
    frequency = 10
)]
pub struct IdentifyCluster<H: IdentifyClusterHandler> {
    pub identify_time: IdentifyTime,
    pub handler: H,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum IdentifyZclCommand {
    Identify(u16) = 0x0,
    IdentifyQuery = 0x1,
    TriggerEffect(EffectIdentifier, EffectVariant) = 0x40,
}

impl TryRead<'_, u8> for IdentifyZclCommand {
    fn try_read(bytes: &[u8], cmd_id: u8) -> byte::Result<(Self, usize)> {
        match cmd_id {
            0x0 => {
                let time = bytes.read_with(&mut 0, byte::LE)?;
                Ok((IdentifyZclCommand::Identify(time), 2))
            }
            0x1 => Ok((IdentifyZclCommand::IdentifyQuery, 0)),
            0x40 => {
                let effect = bytes.read_with(&mut 0, byte::LE)?;
                let variant = bytes.read_with(&mut 1, byte::LE)?;

                Ok((IdentifyZclCommand::TriggerEffect(effect, variant), 2))
            }
            _ => Err(byte::Error::BadInput {
                err: "invalid command id for Identify cluster",
            }),
        }
    }
}

fn identify_custom_command_handler<H: IdentifyClusterHandler>(
    this: &mut IdentifyCluster<H>,
    cmd: &SpecificZclCommand,
) -> Option<ZclFrameCommand> {
    let (cmd, _) = IdentifyZclCommand::try_read(cmd.data.as_slice(), cmd.identifier).ok()?;

    match cmd {
        IdentifyZclCommand::Identify(time) => {
            if let Ok(_) = this.identify_time.set_value(time) {
                if time == 0 {
                    this.handler.identify_stop();
                } else {
                    this.handler.identify_start(time);
                }
            }
            None
        }
        IdentifyZclCommand::IdentifyQuery => {
            if this.identify_time.get_value() > 0 {
                Some(ZclFrameCommand::Specific(SpecificZclCommand {
                    identifier: 0x00,
                    data: this.identify_time.get_value().to_le_bytes().as_slice().into(),
                }))
            } else {
                None
            }
        }
        IdentifyZclCommand::TriggerEffect(effect, variant) => {
            this.handler.identify_effect(effect, variant);
            None
        }
    }
}

fn identify_update_handler<H: IdentifyClusterHandler>(this: &mut IdentifyCluster<H>) -> () {
    this.identify_time.value = this.identify_time.value.saturating_sub(1);
}

