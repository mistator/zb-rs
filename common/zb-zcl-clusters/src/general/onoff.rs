use byte::TryRead;
use byte_derive::TryRead;
use byte_derive::TryWrite;
use core::cmp::max;
use core::cmp::min;
use core::fmt::Debug;
use zb_macros::{zcl_attr, zcl_cluster};
use zigbee::zcl::cluster::types::{AttributeAccess, ClusterType};
use zigbee::zcl::frame::{SpecificZclCommand, ZclFrameCommand};

pub trait OnOffClusterHandler: Sized + Debug {
    fn turn_on(&mut self);
    fn turn_off(&mut self);
}

#[zcl_attr(identifier = 0x0, access = AttributeAccess::READ_REPORT, reported = (0x0, 0xffff, None))]
pub struct OnOff(bool);

#[zcl_attr(identifier = 0x4000)] pub struct GlobalSceneControl(bool);
#[zcl_attr(identifier = 0x4001, access = AttributeAccess::READ_WRITE)] pub struct OnTime(u16);
#[zcl_attr(identifier = 0x4002, access = AttributeAccess::READ_WRITE)] pub struct OffWaitTime(u16);

#[zcl_cluster(
    identifier = 0x0006,
    cluster_type = ClusterType::Server,
    cmd_handler = on_off_custom_command_handler,
    update_handler = on_off_update_handler
)]
pub struct OnOffCluster<H: OnOffClusterHandler> {
    #[R] pub onoff: OnOff,
    pub global_scene_control: GlobalSceneControl,
    pub on_time: OnTime,
    pub off_wait_time: OffWaitTime,
    pub handler: H,
}

impl<H: OnOffClusterHandler> OnOffCluster<H> {
    pub fn is_on(&self) -> bool { self.onoff.value }

    pub fn is_off(&self) -> bool { !self.is_on() }

    pub fn on(&mut self) -> () {
        self.onoff.value = true;
        self.off_wait_time.value = 0;

        self.handler.turn_on();
    }

    pub fn off(&mut self) -> () {
        self.onoff.value = false;
        self.on_time.value = 0;

        self.handler.turn_off();
    }

    pub fn toggle(&mut self) -> () {
        if self.is_off() {
            self.on();
        } else {
            self.off();
        }
    }
}

fn on_off_custom_command_handler<H: OnOffClusterHandler>(
    this: &mut OnOffCluster<H>,
    cmd: &SpecificZclCommand,
) -> Option<ZclFrameCommand> {
    let (cmd, _) = OnOffZclCommand::try_read(cmd.data.as_slice(), cmd.identifier).ok()?;

    match cmd {
        OnOffZclCommand::Off => this.off(),
        OnOffZclCommand::On => this.on(),
        OnOffZclCommand::Toggle => this.toggle(),
        OnOffZclCommand::OffWithEffect(_) => this.off(),
        OnOffZclCommand::OnWithRecallGlobalScene => {
            if this.global_scene_control.value {
                return None;
            }

            this.global_scene_control.value = true;
            if this.on_time.value == 0 {
                this.off_wait_time.value = 0;
            }
        }
        OnOffZclCommand::OnWithTimedOff(cmd) => {
            if cmd.accept_only_when_on && !this.onoff.value {
                return None;
            }

            if cmd.off_wait_time > 0 && !this.onoff.value {
                this.off_wait_time.value = min(cmd.off_wait_time, this.off_wait_time.value);
            } else {
                this.on_time.value = max(cmd.on_time, this.on_time.value);
                this.onoff.value = true;
                this.handler.turn_on();
            }
        }
    }

    None
}

fn on_off_update_handler<H: OnOffClusterHandler>(this: &mut OnOffCluster<H>) -> () {
    if this.is_on() && this.on_time.value > 0 && this.on_time.value != u16::MAX {
        this.on_time.value = this.on_time.value.saturating_sub(1);
        if this.on_time.value == 0 {
            this.off();
            this.off_wait_time.value = 0;
        }
    } else {
        this.off_wait_time.value = this.off_wait_time.value.saturating_sub(1);
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum OnOffZclCommand {
    Off = 0x0,
    On = 0x1,
    Toggle = 0x2,
    OffWithEffect(Effect) = 0x40,
    OnWithRecallGlobalScene = 0x41,
    OnWithTimedOff(OnWithTimedOffCmd) = 0x42,
}

impl TryRead<'_, u8> for OnOffZclCommand {
    fn try_read(bytes: &[u8], cmd_id: u8) -> byte::Result<(Self, usize)> {
        match cmd_id {
            0x0 => Ok((OnOffZclCommand::Off, 0)),
            0x1 => Ok((OnOffZclCommand::On, 0)),
            0x2 => Ok((OnOffZclCommand::Toggle, 0)),
            0x40 => {
                let (effect, size) = Effect::try_read(bytes, byte::LE)?;
                Ok((OnOffZclCommand::OffWithEffect(effect), size))
            }
            0x41 => Ok((OnOffZclCommand::OnWithRecallGlobalScene, 0)),
            0x42 => {
                let (cmd, size) = OnWithTimedOffCmd::try_read(bytes, byte::LE)?;
                Ok((OnOffZclCommand::OnWithTimedOff(cmd), size))
            }
            _ => Err(byte::Error::BadInput {
                err: "invalid command id for OnOff cluster",
            }),
        }
    }
}

#[derive(Copy, Clone, Debug, TryRead, TryWrite)]
#[repr(u8)]
pub enum Effect {
    DelayedAllOff(DelayedEffects) = 0x0,
    DyingLight(DyingLightEffects) = 0x1,
}

#[derive(Copy, Clone, Debug, TryRead, TryWrite)]
#[repr(u8)]
pub enum DelayedEffects {
    NoFade = 0x1,
    DimDownThenFade = 0x2,
}

#[derive(Copy, Clone, Debug, TryRead, TryWrite)]
#[repr(u8)]
pub enum DyingLightEffects {
    DimUpThenFadeOff = 0x0,
}

#[derive(Copy, Clone, Debug, TryRead, TryWrite)]
pub struct OnWithTimedOffCmd {
    #[byte(ctx = ())]
    pub accept_only_when_on: bool,
    pub on_time: u16,
    pub off_wait_time: u16,
}