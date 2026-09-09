use bon::Builder;
use zb_hal::{Ieee802154Driver, NwkMac};
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use zb_types::common::PanId;
use zb_types::mac::{Channel, ChannelMask, MacFrame};

#[derive(Builder, Clone, Copy, Debug)]
pub struct MockDriver {
    extended_address: ExtendedAddress,
    pan_id: Option<PanId>,
    short_addr: Option<NwkAddress>,
    rx_on_when_idle: bool,
    channel: Channel,
}

impl Ieee802154Driver for MockDriver {
    fn get_extended_address(&self) -> ExtendedAddress { self.extended_address }

    fn get_channel_mask(&self) -> ChannelMask { ChannelMask::default() }

    fn is_rx_on_when_idle(&self) -> bool {
        self.rx_on_when_idle
    }

    fn get_pan_id(&self) -> Option<PanId> { self.pan_id }

    async fn set_pan_id(&mut self, pan_id: Option<PanId>) -> () { self.pan_id = pan_id; }

    fn get_short_address(&self) -> Option<NwkAddress> { self.short_addr }

    async fn set_short_address(&mut self, short_addr: Option<NwkAddress>) -> () {
        self.short_addr = short_addr;
    }

    async fn set_channel(&mut self, channel: Channel) -> () { self.channel = channel; }

    async fn transmit(&mut self, _frame: &[u8]) -> Result<(), byte::Error> { Ok(()) }

    async fn flush(&mut self) -> () {}

    async fn poll(&mut self) -> Option<MacFrame> { None }

    async fn wait_frame(&mut self) -> MacFrame { loop {} }

    async fn reset(&mut self, set_default_pib: bool) -> () {
        if set_default_pib {
            self.pan_id = None;
            self.short_addr = None;
            self.channel = Channel::Channel11;
        }
    }
}

impl NwkMac for MockDriver {}