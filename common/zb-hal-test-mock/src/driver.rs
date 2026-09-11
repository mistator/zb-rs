use alloc::collections::VecDeque;
use bon::{Builder};
use byte::TryRead;
use zb_hal::{Ieee802154Driver, NwkMac};
use zb_types::common::ExtendedAddress;
use zb_types::common::NwkAddress;
use zb_types::common::PanId;
use zb_types::mac::{Channel, ChannelMask, MacFrame};

pub const DEFAULT_EXT_ADDR: ExtendedAddress = ExtendedAddress(0x1234_5678_90ab_cdef);
pub const DEFAULT_NWK_ADDR: NwkAddress = NwkAddress(0x1234);
pub const DEFAULT_NWK_PAN_ID: PanId = PanId(0x1234);
pub const DEFAULT_CHANNEL: Channel = Channel::Channel11;

#[derive(Builder)]
pub struct MockDriver {
    #[builder(default = DEFAULT_EXT_ADDR)]
    extended_address: ExtendedAddress,
    pan_id: Option<PanId>,
    short_addr: Option<NwkAddress>,
    #[builder(default = true)]
    rx_on_when_idle: bool,
    #[builder(default = DEFAULT_CHANNEL)]
    channel: Channel,

    #[builder(default = VecDeque::new())]
    received_queue: VecDeque<MacFrame>,
    #[builder(default = VecDeque::new())]
    transmitted_queue: VecDeque<MacFrame>,
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

    async fn transmit(&mut self, buffer: &[u8]) -> Result<(), byte::Error> {
        let (frame, _) = MacFrame::try_read(buffer, ())?;
        self.transmitted_queue.push_back(frame);
        Ok(())
    }

    async fn flush(&mut self) -> () {
        self.received_queue.clear()
    }

    async fn poll(&mut self) -> Option<MacFrame> {
        self.received_queue.pop_front()
    }

    async fn wait_frame(&mut self) -> MacFrame {
        let frame = self.received_queue.pop_front();
        if let Some(frame) = frame {
            return frame;
        }

        panic!("no frame");
    }

    async fn reset(&mut self, set_default_pib: bool) -> () {
        if set_default_pib {
            self.pan_id = None;
            self.short_addr = None;
            self.channel = Channel::Channel11;
        }
    }
}

impl MockDriver {
    pub fn default() -> Self {
        Self::builder()
            .pan_id(DEFAULT_NWK_PAN_ID)
            .short_addr(DEFAULT_NWK_ADDR)
            .build()
    }

    pub fn default_not_connected() -> Self {
        Self::builder().build()
    }

    pub fn add_received_frame(&mut self, frame: MacFrame) -> () {
        self.received_queue.push_back(frame);
    }

    pub fn get_transmitted_frames(&self) -> &VecDeque<MacFrame> {
        &self.transmitted_queue
    }

    pub fn get_last_transmitted_frame(&self) -> Option<&MacFrame> {
        self.transmitted_queue.back()
    }

    pub fn clear_transmitted_frames(&mut self) -> () {
        self.transmitted_queue.clear();
    }
}

impl NwkMac for MockDriver {}
