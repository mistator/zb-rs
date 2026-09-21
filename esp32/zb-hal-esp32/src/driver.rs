use alloc::sync::Arc;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::signal::Signal;
use esp_hal::efuse;
use esp_radio::ieee802154::Error;
use esp_radio::ieee802154::Ieee802154;
use esp_radio::ieee802154::{CcaMode, Config};
use zb_hal::{Ieee802154Driver, NwkMac};
use zb_types::Vec;
use zb_types::common::{ExtendedAddress, NwkAddress, PanId};
use zb_types::mac::{Channel, ChannelMask, MacFrame};

static TX_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static RX_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();

#[derive(Clone, Debug)]
pub struct Esp32Driver {
    ext_addr: ExtendedAddress,
    default_channel: u8,
    rx_when_idle: bool,
    rx_queue_size: usize,
    config: Arc<Mutex<CriticalSectionRawMutex, Config>>,
    driver: Arc<Mutex<CriticalSectionRawMutex, Ieee802154<'static>>>,
}

#[derive(Copy, Clone, Debug)]
pub struct MultipleInitializationError;

#[bon::bon]
impl Esp32Driver {
    #[builder]
    pub fn new(
        #[builder(start_fn)] mut driver: Ieee802154<'static>,
        ext_addr: Option<ExtendedAddress>,
        #[builder(default = 11)] default_channel: u8,
        #[builder(default = true)] rx_when_idle: bool,
        #[builder(default = 10)] rx_queue_size: usize,
    ) -> Result<Self, MultipleInitializationError> {
        driver.set_rx_available_callback_fn(Self::rx_callback);
        driver.set_tx_done_callback_fn(Self::tx_callback);

        let ext_addr = ext_addr.unwrap_or_else(|| {
            let mac = efuse::base_mac_address();
            let bytes = mac.as_bytes();
            let value = u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], 0xff, 0xfe, bytes[3], bytes[4], bytes[5],
            ]);
            ExtendedAddress(value)
        });

        let mut slf = Self {
            config: Arc::new(Mutex::new(Config::default())),
            driver: Arc::new(Mutex::new(driver)),
            ext_addr,
            default_channel,
            rx_when_idle,
            rx_queue_size,
        };
        slf.reset(true);

        Ok(slf)
    }
}

impl Esp32Driver {
    fn set_config(&self) {
        let config = self.config.lock(|config| config.clone());
        unsafe { self.driver.lock_mut(|driver| driver.set_config(config)); }
    }

    fn rx_callback() {
        RX_SIGNAL.signal(());
    }

    fn tx_callback() {
        TX_SIGNAL.signal(());
    }

    async fn wait_rx_available(&self) {
        RX_SIGNAL.reset();
        RX_SIGNAL.wait().await;
    }
}

impl Ieee802154Driver for Esp32Driver {
    fn get_extended_address(&self) -> ExtendedAddress {
        self.ext_addr
    }

    fn get_channel_mask(&self) -> ChannelMask {
        ChannelMask::default()
    }

    fn is_rx_on_when_idle(&self) -> bool {
        self.config.lock(|config| config.rx_when_idle)
    }

    fn get_pan_id(&self) -> Option<PanId> {
        self.config.lock(|config| config.pan_id).map(PanId)
    }

    fn set_pan_id(&mut self, pan_id: Option<PanId>) -> () {
        unsafe { self.config.lock_mut(|config| config.pan_id = pan_id.map(|pan_id| pan_id.0)) }
        self.set_config();
    }

    fn get_short_address(&self) -> Option<NwkAddress> {
        self.config.lock(|config| config.short_addr).map(NwkAddress)
    }

    fn set_short_address(&mut self, short_addr: Option<NwkAddress>) -> () {
        unsafe { self.config.lock_mut(|config| config.short_addr = short_addr.map(|addr| addr.0)) }
        self.set_config();
    }

    fn get_channel(&self) -> Channel {
        Channel::from(self.config.lock(|config| config.channel))
    }

    fn set_channel(&mut self, channel: Channel) -> () {
        unsafe { self.config.lock_mut(|config| config.channel = channel as u8) };
        self.set_config();
    }

    async fn transmit(&mut self, frame: &[u8]) -> Result<(), byte::Error> {
        TX_SIGNAL.reset();
        let result = unsafe { self.driver.lock_mut(|driver| {
            driver.transmit_raw(frame, true).map_err(|err| match err {
                Error::Incomplete => byte::Error::Incomplete,
                Error::BadInput => byte::Error::BadInput {
                    err: "error transmitting frame in ESP32 driver",
                },
            })
        }) };

        match result {
            Err(err) => {
                log::warn!("[ESP32-DRIVER] error transmitting frame: {:?}", err);
                unsafe { self.driver.lock_mut(|driver| driver.start_receive()); }
                Err(err)
            }
            Ok(()) => {
                TX_SIGNAL.wait().await;
                Ok(())
            }
        }
    }

    fn flush(&mut self) -> () {
        while self.poll().is_some() {}
    }

    fn poll(&mut self) -> Option<MacFrame> {
        unsafe { self.driver.lock_mut(|driver| {
            driver
                .received()?
                .map_err(|err| {
                    log::warn!("error in ESP32 driver while receiving frame: {:?}", err);
                    err
                })
                .ok()
                .map(|rf| MacFrame {
                    header: rf.frame.header,
                    content: rf.frame.content,
                    payload: Vec::from_iter(rf.frame.payload),
                    footer: rf.frame.footer,
                })
        }) }
    }

    async fn wait_frame(&mut self) -> MacFrame {
        loop {
            if let Some(result) = self.poll() {
                return result;
            }
            self.wait_rx_available().await;
        }
    }

    fn reset(&mut self, set_default_pib: bool) {
        unsafe { self.config.lock_mut(|config| {
            config.auto_ack_tx = true;
            config.auto_ack_rx = true;
            config.promiscuous = true;
            config.rx_when_idle = self.rx_when_idle;
            config.rx_queue_size = self.rx_queue_size;
            config.txpower = 10;
            config.cca_threshold = -60;
            config.cca_mode = CcaMode::Ed;
            config.enhance_ack_tx = false;

            if set_default_pib {
                config.pan_id = None;
                config.short_addr = None;
                config.channel = self.default_channel;
            }
        }); }

        self.set_config()
    }
}

impl NwkMac for Esp32Driver {}