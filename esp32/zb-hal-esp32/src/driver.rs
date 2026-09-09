use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
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
static DRIVER: Mutex<CriticalSectionRawMutex, Option<Ieee802154<'static>>> = Mutex::new(None);

#[derive(Copy, Clone, Debug)]
pub struct Esp32Driver {
    config: Config,
    ext_addr: ExtendedAddress,
    default_channel: u8,
    rx_when_idle: bool,
    rx_queue_size: usize,
}

#[derive(Copy, Clone, Debug)]
pub struct MultipleInitializationError;

#[bon::bon]
impl Esp32Driver {
    #[builder]
    pub async fn new(
        #[builder(start_fn)] mut driver: Ieee802154<'static>,
        ext_addr: Option<ExtendedAddress>,
        #[builder(default = 11)] default_channel: u8,
        #[builder(default = true)] rx_when_idle: bool,
        #[builder(default = 10)] rx_queue_size: usize,
    ) -> Result<Self, MultipleInitializationError> {
        {
            let mut lck = DRIVER.lock().await;
            if (*lck).is_some() {
                return Err(MultipleInitializationError);
            }

            driver.set_rx_available_callback_fn(Self::rx_callback);
            driver.set_tx_done_callback_fn(Self::tx_callback);

            *lck = Some(driver);
        }

        let ext_addr = ext_addr.unwrap_or_else(|| {
            let mac = efuse::base_mac_address();
            let bytes = mac.as_bytes();
            let value = u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], 0xff, 0xfe, bytes[3], bytes[4], bytes[5],
            ]);
            ExtendedAddress(value)
        });

        let mut slf = Self {
            config: Config::default(),
            ext_addr,
            default_channel,
            rx_when_idle,
            rx_queue_size,
        };
        slf.reset(true).await;

        Ok(slf)
    }
}

impl Esp32Driver {
    async fn use_driver<Output, F: FnOnce(&mut Ieee802154<'static>) -> Output>(cb: F) -> Output {
        let mut lck = DRIVER.lock().await;
        let driver = lck.as_mut().unwrap();

        cb(driver)
    }

    async fn set_config(&self) {
        Self::use_driver(|driver| driver.set_config(self.config))
            .await;
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
        self.config.rx_when_idle
    }

    fn get_pan_id(&self) -> Option<PanId> {
        self.config.pan_id.map(PanId)
    }

    async fn set_pan_id(&mut self, pan_id: Option<PanId>) -> () {
        self.config.pan_id = pan_id.map(|pan_id| pan_id.0);
        self.set_config().await
    }

    fn get_short_address(&self) -> Option<NwkAddress> {
        self.config.short_addr.map(NwkAddress)
    }

    async fn set_short_address(&mut self, short_addr: Option<NwkAddress>) -> () {
        self.config.short_addr = short_addr.map(|short_addr| short_addr.0);
        self.set_config().await;
    }

    async fn set_channel(&mut self, channel: Channel) -> () {
        self.config.channel = channel as u8;
        self.set_config().await;
    }

    async fn transmit(&mut self, frame: &[u8]) -> Result<(), byte::Error> {
        TX_SIGNAL.reset();
        let result = Self::use_driver(|driver| {
            driver.transmit_raw(frame, true).map_err(|err| match err {
                Error::Incomplete => byte::Error::Incomplete,
                Error::BadInput => byte::Error::BadInput {
                    err: "error transmitting frame in ESP32 driver",
                },
            })
        }).await;

        match result {
            Err(err) => {
                log::warn!("[ESP32-DRIVER] error transmitting frame: {:?}", err);
                Self::use_driver(|driver| driver.start_receive()).await;
                Err(err)
            }
            Ok(()) => {
                TX_SIGNAL.wait().await;
                Ok(())
            }
        }
    }

    async fn flush(&mut self) -> () {
        while self.poll().await.is_some() {}
    }

    async fn poll(&mut self) -> Option<MacFrame> {
        Self::use_driver(|driver| {
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
        }).await
    }

    async fn wait_frame(&mut self) -> MacFrame {
        loop {
            if let Some(result) = self.poll().await {
                return result;
            }
            self.wait_rx_available().await;
        }
    }

    async fn reset(&mut self, set_default_pib: bool) {
        self.config.auto_ack_tx = true;
        self.config.auto_ack_rx = true;
        self.config.promiscuous = true;
        self.config.rx_when_idle = self.rx_when_idle;
        self.config.rx_queue_size = self.rx_queue_size;
        self.config.txpower = 10;
        self.config.cca_threshold = -60;
        self.config.cca_mode = CcaMode::Ed;
        self.config.enhance_ack_tx = false;

        if set_default_pib {
            self.config.pan_id = None;
            self.config.short_addr = None;
            self.config.channel = self.default_channel;
        }

        self.set_config().await
    }
}

impl NwkMac for Esp32Driver {}