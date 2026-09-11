#![no_std]
#![no_main]
extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;
use core::fmt::Debug;
use core::fmt::Formatter;

use embassy_futures::select::select3;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
use embassy_time::Duration;
use embassy_time::Timer;
use esp_hal::gpio::Input;
use esp_hal::gpio::InputConfig;
use esp_hal::gpio::Level;
use esp_hal::gpio::Output;
use esp_hal::gpio::OutputConfig;
use esp_hal::gpio::Pull;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::timer::timg::TimerGroup;
use esp_radio::ieee802154::Ieee802154;
use esp_storage::FlashStorage;
use zb_hal_esp32::driver::Esp32Driver;
use zb_hal_esp32::storage::EspStoragePool;
use zb_types::common::{DeviceType, ExtendedAddress};
use zigbee::apl::application::types::BaseApplication;
use zigbee::apl::application::types::HomeAutomationDeviceIds;
use zigbee::apl::application::types::ZbDevice;
use zigbee::apl::aps::types::ApsEndpoint;
use zigbee::apl::zb_application::{ZbApplication, ZbApplicationsDef, ZigbeeApplication};
use zigbee::apl::zdo;
use zigbee::apl::zdo::config::ZbConfig;
use zigbee::apl::zdo::InitializedNode;
use zigbee::apl::zdp::types::descriptors::AvailablePowerSources;
use zigbee::define_application;
use zigbee::mac::mlme::Mlme;
use zigbee::zcl::cluster::types::Attribute;
use zigbee::zcl::cluster::types::ZclCluster;
use zb_zcl_clusters::general::onoff::{OnOffCluster, OnOffClusterHandler};
use zb_zcl_clusters::general::identify::{IdentifyCluster, IdentifyClusterHandler, EffectIdentifier, EffectVariant};
use zb_zcl_clusters::general::basic::{BasicCluster, BasicClusterConfig};

#[allow(unused_imports)]
use esp_backtrace as _;

esp_bootloader_esp_idf::esp_app_desc!();

static IDENTIFY_CANCELLATION_SIGNAL: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static GPIO10: Mutex<CriticalSectionRawMutex, Option<Output<'static>>> = Mutex::new(None);

struct IdentifyHandler {
    spawner: embassy_executor::SendSpawner,
}

impl IdentifyClusterHandler for IdentifyHandler {
    fn identify_start(&mut self, seconds: u16) {
        self.identify_stop();

        if seconds > 0 {
            self.spawner
                .spawn(identify_blink(Duration::from_secs(seconds as u64)).unwrap());
        }
    }

    fn identify_stop(&mut self) { IDENTIFY_CANCELLATION_SIGNAL.signal(()); }

    fn identify_effect(&mut self, identifier: EffectIdentifier, _variant: EffectVariant) {
        // TODO
    }
}

#[embassy_executor::task]
async fn identify_blink(duration: Duration) {
    let blink = async {
        let mut ticker = embassy_time::Ticker::every(Duration::from_millis(500));

        loop {
            {
                let mut pin = GPIO10.lock().await;
                if let Some(pin) = pin.as_mut() {
                    pin.toggle();
                }
            }

            ticker.next().await
        }
    };

    select3(
        blink,
        Timer::after(duration),
        IDENTIFY_CANCELLATION_SIGNAL.wait(),
    )
    .await;

    let mut pin = GPIO10.lock().await;
    if let Some(pin) = pin.as_mut() {
        pin.set_low();
    }
}

static BUTTON: Mutex<CriticalSectionRawMutex, Option<Input>> = Mutex::new(None);

#[embassy_executor::task]
async fn button_push(app: Arc<Mutex<CriticalSectionRawMutex, Box<dyn ZigbeeApplication>>>) {
    let mut button = BUTTON.lock().await;
    let button = button.as_mut().unwrap();

    button.wait_for_high().await;

    let mut app = app.lock().await;
    let output = app.as_any_mut().downcast_mut::<OnOffOutput>().unwrap();

    output.onoff.toggle();
}

#[derive(Debug)]
struct OnOffHandler {
    pin: Output<'static>,
}

impl OnOffClusterHandler for OnOffHandler {
    fn turn_on(&mut self) { self.pin.set_high(); }
    fn turn_off(&mut self) { self.pin.set_low(); }
}

define_application! {
    #[device(ZbDevice::HomeAutomation(HomeAutomationDeviceIds::OnOffOutput))]
    pub struct OnOffOutput {
        pub onoff: OnOffCluster<OnOffHandler>,
        pub identify: IdentifyCluster<IdentifyHandler>,
        pub basic: BasicCluster,
    }
}

impl ZigbeeApplication for OnOffOutput {}

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) -> ! {
    esp_println::logger::init_logger_from_env();

    let config = esp_hal::Config::default();
    let peripherals = esp_hal::init(config);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = TimerGroup::new(peripherals.TIMG0);

    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);
    esp_alloc::heap_allocator!(size: 64000);

    let ieee802154 = Ieee802154::new(peripherals.IEEE802154);
    let driver = Esp32Driver::builder(ieee802154)
        .ext_addr(ExtendedAddress(0x1cc089fffe70d46a))
        .build()
        .await
        .unwrap();
    let mac = Mlme::new(driver);

    let flash = FlashStorage::new(peripherals.FLASH);
    let storage = EspStoragePool::new(flash).await;

    let config = ZbConfig::builder()
        .device_type(DeviceType::EndDevice)
        .manufacturer_code(0x1234)
        .rx_on_when_idle(true)
        .available_power_sources(AvailablePowerSources {
            mains_power: true,
            rechargeable_battery: false,
            disposable_battery: false,
        })
        .build();

    // LED (for identify cluster)
    let pin10 = Output::new(peripherals.GPIO10, Level::Low, OutputConfig::default());
    {
        *(GPIO10.lock().await) = Some(pin10);
    }

    // BUTTON (manually toggle on/off)
    let pin11 = Input::new(
        peripherals.GPIO11,
        InputConfig::default().with_pull(Pull::Down),
    );
    {
        *(BUTTON.lock().await) = Some(pin11);
    }

    // Switch output (PIN 16)
    let pin = Output::new(peripherals.GPIO16, Level::Low, OutputConfig::default());
    let handler = OnOffHandler { pin };
    let on_off_output = OnOffOutput {
        onoff: OnOffCluster::new(handler),
        identify: IdentifyCluster::new(IdentifyHandler {
            spawner: spawner.make_send(),
        }),
        basic: BasicCluster::with_config(BasicClusterConfig::default()),
    };

    let switch: Arc<Mutex<CriticalSectionRawMutex, Box<dyn ZigbeeApplication>>> =
        Arc::new(Mutex::new(Box::new(on_off_output)));

    let mut map = ZbApplicationsDef::new();
    spawner.spawn(button_push(switch.clone()).unwrap());
    map.insert(ApsEndpoint::new(1).unwrap(), switch).ok();

    let mut node = match zdo::initialize(config, spawner, map, mac, storage).await {
        InitializedNode::Joined(joined) => joined,
        InitializedNode::Unjoined(mut unjoined) => {
            (async || {
                log::info!("node is not on a network, trying to connect...");

                loop {
                    match unjoined.network_steering().await {
                        Ok(joined) => return joined,
                        Err(err) => unjoined = err.state,
                    };

                    log::warn!("couldn't connect to a network, retrying in 10 seconds...");
                    Timer::after_secs(10).await;
                }
            })().await
        }
    };

    node.start().await
}
