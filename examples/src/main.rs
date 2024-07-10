#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_hal::{
    clock::{ClockControl, Clocks},
    dma::Dma,
    dma_descriptors,
    gpio::{any_pin::AnyPin, Io, Level, Output},
    peripherals::{Peripherals, DMA, SPI3},
    prelude::*,
    spi::{
        master::{dma::SpiDma, prelude::*, Spi},
        FullDuplexMode, SpiMode,
    },
    system::SystemControl,
    timer::{timg::TimerGroup, OneShotTimer},
    Async,
};
use log::{debug, error, info};
use mfrc522_esp_hal::{consts::UidSize, debug::MFRC522Debug};
use static_cell::make_static;

#[main]
async fn main(_spawner: Spawner) {
    let peripherals = Peripherals::take();
    let system = SystemControl::new(peripherals.SYSTEM);
    let clocks = ClockControl::max(system.clock_control).freeze();
    let clocks = &*make_static!(clocks);

    esp_println::logger::init_logger_from_env();

    let timg0 = TimerGroup::new(peripherals.TIMG0, &clocks, None);
    let timers = make_static!([OneShotTimer::new(timg0.timer0.into())]);
    esp_hal_embassy::init(&clocks, timers);
    log::set_max_level(log::LevelFilter::Trace);

    let io = Io::new(peripherals.GPIO, peripherals.IO_MUX);
    let sck = AnyPin::new(io.pins.gpio4);
    let miso = AnyPin::new(io.pins.gpio2);
    let mosi = AnyPin::new(io.pins.gpio3);
    let cs = AnyPin::new(io.pins.gpio5);

    _ = _spawner.spawn(rfid_task(
        miso,
        mosi,
        sck,
        cs,
        &clocks,
        peripherals.SPI3,
        peripherals.DMA,
    ));

    loop {
        info!("main loop");
        Timer::after(Duration::from_millis(15000)).await;
    }
}

#[embassy_executor::task]
async fn rfid_task(
    miso: AnyPin<'static>,
    mosi: AnyPin<'static>,
    sck: AnyPin<'static>,
    cs: AnyPin<'static>,
    clocks: &'static Clocks<'static>,
    spi: SPI3,
    dma: DMA,
) {
    let dma = Dma::new(dma);
    let dma_chan = dma.channel0;
    let (descriptors, rx_descriptors) = dma_descriptors!(32000);
    let dma_chan = dma_chan.configure_for_async(false, esp_hal::dma::DmaPriority::Priority0);

    let cs = Output::new(cs, Level::High);
    let spi = Spi::new(spi, 5.MHz(), SpiMode::Mode0, &clocks);
    let spi: Spi<SPI3, FullDuplexMode> = spi.with_sck(sck).with_miso(miso).with_mosi(mosi);
    let spi: SpiDma<SPI3, _, FullDuplexMode, Async> =
        spi.with_dma(dma_chan, descriptors, rx_descriptors);

    //mfrc522_esp_hal::MFRC522::new(spi, cs, || esp_hal::time::current_time().ticks());
    let mut mfrc522 = mfrc522_esp_hal::MFRC522::new(spi, cs); // embassy-time feature is enabled,
                                                              // so no need to pass current_time
                                                              // function

    _ = mfrc522.pcd_init().await;
    _ = mfrc522.pcd_selftest().await;
    debug!("PCD ver: {:?}", mfrc522.pcd_get_version().await);

    if !mfrc522.pcd_is_init().await {
        error!("MFRC522 init failed! Try to power cycle to module!");
    }

    loop {
        if mfrc522.picc_is_new_card_present().await.is_ok() {
            let card = mfrc522.get_card(UidSize::Four).await;
            if let Ok(card) = card {
                info!("Card UID: {}", card.get_number());
                _ = mfrc522.debug_dump_card(&card).await;
            }

            _ = mfrc522.picc_halta().await;
        }

        Timer::after(Duration::from_millis(1)).await;
    }
}
