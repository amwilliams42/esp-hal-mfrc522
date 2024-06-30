#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use core::mem::size_of;

use consts::{PCDCommand, PCDRegister, PICCCommand};
use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use embedded_hal::digital::OutputPin;
use esp_backtrace as _;
use esp_hal::{
    clock::ClockControl,
    dma::Dma,
    dma_descriptors,
    gpio::{Io, Level, Output},
    peripherals::{Peripherals, DMA, SPI3},
    prelude::*,
    spi::{
        master::{dma::SpiDma, prelude::*, Spi},
        FullDuplexMode, SpiMode,
    },
    system::SystemControl,
    timer::timg::TimerGroup,
    Async,
};
use heapless::String;
use log::{debug, info, trace};

mod consts;

#[main]
async fn main(_spawner: Spawner) {
    let peripherals = Peripherals::take();
    let system = SystemControl::new(peripherals.SYSTEM);
    let clocks = ClockControl::max(system.clock_control).freeze();
    esp_println::logger::init_logger_from_env();

    let timg0 = TimerGroup::new_async(peripherals.TIMG0, &clocks);
    esp_hal_embassy::init(&clocks, timg0);
    log::set_max_level(log::LevelFilter::Trace);

    let io = Io::new(peripherals.GPIO, peripherals.IO_MUX);
    let sck = io.pins.gpio4;
    let miso = io.pins.gpio2;
    let mosi = io.pins.gpio3;
    let cs = Output::new(io.pins.gpio5, Level::High);

    let dma = Dma::new(peripherals.DMA);
    let dma_chan = dma.channel0;
    let (mut descriptors, mut rx_descriptors) = dma_descriptors!(32000);
    let dma_chan = dma_chan.configure_for_async(
        false,
        &mut descriptors,
        &mut rx_descriptors,
        esp_hal::dma::DmaPriority::Priority0,
    );

    let spi = Spi::new(peripherals.SPI3, 4.MHz(), SpiMode::Mode0, &clocks);
    let spi: Spi<SPI3, FullDuplexMode> = spi.with_sck(sck).with_miso(miso).with_mosi(mosi);
    let spi: SpiDma<SPI3, _, FullDuplexMode, Async> = spi.with_dma(dma_chan);

    let mut mfrc522 = MFRC522::new(spi, cs);
    _ = mfrc522.pcd_init().await;
    _ = mfrc522.pcd_selftest().await;
    debug!("PCD ver: {:?}", mfrc522.pcd_get_version().await);

    loop {
        if mfrc522.picc_is_new_card_present().await.is_ok() {
            let mut dsa = 0;
            let res = mfrc522.picc_select(&mut dsa, 0).await;
            info!("CARD IS PRESENT: {res:?}");
        }

        Timer::after(Duration::from_millis(20)).await;
    }
}

pub struct MFRC522<S, C>
where
    S: embedded_hal_async::spi::SpiBus,
    C: OutputPin,
{
    spi: S,
    cs: C,
    read_buff: [u8; 1],
}

// TODO: implement own errors type (using for example thiserror-no-std or snafu)
impl<S, C> MFRC522<S, C>
where
    S: embedded_hal_async::spi::SpiBus,
    C: OutputPin,
{
    pub fn new(spi: S, cs: C) -> Self {
        Self {
            spi,
            cs,
            read_buff: [0],
        }
    }

    pub async fn pcd_init(&mut self) -> Result<(), ()> {
        self.pcd_reset().await?;

        self.write_reg(PCDRegister::TxModeReg, 0x00).await?;
        self.write_reg(PCDRegister::RxModeReg, 0x00).await?;

        self.write_reg(PCDRegister::ModWidthReg, 0x26).await?;

        self.write_reg(PCDRegister::TModeReg, 0x80).await?;
        self.write_reg(PCDRegister::TPrescalerReg, 0xA9).await?;
        self.write_reg(PCDRegister::TReloadRegH, 0x03).await?;
        self.write_reg(PCDRegister::TReloadRegL, 0xE8).await?;

        self.write_reg(PCDRegister::TxASKReg, 0x40).await?;
        self.write_reg(PCDRegister::ModeReg, 0x3D).await?;

        self.pcd_antenna_on().await?;
        Timer::after(Duration::from_millis(4)).await;

        Ok(())
    }

    pub async fn pcd_reset(&mut self) -> Result<(), ()> {
        self.write_reg(PCDRegister::CommandReg, PCDCommand::SoftReset)
            .await?;

        // max 3 tries
        for _ in 0..3 {
            let out = self.read_reg(PCDRegister::CommandReg).await;
            if let Ok(out) = out {
                let out = out & (1 << 4);
                if out == 0 {
                    break;
                }
            }

            Timer::after(Duration::from_millis(50)).await;
        }

        Ok(())
    }

    pub async fn pcd_antenna_on(&mut self) -> Result<(), ()> {
        let val = self.read_reg(PCDRegister::TxControlReg).await?;
        if (val & 0x03) != 0x03 {
            self.write_reg(PCDRegister::TxControlReg, val | 0x03)
                .await?;
        }

        Ok(())
    }

    pub async fn pcd_get_version(&mut self) -> Result<u8, ()> {
        self.read_reg(PCDRegister::VersionReg).await
    }

    /*
    pub async fn pcd_mifare_transceive(
        &mut self,
        send_data: &[u8],
        mut send_len: u8,
        _accept_timeout: bool,
    ) -> Result<(), ()> {
        let mut cmd_buff = [0; 18];
        if send_len > 16 {
            return Err(());
        }

        cmd_buff.copy_from_slice(&send_data[..send_len as usize]);
        self.pcd_calc_crc(
            &cmd_buff.clone(), // i cant make it like in C :(
            send_len,
            &mut cmd_buff[send_len as usize..],
        )
        .await?;

        send_len += 2;

        let wait_irq = 0x30;
        let mut cmd_buff_size = 18; //???? (sizeof(cmdBuffer) - isnt it always 18???)
        let mut valid_bits = 0;

        self.pcd_communicate_with_picc(
            PCDCommand::Transceive,
            wait_irq,
            &cmd_buff.clone(),
            send_len,
            &mut cmd_buff,
            &mut cmd_buff_size,
            &mut valid_bits,
            0,
            false,
        )
        .await?;

        if cmd_buff_size != 1 || valid_bits != 4 {
            return Err(());
        }

        if cmd_buff[0] != 0xA {
            // MIFARE_Misc::MF_ACK type
            return Err(());
        }

        Ok(())
    }
    */

    pub async fn picc_is_new_card_present(&mut self) -> Result<bool, ()> {
        let mut buffer_atqa = [0; 2];
        let mut buffer_size = 2;

        self.write_reg(PCDRegister::TxModeReg, 0x00).await?;
        self.write_reg(PCDRegister::RxModeReg, 0x00).await?;
        self.write_reg(PCDRegister::ModWidthReg, 0x26).await?;

        self.picc_request_a(&mut buffer_atqa, &mut buffer_size)
            .await?;
        Ok(true)
    }

    pub async fn picc_select(&mut self, uid: &mut u128, valid_bits: u8) -> Result<(), u8> {
        let mut uid_complete = false;
        let mut select_done = false;
        let mut use_casdcade_tag = false;
        let mut cascade_level = 1u8;
        let mut count = 0u8;
        let mut check_bit = 0u8;
        let mut index = 0u8;
        let mut uid_index = 0u8;
        let mut current_level_known_bits = 0i8;
        let mut buff = [0u8; 9];
        let mut buffer_used = 0u8;
        let mut rx_align = 0u8;
        let mut tx_last_bits = 0u8;
        let mut response_buffer = [0u8; 9]; // max 9 length
        let mut response_length = 0u8;

        if valid_bits > 80 {
            return Err(0);
        }

        self.pcd_clear_register_bit_mask(PCDRegister::CollReg, 0x80)
            .await
            .map_err(|_| 1)?;

        while !uid_complete {
            match cascade_level {
                1 => {
                    buff[0] = PICCCommand::PICC_CMD_SEL_CL1;
                    uid_index = 0;

                    // this first 4 is uid_size, for now its constant 4
                    use_casdcade_tag = valid_bits != 0 && (4 > 4);
                }
                2 => {
                    buff[0] = PICCCommand::PICC_CMD_SEL_CL2;
                    uid_index = 3;

                    // this first 4 is uid_size, for now its constant 4
                    use_casdcade_tag = valid_bits != 0 && (4 > 7);
                }
                3 => {
                    buff[0] = PICCCommand::PICC_CMD_SEL_CL3;
                    uid_index = 6;
                    use_casdcade_tag = false;
                }
                _ => {
                    return Err(2);
                }
            }

            current_level_known_bits = valid_bits as i8 - (8i8 * uid_index as i8);
            if current_level_known_bits < 0 {
                current_level_known_bits = 0;
            }

            index = 2;
            if use_casdcade_tag {
                buff[index as usize] = PICCCommand::PICC_CMD_CT;
                index += 1;
            }

            // TODO: copy uid bytes
            /*
            let bytes_to_copy = current_level_known_bits / 8
                + (if current_level_known_bits % 8 != 0 {
                    1
                } else {
                    0
                });

            if bytes_to_copy != 0 {
                let mut max_bytes = if use_casdcade_tag { 3 } else { 4 };
                if bytes_to_copy > max_bytes {
                    bytes_to_copy = max_bytes;
                }

                for count in 0..bytes_to_copy {
                    //buf[index] = //copy uid bytes
                    index += 1;
                }
            }
            */

            if use_casdcade_tag {
                current_level_known_bits += 8;
            }

            while !select_done {
                if current_level_known_bits >= 32 {
                    buff[1] = 0x70;
                    buff[6] = buff[2] ^ buff[3] ^ buff[4] ^ buff[5];

                    self.pcd_calc_crc(&buff.clone(), 7, &mut buff[7..])
                        .await
                        .map_err(|_| 4)?;

                    tx_last_bits = 0;
                    buffer_used = 9;
                    response_length = 3;
                    response_buffer[..3].copy_from_slice(&buff[6..]);
                } else {
                    tx_last_bits = (current_level_known_bits % 8) as u8;
                    count = (current_level_known_bits / 8) as u8;
                    index = 2 + count;
                    buff[1] = (index << 4) + tx_last_bits;
                    buffer_used = index + (if tx_last_bits != 0 { 1 } else { 0 });

                    response_length = 9 - index;
                    response_buffer[0..response_length as usize]
                        .copy_from_slice(&buff[index as usize..]);
                }

                rx_align = tx_last_bits;
                self.write_reg(PCDRegister::BitFramingReg, (rx_align << 4) + tx_last_bits)
                    .await
                    .map_err(|_| 5)?;

                let res = self
                    .pcd_transceive_data(
                        &buff,
                        buffer_used,
                        &mut response_buffer,
                        &mut response_length,
                        &mut tx_last_bits,
                        rx_align,
                        false,
                    )
                    .await
                    .map_err(|_| 6)?;

                if res {
                    // collision
                    let value_of_coll_reg =
                        self.read_reg(PCDRegister::CollReg).await.map_err(|_| 7)?;
                    if value_of_coll_reg & 0x20 != 0 {
                        return Err(8);
                    }

                    let mut collision_pos = value_of_coll_reg & 0x1F;
                    if collision_pos == 0 {
                        collision_pos = 32;
                    }

                    if collision_pos as i8 <= current_level_known_bits {
                        return Err(9);
                    }

                    current_level_known_bits = collision_pos as i8;
                    count = (current_level_known_bits % 8) as u8;
                    check_bit = ((current_level_known_bits - 1) % 8) as u8;
                    index =
                        1 + (current_level_known_bits / 8) as u8 + (if count != 0 { 1 } else { 0 });

                    buff[index as usize] |= 1 << check_bit;
                } else {
                    if current_level_known_bits >= 32 {
                        select_done = true;
                    } else {
                        current_level_known_bits = 32;
                    }
                }
            }

            index = if buff[2] == PICCCommand::PICC_CMD_CT {
                3
            } else {
                2
            };

            let bytes_to_copy = if buff[2] == PICCCommand::PICC_CMD_CT {
                3
            } else {
                4
            };

            // TODO: construct u128 from this or own UID struct
            for i in 0..bytes_to_copy {
                debug!("{i}: {}", buff[index as usize]);
                index += 1;
            }

            trace!("response_length: {response_length}, tx_last_bits: {tx_last_bits}");
            if response_length != 3 || tx_last_bits != 0 {
                return Err(10);
            }

            self.pcd_calc_crc(&response_buffer, 1, &mut buff[2..])
                .await
                .map_err(|_| 11)?;

            if (buff[2] != response_buffer[1]) || (buff[3] != response_buffer[3]) {
                return Err(12);
            }

            if response_buffer[0] & 0x04 != 0 {
                cascade_level += 1;
            } else {
                uid_complete = true;
                debug!("SAK: {}", response_buffer[0]);
            }
        }

        debug!("UID_SIZE: {}", 3 * cascade_level + 1);
        Ok(())
    }

    pub async fn picc_request_a(
        &mut self,
        buffer_atqa: &mut [u8],
        buffer_size: &mut u8,
    ) -> Result<(), ()> {
        self.picc_reqa_or_wupa(PICCCommand::PICC_CMD_REQA, buffer_atqa, buffer_size)
            .await
    }

    pub async fn picc_reqa_or_wupa(
        &mut self,
        cmd: u8,
        buffer_atqa: &mut [u8],
        buffer_size: &mut u8,
    ) -> Result<(), ()> {
        if *buffer_size < 2 {
            return Err(());
        }

        self.pcd_clear_register_bit_mask(PCDRegister::CollReg, 0x80)
            .await?;
        let mut valid_bits = 7;
        self.pcd_transceive_data(
            &[cmd],
            1,
            buffer_atqa,
            buffer_size,
            &mut valid_bits,
            0,
            false,
        )
        .await?;

        if *buffer_size != 2 || valid_bits != 0 {
            return Err(());
        }

        Ok(())
    }

    pub async fn pcd_transceive_data(
        &mut self,
        send_data: &[u8],
        send_len: u8,
        back_data: &mut [u8],
        back_len: &mut u8,
        valid_bits: &mut u8,
        rx_align: u8,
        check_crc: bool,
    ) -> Result<bool, ()> {
        let wait_irq = 0x30;
        self.pcd_communicate_with_picc(
            PCDCommand::Transceive,
            wait_irq,
            send_data,
            send_len,
            back_data,
            back_len,
            valid_bits,
            rx_align,
            check_crc,
        )
        .await
    }

    pub async fn pcd_communicate_with_picc(
        &mut self,
        cmd: u8,
        wait_irq: u8,
        send_data: &[u8],
        send_len: u8,
        back_data: &mut [u8],
        back_len: &mut u8,
        valid_bits: &mut u8,
        rx_align: u8,
        check_crc: bool,
    ) -> Result<bool, ()> {
        let tx_last_bits = *valid_bits;
        let bit_framing = (rx_align << 4) + tx_last_bits;

        self.write_reg(PCDRegister::CommandReg, PCDCommand::Idle)
            .await?;
        self.write_reg(PCDRegister::ComIrqReg, 0x7F).await?;
        self.write_reg(PCDRegister::FIFOLevelReg, 0x80).await?;
        self.write_reg_buff(PCDRegister::FIFODataReg, send_len as usize, send_data)
            .await?;
        self.write_reg(PCDRegister::BitFramingReg, bit_framing)
            .await?;
        self.write_reg(PCDRegister::CommandReg, cmd).await?;

        if cmd == PCDCommand::Transceive {
            self.pcd_set_register_bit_mask(PCDRegister::BitFramingReg, 0x80)
                .await?;
        }

        for i in 0..2000 {
            if i == 2000 {
                // timeout??
                return Err(());
            }

            let n = self.read_reg(PCDRegister::ComIrqReg).await?;
            if n & wait_irq != 0 {
                break;
            }

            if n & 0x01 != 0 {
                // timeout??
                return Err(());
            }
        }

        let error_reg_value = self.read_reg(PCDRegister::ErrorReg).await?;
        if error_reg_value & 0x13 != 0 {
            return Err(());
        }

        let mut _valid_bits = 0;
        if *back_len != 0 {
            let n = self.read_reg(PCDRegister::FIFOLevelReg).await?;
            if n > *back_len {
                return Err(());
            }

            *back_len = n;
            self.read_reg_buff(PCDRegister::FIFODataReg, n as usize, back_data, rx_align)
                .await?;

            _valid_bits = self.read_reg(PCDRegister::ControlReg).await? & 0x07;
            if *valid_bits != 0 {
                *valid_bits = _valid_bits;
            }
        }

        if error_reg_value & 0x08 != 0 {
            // collision - so true
            return Ok(true);
        }

        if *back_len != 0 && check_crc {
            if *back_len == 1 && _valid_bits == 4 {
                return Err(());
            }

            if *back_len < 2 || _valid_bits != 0 {
                return Err(());
            }

            let mut control_buff = [0; 2];
            self.pcd_calc_crc(&back_data, *back_len - 2, &mut control_buff)
                .await?;

            if (back_data[*back_len as usize - 2] != control_buff[0])
                || (back_data[*back_len as usize - 1] != control_buff[1])
            {
                return Err(()); // cnc wrong
            }
        }

        Ok(false)
    }

    /// Now it prints data to console, TODO: change this
    /// Always returns false (for now)
    pub async fn pcd_selftest(&mut self) -> Result<bool, ()> {
        debug!("Running PCD_Selftest!\n");

        self.write_reg(PCDRegister::FIFOLevelReg, 0x80).await?;
        self.write_reg_buff(PCDRegister::FIFODataReg, 25, &[0; 25])
            .await?;

        self.write_reg(PCDRegister::CommandReg, PCDCommand::Mem)
            .await?;
        self.write_reg(PCDRegister::AutoTestReg, 0x09).await?;
        self.write_reg(PCDRegister::FIFODataReg, 0x00).await?;
        self.write_reg(PCDRegister::CommandReg, PCDCommand::CalcCRC)
            .await?;

        for _ in 0..0xFF {
            let n = self.read_reg(PCDRegister::FIFOLevelReg).await?;
            if n >= 64 {
                break;
            }
        }

        self.write_reg(PCDRegister::CommandReg, PCDCommand::Idle)
            .await?;

        let mut res = [0; 64];
        self.read_reg_buff(PCDRegister::FIFODataReg, 64, &mut res, 0)
            .await?;
        self.write_reg(PCDRegister::AutoTestReg, 0x40 & 0x00)
            .await?;

        let mut str: String<128> = String::new();
        for i in 0..64 {
            if i % 8 == 0 && str.len() != 0 {
                debug!("{}", str);
                str.clear();
            }

            _ = core::fmt::write(&mut str, format_args!("{:#04x} ", res[i]));
        }
        debug!("{}", str);

        debug!("PCD_Selftest Done!\n");
        self.pcd_init().await?;
        Ok(false)
    }

    pub async fn write_reg(&mut self, reg: u8, val: u8) -> Result<(), ()> {
        _ = self.cs.set_low();
        _ = self.spi.transfer(&mut self.read_buff, &[reg << 1]).await;
        _ = self.spi.transfer(&mut self.read_buff, &[val]).await;
        _ = self.cs.set_high();

        Ok(())
    }

    pub async fn write_reg_buff(&mut self, reg: u8, count: usize, values: &[u8]) -> Result<(), ()> {
        _ = self.cs.set_low();
        _ = self.spi.transfer(&mut self.read_buff, &[reg << 1]).await;

        for i in 0..count {
            _ = self.spi.transfer(&mut self.read_buff, &[values[i]]).await;
        }

        _ = self.cs.set_high();
        Ok(())
    }

    pub async fn read_reg(&mut self, reg: u8) -> Result<u8, ()> {
        _ = self.cs.set_low();
        _ = self
            .spi
            .transfer(&mut self.read_buff, &[(reg << 1) | 0x80])
            .await;

        _ = self.spi.transfer(&mut self.read_buff, &[0]).await;
        _ = self.cs.set_high();

        Ok(self.read_buff[0])
    }

    pub async fn read_reg_buff(
        &mut self,
        reg: u8,
        count: usize,
        output_buff: &mut [u8],
        rx_align: u8,
    ) -> Result<(), ()> {
        if count == 0 {
            return Ok(());
        }

        let addr = 0x80 | (reg << 1);
        let mut index = 0;

        _ = self.cs.set_low();
        _ = self.spi.transfer(&mut self.read_buff, &[addr]).await;
        if rx_align > 0 {
            let mask = (0xFF << rx_align) & 0xFF;
            _ = self.spi.transfer(&mut self.read_buff, &[addr]).await;

            output_buff[0] = (output_buff[0] & !mask) | (self.read_buff[0] & mask);
            index += 1;
        }

        while index < count - 1 {
            _ = self.spi.transfer(&mut self.read_buff, &[addr]).await;
            output_buff[index] = self.read_buff[0];
            index += 1;
        }

        _ = self.spi.transfer(&mut self.read_buff, &[0]).await;
        output_buff[index] = self.read_buff[0];

        _ = self.cs.set_high();
        Ok(())
    }

    pub async fn pcd_clear_register_bit_mask(&mut self, reg: u8, mask: u8) -> Result<(), ()> {
        let tmp = self.read_reg(reg).await?;
        self.write_reg(reg, tmp & (!mask)).await?;

        Ok(())
    }

    pub async fn pcd_set_register_bit_mask(&mut self, reg: u8, mask: u8) -> Result<(), ()> {
        let tmp = self.read_reg(reg).await?;
        self.write_reg(reg, tmp | mask).await?;

        Ok(())
    }

    pub async fn pcd_calc_crc(
        &mut self,
        data: &[u8],
        length: u8,
        res: &mut [u8],
    ) -> Result<(), ()> {
        self.write_reg(PCDRegister::CommandReg, PCDCommand::Idle)
            .await?;
        self.write_reg(PCDRegister::DivIrqReg, 0x04).await?;
        self.write_reg(PCDRegister::FIFOLevelReg, 0x80).await?;
        self.write_reg_buff(PCDRegister::FIFODataReg, length as usize, data)
            .await?;
        self.write_reg(PCDRegister::CommandReg, PCDCommand::CalcCRC)
            .await?;

        // TODO: make sth like timeout (this 5000 is only for waiting)
        for _ in 0..5000 {
            let n = self.read_reg(PCDRegister::DivIrqReg).await?;
            if n & 0x04 != 0 {
                self.write_reg(PCDRegister::CommandReg, PCDCommand::Idle)
                    .await?;

                res[0] = self.read_reg(PCDRegister::CRCResultRegL).await?;
                res[1] = self.read_reg(PCDRegister::CRCResultRegH).await?;
                return Ok(());
            }
        }

        // timeout?
        Err(())
    }
}
