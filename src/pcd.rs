use crate::{
    consts::{PCDCommand, PCDErrorCode, PCDRegister, PCDVersion, Uid},
    MFRC522,
};
use embedded_hal::digital::OutputPin;
use heapless::String;

/// assert return boolean (false)
macro_rules! assert_rb {
    ($expr:expr, $expected:expr) => {
        if $expr != $expected {
            return false;
        }
    };
}

impl<S> MFRC522<S>
where
    S: embedded_hal::spi::SpiDevice,
{
    pub async fn pcd_init(&mut self) -> Result<(), PCDErrorCode> {
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

        self.sleep(4).await;
        Ok(())
    }

    pub async fn pcd_is_init(&mut self) -> bool {
        assert_rb!(self.read_reg(PCDRegister::TxModeReg).await, Ok(0x00));
        assert_rb!(self.read_reg(PCDRegister::RxModeReg).await, Ok(0x00));
        assert_rb!(self.read_reg(PCDRegister::ModWidthReg).await, Ok(0x26));

        assert_rb!(self.read_reg(PCDRegister::TModeReg).await, Ok(0x80));
        assert_rb!(self.read_reg(PCDRegister::TPrescalerReg).await, Ok(0xA9));
        assert_rb!(self.read_reg(PCDRegister::TReloadRegH).await, Ok(0x03));
        assert_rb!(self.read_reg(PCDRegister::TReloadRegL).await, Ok(0xE8));

        assert_rb!(self.read_reg(PCDRegister::TxASKReg).await, Ok(0x40));
        assert_rb!(self.read_reg(PCDRegister::ModeReg).await, Ok(0x3D));
        true
    }

    pub async fn pcd_reset(&mut self) -> Result<(), PCDErrorCode> {
        // self.spi.flush().await.map_err(|_| PCDErrorCode::Unknown)?;
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

            self.sleep(50).await;
        }

        Ok(())
    }

    pub async fn pcd_antenna_on(&mut self) -> Result<(), PCDErrorCode> {
        let val = self.read_reg(PCDRegister::TxControlReg).await?;
        if (val & 0x03) != 0x03 {
            self.write_reg(PCDRegister::TxControlReg, val | 0x03)
                .await?;
        }

        Ok(())
    }

    pub async fn pcd_antenna_off(&mut self) -> Result<(), PCDErrorCode> {
        self.pcd_clear_register_bit_mask(PCDRegister::TxControlReg, 0x03)
            .await
    }

    pub async fn pcd_get_antenna_gain(&mut self) -> Result<u8, PCDErrorCode> {
        let res = self.read_reg(PCDRegister::RFCfgReg).await?;
        Ok(res & (0x07 << 4))
    }

    pub async fn pcd_set_antenna_gain(&mut self, mask: u8) -> Result<(), PCDErrorCode> {
        if self.pcd_get_antenna_gain().await? != mask {
            self.pcd_clear_register_bit_mask(PCDRegister::RFCfgReg, 0x07 << 4)
                .await?;

            self.pcd_set_register_bit_mask(PCDRegister::RFCfgReg, mask & (0x07 << 4))
                .await?;
        }

        Ok(())
    }

    pub async fn pcd_get_version(&mut self) -> Result<PCDVersion, PCDErrorCode> {
        Ok(PCDVersion::from_byte(
            self.read_reg(PCDRegister::VersionReg).await?,
        ))
    }

    pub async fn pcd_soft_power_down(&mut self) -> Result<(), PCDErrorCode> {
        let mut val = self.read_reg(PCDRegister::CommandReg).await?;
        val |= 1 << 4;
        self.write_reg(PCDRegister::CommandReg, val).await?;

        Ok(())
    }

    pub async fn pcd_soft_power_up(&mut self) -> Result<(), PCDErrorCode> {
        let mut val = self.read_reg(PCDRegister::CommandReg).await?;
        val &= !(1 << 4);
        self.write_reg(PCDRegister::CommandReg, val).await?;

        let start_time = (self.get_current_time)();
        while (self.get_current_time)() - start_time < 500_000 {
            let val = self.read_reg(PCDRegister::CommandReg).await?;
            if val & (1 << 4) == 0 {
                return Ok(());
            }
        }

        Err(PCDErrorCode::Timeout)
    }

    pub async fn pcd_stop_crypto1(&mut self) -> Result<(), PCDErrorCode> {
        self.pcd_clear_register_bit_mask(PCDRegister::Status2Reg, 0x08)
            .await
    }

    /// Key - 6 bytes
    pub async fn pcd_authenticate(
        &mut self,
        cmd: u8,
        block_addr: u8,
        key: &[u8],
        uid: &Uid,
    ) -> Result<(), PCDErrorCode> {
        if key.len() != 6 && key.len() != 0xA {
            return Err(PCDErrorCode::Invalid);
        }

        let wait_irq = 0x10;
        let mut send_data = [0; 12];
        send_data[0] = cmd;
        send_data[1] = block_addr;
        send_data[2..8].copy_from_slice(&key);
        send_data[8..12]
            .copy_from_slice(&uid.uid_bytes[(uid.size as usize - 4)..(uid.size as usize)]);

        self.pcd_communicate_with_picc(
            PCDCommand::MFAuthent,
            wait_irq,
            &send_data,
            12,
            &mut [],
            &mut 0,
            &mut 0,
            0,
            false,
        )
        .await
    }

    pub async fn pcd_mifare_transceive(
        &mut self,
        send_data: &[u8],
        mut send_len: u8,
        accept_timeout: bool,
    ) -> Result<(), PCDErrorCode> {
        let mut cmd_buff = [0; 18];
        if send_len > 16 {
            return Err(PCDErrorCode::Invalid);
        }

        cmd_buff[..send_len as usize].copy_from_slice(&send_data[..send_len as usize]);
        self.pcd_calc_crc(
            &send_data[..send_len as usize],
            send_len,
            &mut cmd_buff[send_len as usize..],
        )
        .await?;

        send_len += 2;

        let wait_irq = 0x30;
        let mut cmd_buff_size = 18;
        let mut valid_bits = 0;

        let res = self
            .pcd_communicate_with_picc(
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
            .await;

        match res {
            Err(PCDErrorCode::Timeout) => {
                if accept_timeout {
                    return Ok(());
                }
            }
            Err(e) => return Err(e),
            Ok(_) => {}
        }

        if cmd_buff_size != 1 || valid_bits != 4 {
            return Err(PCDErrorCode::Error);
        }

        if cmd_buff[0] != 0xA {
            // MIFARE_Misc::MF_ACK type
            return Err(PCDErrorCode::MifareNack);
        }

        Ok(())
    }

    pub async fn pcd_ntag216_auth(&mut self, password: [u8; 4]) -> Result<[u8; 2], PCDErrorCode> {
        let mut cmd_buff = [0; 18];
        cmd_buff[0] = 0x1B;
        cmd_buff[1..5].copy_from_slice(&password);

        self.pcd_calc_crc_single_buf(&mut cmd_buff, 5, 5).await?;

        let wait_irq = 0x30;
        let mut valid_bits = 0;
        let mut rx_length = 5;

        self.pcd_communicate_with_picc(
            PCDCommand::Transceive,
            wait_irq,
            &cmd_buff.clone(),
            7,
            &mut cmd_buff,
            &mut rx_length,
            &mut valid_bits,
            0,
            false,
        )
        .await?;

        Ok([cmd_buff[0], cmd_buff[1]])
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
    ) -> Result<(), PCDErrorCode> {
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
    ) -> Result<(), PCDErrorCode> {
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

        let start_time = (self.get_current_time)();
        loop {
            let n = self.read_reg(PCDRegister::ComIrqReg).await?;
            if n & wait_irq != 0 {
                break;
            }

            if n & 0x01 != 0 || (self.get_current_time)() - start_time >= 36_000 {
                return Err(PCDErrorCode::Timeout);
            }
        }

        let error_reg_value = self.read_reg(PCDRegister::ErrorReg).await?;
        if error_reg_value & 0x13 != 0 {
            return Err(PCDErrorCode::Error);
        }

        let mut _valid_bits = 0;
        if *back_len != 0 {
            let n = self.read_reg(PCDRegister::FIFOLevelReg).await?;
            if n > *back_len {
                return Err(PCDErrorCode::NoRoom);
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
            return Err(PCDErrorCode::Collision);
        }

        if *back_len != 0 && check_crc {
            if *back_len == 1 && _valid_bits == 4 {
                return Err(PCDErrorCode::MifareNack);
            }

            if *back_len < 2 || _valid_bits != 0 {
                return Err(PCDErrorCode::CrcWrong);
            }

            let mut control_buff = [0; 2];
            self.pcd_calc_crc(&back_data, *back_len - 2, &mut control_buff)
                .await?;

            if (back_data[*back_len as usize - 2] != control_buff[0])
                || (back_data[*back_len as usize - 1] != control_buff[1])
            {
                return Err(PCDErrorCode::CrcWrong);
            }
        }

        Ok(())
    }

    /// Now it prints data to console, TODO: change this
    /// Always returns false (for now)
    pub async fn pcd_selftest(&mut self) -> Result<bool, PCDErrorCode> {
        log::debug!("Running PCD_Selftest!\n");

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
                log::debug!("{}", str);
                str.clear();
            }

            _ = core::fmt::write(&mut str, format_args!("{:#04x} ", res[i]));
        }
        log::debug!("{}", str);

        log::debug!("PCD_Selftest Done!\n");
        self.pcd_init().await?;
        Ok(false)
    }

    pub async fn pcd_clear_register_bit_mask(
        &mut self,
        reg: u8,
        mask: u8,
    ) -> Result<(), PCDErrorCode> {
        let tmp = self.read_reg(reg).await?;
        self.write_reg(reg, tmp & (!mask)).await?;

        Ok(())
    }

    pub async fn pcd_set_register_bit_mask(
        &mut self,
        reg: u8,
        mask: u8,
    ) -> Result<(), PCDErrorCode> {
        let tmp = self.read_reg(reg).await?;
        self.write_reg(reg, tmp | mask).await?;

        Ok(())
    }

    pub async fn pcd_calc_crc(
        &mut self,
        data: &[u8],
        length: u8,
        res: &mut [u8],
    ) -> Result<(), PCDErrorCode> {
        self.write_reg(PCDRegister::CommandReg, PCDCommand::Idle)
            .await?;

        self.write_reg(PCDRegister::DivIrqReg, 0x04).await?;
        self.write_reg(PCDRegister::FIFOLevelReg, 0x80).await?;
        self.write_reg_buff(PCDRegister::FIFODataReg, length as usize, data)
            .await?;

        self.write_reg(PCDRegister::CommandReg, PCDCommand::CalcCRC)
            .await?;

        let start_time = (self.get_current_time)();
        while (self.get_current_time)() - start_time < 89_000 {
            let n = self.read_reg(PCDRegister::DivIrqReg).await?;
            if n & 0x04 != 0 {
                self.write_reg(PCDRegister::CommandReg, PCDCommand::Idle)
                    .await?;

                res[0] = self.read_reg(PCDRegister::CRCResultRegL).await?;
                res[1] = self.read_reg(PCDRegister::CRCResultRegH).await?;
                return Ok(());
            }
        }

        Err(PCDErrorCode::Timeout)
    }

    /// This function is to prevent unnesecary clones
    pub async fn pcd_calc_crc_single_buf(
        &mut self,
        data: &mut [u8],
        length: u8,
        out_offset: usize,
    ) -> Result<(), PCDErrorCode> {
        self.write_reg(PCDRegister::CommandReg, PCDCommand::Idle)
            .await?;

        self.write_reg(PCDRegister::DivIrqReg, 0x04).await?;
        self.write_reg(PCDRegister::FIFOLevelReg, 0x80).await?;
        self.write_reg_buff(PCDRegister::FIFODataReg, length as usize, data)
            .await?;

        self.write_reg(PCDRegister::CommandReg, PCDCommand::CalcCRC)
            .await?;

        let start_time = (self.get_current_time)();
        while (self.get_current_time)() - start_time < 89_000 {
            let n = self.read_reg(PCDRegister::DivIrqReg).await?;
            if n & 0x04 != 0 {
                self.write_reg(PCDRegister::CommandReg, PCDCommand::Idle)
                    .await?;

                data[out_offset + 0] = self.read_reg(PCDRegister::CRCResultRegL).await?;
                data[out_offset + 1] = self.read_reg(PCDRegister::CRCResultRegH).await?;
                return Ok(());
            }
        }

        Err(PCDErrorCode::Timeout)
    }
}
