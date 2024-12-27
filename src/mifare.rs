use embedded_hal::digital::OutputPin;

use crate::{
    consts::{PCDErrorCode, PICCCommand},
    MFRC522,
};

impl<S, C> MFRC522<S, C>
where
    S: embedded_hal_async::spi::SpiDevice,
    C: OutputPin,
{
    pub async fn mifare_read(
        &mut self,
        block_addr: u8,
        buff: &mut [u8],
        buff_size: &mut u8,
    ) -> Result<(), PCDErrorCode> {
        if *buff_size < 18 {
            return Err(PCDErrorCode::NoRoom);
        }

        buff[0] = PICCCommand::PICC_CMD_MF_READ;
        buff[1] = block_addr;

        let mut tmp_buff = [0; 2];
        tmp_buff.copy_from_slice(&buff[..2]);
        self.pcd_calc_crc(&tmp_buff, 2, &mut buff[2..]).await?;

        let mut tmp_buff = [0; 4];
        tmp_buff.copy_from_slice(&buff[..4]);

        self.pcd_transceive_data(&tmp_buff, 4, buff, buff_size, &mut 0, 0, true)
            .await
    }

    pub async fn mifare_write(
        &mut self,
        block_addr: u8,
        buff: &[u8],
        buff_size: u8,
    ) -> Result<(), PCDErrorCode> {
        if buff_size < 16 {
            return Err(PCDErrorCode::Invalid);
        }

        let cmd_buff = [PICCCommand::PICC_CMD_MF_WRITE, block_addr];
        self.pcd_mifare_transceive(&cmd_buff, 2, false).await?;
        self.pcd_mifare_transceive(buff, buff_size, false).await?;

        Ok(())
    }

    pub async fn mifare_ultralight_write(
        &mut self,
        page: u8,
        buff: &mut [u8],
        buff_size: u8,
    ) -> Result<(), PCDErrorCode> {
        if buff_size < 4 {
            return Err(PCDErrorCode::Invalid);
        }

        let mut cmd_buff = [0; 6];
        cmd_buff[0] = PICCCommand::PICC_CMD_UL_WRITE;
        cmd_buff[1] = page;
        cmd_buff[2..].copy_from_slice(&mut buff[..4]);

        self.pcd_mifare_transceive(&mut cmd_buff, 6, false).await?;
        Ok(())
    }

    pub async fn mifare_transfer(&mut self, block_addr: u8) -> Result<(), PCDErrorCode> {
        let cmd_buff = [PICCCommand::PICC_CMD_MF_TRANSFER, block_addr];
        self.pcd_mifare_transceive(&cmd_buff, 2, false).await?;

        Ok(())
    }

    pub async fn mifare_two_step_helper(
        &mut self,
        cmd: u8,
        block_addr: u8,
        data: u32,
    ) -> Result<(), PCDErrorCode> {
        let cmd_buff = [cmd, block_addr];
        self.pcd_mifare_transceive(&cmd_buff, 2, false).await?;
        self.pcd_mifare_transceive(&data.to_le_bytes(), 4, false)
            .await?;

        Ok(())
    }

    pub async fn mifare_decrement(
        &mut self,
        block_addr: u8,
        delta: u32,
    ) -> Result<(), PCDErrorCode> {
        self.mifare_two_step_helper(PICCCommand::PICC_CMD_MF_DECREMENT, block_addr, delta)
            .await
    }

    pub async fn mifare_increment(
        &mut self,
        block_addr: u8,
        delta: u32,
    ) -> Result<(), PCDErrorCode> {
        self.mifare_two_step_helper(PICCCommand::PICC_CMD_MF_INCREMENT, block_addr, delta)
            .await
    }

    pub async fn mifare_restore(&mut self, block_addr: u8) -> Result<(), PCDErrorCode> {
        self.mifare_two_step_helper(PICCCommand::PICC_CMD_MF_RESTORE, block_addr, 0)
            .await
    }

    pub async fn mifare_get_value(&mut self, block_addr: u8) -> Result<u32, PCDErrorCode> {
        let mut buff = [0; 18];
        let mut size = 18;

        self.mifare_read(block_addr, &mut buff, &mut size).await?;
        Ok(((buff[3] as u32) << 24)
            | ((buff[2] as u32) << 16)
            | ((buff[1] as u32) << 8)
            | (buff[0] as u32))
    }

    pub async fn mifare_set_value(
        &mut self,
        block_addr: u8,
        value: u32,
    ) -> Result<(), PCDErrorCode> {
        let mut buff = [0; 18];

        buff[0] = (value & 0xFF) as u8;
        buff[8] = (value & 0xFF) as u8;
        buff[1] = (value & 0xFF00) as u8 >> 8;
        buff[9] = (value & 0xFF00) as u8 >> 8;
        buff[2] = (value & 0xFF0000) as u8 >> 16;
        buff[10] = (value & 0xFF0000) as u8 >> 16;
        buff[3] = (value & 0xFF000000) as u8 >> 24;
        buff[11] = (value & 0xFF000000) as u8 >> 24;

        buff[4] = !buff[0];
        buff[5] = !buff[1];
        buff[6] = !buff[2];
        buff[7] = !buff[3];

        buff[12] = block_addr;
        buff[14] = block_addr;
        buff[13] = !block_addr;
        buff[15] = !block_addr;

        self.mifare_write(block_addr, &buff, 16).await
    }

    pub async fn mifare_calculate_access_bits(
        &mut self,
        buff: &mut [u8],
        g0: u8,
        g1: u8,
        g2: u8,
        g3: u8,
    ) -> Result<(), PCDErrorCode> {
        let c1 = ((g3 & 4) << 1) | ((g2 & 4) << 0) | ((g1 & 4) >> 1) | ((g0 & 4) >> 2);
        let c2 = ((g3 & 2) << 2) | ((g2 & 2) << 1) | ((g1 & 2) << 0) | ((g0 & 2) >> 1);
        let c3 = ((g3 & 1) << 3) | ((g2 & 1) << 2) | ((g1 & 1) << 1) | ((g0 & 1) << 0);

        buff[0] = (!c2 & 0xF) << 4 | (!c1 & 0xF);
        buff[1] = c1 << 4 | (!c3 & 0xF);
        buff[2] = c3 << 4 | c2;

        Ok(())
    }
}
