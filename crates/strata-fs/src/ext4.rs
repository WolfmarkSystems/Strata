use crate::errors::ForensicError;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const EXT4_MAGIC: u16 = 0x53EF;
pub const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
pub const EXT4_BLOCK_SIZE_MIN: u32 = 1024;

pub struct Ext4Reader {
    pub file: File,
    pub superblock: Ext4Superblock,
    pub block_size: u32,
    pub file_size: u64,
    pub block_groups: Vec<Ext4BlockGroup>,
    pub inode_size: u16,
}

#[derive(Debug, Clone)]
pub struct Ext4Superblock {
    pub s_inodes_count: u32,
    pub s_blocks_count_lo: u32,
    pub s_r_blocks_count_lo: u32,
    pub s_free_blocks_count_lo: u32,
    pub s_free_inodes_count: u32,
    pub s_first_data_block: u32,
    pub s_log_block_size: u32,
    pub s_blocks_per_group: u32,
    pub s_inodes_per_group: u32,
    pub s_mtime: u32,
    pub s_wtime: u32,
    pub s_mnt_count: u16,
    pub s_max_mnt_count: u16,
    pub s_magic: u16,
    pub s_state: u16,
    pub s_errors: u16,
    pub s_minor_rev_level: u16,
    pub s_lastcheck: u32,
    pub s_checkinterval: u32,
    pub s_creator_os: u32,
    pub s_rev_level: u32,
    pub s_def_resuid: u16,
    pub s_def_resgid: u16,
    pub s_first_ino: u32,
    pub s_inode_size: u16,
    pub s_block_group_nr: u16,
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_volume_name: [u8; 16],
    pub s_last_mounted: [u8; 64],
    pub s_algorithm_usage_bitmap: u32,
    pub s_prealloc_blocks: u8,
    pub s_prealloc_dir_blocks: u8,
    pub s_reserved_gdt_blocks: u16,
    pub s_journal_uuid: [u8; 16],
    pub s_journal_inum: u32,
    pub s_journal_dev: u32,
    pub s_last_orphan: u32,
    pub s_hash_seed: [u32; 4],
    pub s_def_hash_version: u8,
    pub s_jnl_backup_type: u8,
    pub s_desc_size: u16,
    pub s_default_mount_opts: u32,
    pub s_first_meta_bg: u32,
    pub s_mkfs_time: u32,
    pub s_jnl_blocks: [u32; 17],
    pub s_blocks_count_hi: u32,
    pub s_r_blocks_count_hi: u32,
    pub s_free_blocks_hi: u32,
    pub s_min_extra_isize: u16,
    pub s_want_extra_isize: u16,
    pub s_flags: u32,
    pub s_raid_stride: u16,
    pub s_mmp_update_interval: u16,
    pub s_mmp_block: u64,
    pub s_raid_stripe_width: u32,
    pub s_log_groups_per_flex: u8,
    pub s_char_editcount: u8,
    pub s_reserved: [u8; 96],
}

impl Default for Ext4Superblock {
    fn default() -> Self {
        Self {
            s_inodes_count: 0,
            s_blocks_count_lo: 0,
            s_r_blocks_count_lo: 0,
            s_free_blocks_count_lo: 0,
            s_free_inodes_count: 0,
            s_first_data_block: 0,
            s_log_block_size: 0,
            s_blocks_per_group: 0,
            s_inodes_per_group: 0,
            s_mtime: 0,
            s_wtime: 0,
            s_mnt_count: 0,
            s_max_mnt_count: 0,
            s_magic: 0,
            s_state: 0,
            s_errors: 0,
            s_minor_rev_level: 0,
            s_lastcheck: 0,
            s_checkinterval: 0,
            s_creator_os: 0,
            s_rev_level: 0,
            s_def_resuid: 0,
            s_def_resgid: 0,
            s_first_ino: 0,
            s_inode_size: 0,
            s_block_group_nr: 0,
            s_feature_compat: 0,
            s_feature_incompat: 0,
            s_feature_ro_compat: 0,
            s_uuid: [0; 16],
            s_volume_name: [0; 16],
            s_last_mounted: [0; 64],
            s_algorithm_usage_bitmap: 0,
            s_prealloc_blocks: 0,
            s_prealloc_dir_blocks: 0,
            s_reserved_gdt_blocks: 0,
            s_journal_uuid: [0; 16],
            s_journal_inum: 0,
            s_journal_dev: 0,
            s_last_orphan: 0,
            s_hash_seed: [0; 4],
            s_def_hash_version: 0,
            s_jnl_backup_type: 0,
            s_desc_size: 0,
            s_default_mount_opts: 0,
            s_first_meta_bg: 0,
            s_mkfs_time: 0,
            s_jnl_blocks: [0; 17],
            s_blocks_count_hi: 0,
            s_r_blocks_count_hi: 0,
            s_free_blocks_hi: 0,
            s_min_extra_isize: 0,
            s_want_extra_isize: 0,
            s_flags: 0,
            s_raid_stride: 0,
            s_mmp_update_interval: 0,
            s_mmp_block: 0,
            s_raid_stripe_width: 0,
            s_log_groups_per_flex: 0,
            s_char_editcount: 0,
            s_reserved: [0; 96],
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ext4BlockGroup {
    pub index: u32,
    pub block_bitmap_lo: u32,
    pub inode_bitmap_lo: u32,
    pub inode_table_lo: u32,
    pub free_blocks_count_lo: u16,
    pub free_inodes_count_lo: u16,
    pub used_dirs_count_lo: u16,
    pub flags: u16,
    pub exclude_bitmap: u32,
    pub block_bitmap_csum_lo: u16,
    pub inode_bitmap_csum_lo: u16,
    pub itable_unused_lo: u16,
    pub bg_flags: u32,
    pub bg_itable_unused_hi: u16,
    pub bg_checksum: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Ext4Inode {
    pub inode_num: u32,
    pub mode: u16,
    pub uid: u16,
    pub size_lo: u32,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub gid: u16,
    pub links_count: u16,
    pub blocks_lo: u32,
    pub flags: u32,
    pub osd1: u32,
    pub block: [u32; 15],
    pub generation: u32,
    pub file_acl_lo: u32,
    pub size_high: u32,
    pub frag_addr: u32,
    pub osd2: [u8; 12],
    pub extra_isize: u16,
    pub checksum_hi: u16,
    pub ctime_extra: u32,
    pub mtime_extra: u32,
    pub atime_extra: u32,
    pub created: u32,
    pub version_hi: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Ext4DirEntry {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u16,
    pub file_type: u8,
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum Ext4FileType {
    #[default]
    Unknown,
    Regular,
    Directory,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Symlink,
}

impl Ext4Reader {
    pub fn open(path: &Path) -> Result<Self, ForensicError> {
        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len();

        let superblock = Self::read_superblock(&mut file)?;
        let block_size = 1024u32 << superblock.s_log_block_size;
        let inode_size = superblock.s_inode_size;

        let mut reader = Self {
            file,
            superblock,
            block_size,
            file_size,
            block_groups: Vec::new(),
            inode_size,
        };

        reader.parse_block_groups()?;

        Ok(reader)
    }

    fn read_superblock(file: &mut File) -> Result<Ext4Superblock, ForensicError> {
        file.seek(SeekFrom::Start(EXT4_SUPERBLOCK_OFFSET))?;

        let mut sb = Ext4Superblock::default();
        let mut data = [0u8; 1024];
        file.read_exact(&mut data)?;

        sb.s_inodes_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        sb.s_blocks_count_lo = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        sb.s_free_blocks_count_lo = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        sb.s_free_inodes_count = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        sb.s_first_data_block = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        sb.s_log_block_size = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        sb.s_blocks_per_group = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        sb.s_inodes_per_group = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);
        sb.s_magic = u16::from_le_bytes([data[0x38], data[0x39]]);

        if sb.s_magic != EXT4_MAGIC {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        sb.s_inode_size = u16::from_le_bytes([data[0x58], data[0x59]]);
        if sb.s_inode_size == 0 {
            sb.s_inode_size = 128;
        }

        sb.s_uuid.copy_from_slice(&data[0x68..0x78]);
        sb.s_volume_name.copy_from_slice(&data[0x78..0x88]);

        Ok(sb)
    }

    fn parse_block_groups(&mut self) -> Result<(), ForensicError> {
        let bgdt_offset = (self.superblock.s_first_data_block as u64 + 1) * self.block_size as u64;

        if self.file.seek(SeekFrom::Start(bgdt_offset)).is_err() {
            return Ok(());
        }

        let num_groups = self
            .superblock
            .s_blocks_count_lo
            .div_ceil(self.superblock.s_blocks_per_group);

        let desc_size = if self.superblock.s_feature_incompat & 0x80 != 0 {
            64
        } else {
            32
        };

        for i in 0..num_groups.min(1000) {
            let offset = bgdt_offset + (i as u64 * desc_size as u64);
            if let Ok(bg) = self.read_block_group(offset, i) {
                self.block_groups.push(bg);
            }
        }

        Ok(())
    }

    fn read_block_group(
        &mut self,
        offset: u64,
        index: u32,
    ) -> Result<Ext4BlockGroup, ForensicError> {
        self.file.seek(SeekFrom::Start(offset))?;

        let mut data = vec![0u8; 32];
        self.file.read_exact(&mut data)?;

        Ok(Ext4BlockGroup {
            index,
            block_bitmap_lo: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            inode_bitmap_lo: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            inode_table_lo: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            free_blocks_count_lo: u16::from_le_bytes([data[12], data[13]]),
            free_inodes_count_lo: u16::from_le_bytes([data[14], data[15]]),
            used_dirs_count_lo: u16::from_le_bytes([data[16], data[17]]),
            flags: u16::from_le_bytes([data[18], data[19]]),
            ..Default::default()
        })
    }

    pub fn read_block(&mut self, block: u64) -> Result<Vec<u8>, ForensicError> {
        let offset = block * self.block_size as u64;
        let mut buffer = vec![0u8; self.block_size as usize];
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    pub fn read_inode(&mut self, inode_num: u32) -> Result<Ext4Inode, ForensicError> {
        let inode_index = inode_num - 1;
        let bg_index = inode_index / self.superblock.s_inodes_per_group;
        let index_in_bg = inode_index % self.superblock.s_inodes_per_group;

        if (bg_index as usize) >= self.block_groups.len() {
            return Err(ForensicError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Block group not found",
            )));
        }

        let bg = &self.block_groups[bg_index as usize];
        let inode_table_block = bg.inode_table_lo as u64;

        let inode_offset = inode_table_block * self.block_size as u64
            + (index_in_bg * self.inode_size as u32) as u64;

        self.file.seek(SeekFrom::Start(inode_offset))?;

        let mut data = vec![0u8; self.inode_size as usize];
        self.file.read_exact(&mut data)?;

        let inode = Ext4Inode {
            inode_num,
            mode: u16::from_le_bytes([data[0], data[1]]),
            ..Ext4Inode::default()
        };

        Ok(inode)
    }

    pub fn enumerate_root(&mut self) -> Result<Vec<Ext4DirEntry>, ForensicError> {
        self.read_directory(2)
    }

    pub fn read_directory(&mut self, inode_num: u32) -> Result<Vec<Ext4DirEntry>, ForensicError> {
        let inode = self.read_inode(inode_num)?;

        if (inode.mode & 0x4000) == 0 {
            return Ok(vec![]);
        }

        let mut entries = Vec::new();

        if inode.block[0] > 0 {
            if let Ok(data) = self.read_block(inode.block[0] as u64) {
                let mut pos = 0;
                while pos + 8 <= data.len() {
                    let entry_inode = u32::from_le_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                    ]);
                    let rec_len = u16::from_le_bytes([data[pos + 4], data[pos + 5]]);
                    let name_len = data[pos + 6] as usize;
                    let file_type = data[pos + 7];

                    if entry_inode == 0 {
                        pos += rec_len as usize;
                        continue;
                    }

                    if pos + 8 + name_len > data.len() {
                        break;
                    }

                    let name =
                        String::from_utf8_lossy(&data[pos + 8..pos + 8 + name_len]).to_string();

                    entries.push(Ext4DirEntry {
                        inode: entry_inode,
                        rec_len,
                        name_len: name_len as u16,
                        file_type,
                        name,
                    });

                    if rec_len == 0 {
                        break;
                    }
                    pos += rec_len as usize;
                }
            }
        }

        Ok(entries)
    }

    pub fn read_file(
        &mut self,
        inode_num: u32,
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>, ForensicError> {
        let inode = self.read_inode(inode_num)?;

        let total_size = ((inode.size_high as u64) << 32) | (inode.size_lo as u64);

        if offset >= total_size {
            return Ok(vec![]);
        }

        let remaining = total_size - offset;
        let read_size = size.min(remaining).min(1024 * 1024) as usize;
        let mut buffer = vec![0u8; read_size];

        let mut file_offset: u64 = 0;

        for &block_num in &inode.block {
            if block_num == 0 {
                continue;
            }

            let block_start = block_num as u64 * self.block_size as u64;
            let _block_end = block_start + self.block_size as u64;

            if file_offset + self.block_size as u64 <= offset {
                file_offset += self.block_size as u64;
                continue;
            }

            let data = self.read_block(block_num as u64)?;

            let copy_start = if file_offset < offset {
                (offset - file_offset) as usize
            } else {
                0
            };

            let copy_end = (copy_start + read_size).min(data.len());
            let copy_len = copy_end - copy_start;

            buffer[..copy_len].copy_from_slice(&data[copy_start..copy_end]);

            if buffer.iter().all(|&b| b == 0) {
                break;
            }

            break;
        }

        Ok(buffer)
    }

    pub fn get_stats(&self) -> Ext4Stats {
        let total_blocks = ((self.superblock.s_blocks_count_hi as u64) << 32)
            | (self.superblock.s_blocks_count_lo as u64);
        let free_blocks = ((self.superblock.s_free_blocks_hi as u64) << 32)
            | (self.superblock.s_free_blocks_count_lo as u64);

        Ext4Stats {
            total_blocks,
            free_blocks,
            used_blocks: total_blocks - free_blocks,
            total_inodes: self.superblock.s_inodes_count,
            free_inodes: self.superblock.s_free_inodes_count,
            block_size: self.block_size,
            block_groups: self.block_groups.len() as u32,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ext4Stats {
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub used_blocks: u64,
    pub total_inodes: u32,
    pub free_inodes: u32,
    pub block_size: u32,
    pub block_groups: u32,
}

pub fn ext4_detect(path: &Path) -> Result<bool, ForensicError> {
    let mut file = File::open(path)?;

    file.seek(SeekFrom::Start(EXT4_SUPERBLOCK_OFFSET))?;
    let mut data = [0u8; 2];

    if file.read_exact(&mut data).is_ok() {
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic == EXT4_MAGIC {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn ext4_open(path: &Path) -> Result<Ext4Reader, ForensicError> {
    if ext4_detect(path)? {
        Ext4Reader::open(path)
    } else {
        Err(ForensicError::UnsupportedFilesystem)
    }
}

pub fn ext4_enumerate_root(path: &Path) -> Result<Vec<Ext4DirEntry>, ForensicError> {
    let mut reader = ext4_open(path)?;
    reader.enumerate_root()
}

pub fn ext4_read_directory(path: &Path, inode: u32) -> Result<Vec<Ext4DirEntry>, ForensicError> {
    let mut reader = ext4_open(path)?;
    reader.read_directory(inode)
}

pub fn ext4_read_file(
    path: &Path,
    inode: u32,
    offset: u64,
    size: u64,
) -> Result<Vec<u8>, ForensicError> {
    let mut reader = ext4_open(path)?;
    reader.read_file(inode, offset, size)
}

pub fn ext4_stats(path: &Path) -> Result<Ext4Stats, ForensicError> {
    let reader = ext4_open(path)?;
    Ok(reader.get_stats())
}
