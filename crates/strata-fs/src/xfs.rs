use crate::errors::ForensicError;

pub fn xfs_fast_scan(data: &[u8]) -> Result<XfsFastScanResult, ForensicError> {
    if data.len() < 0x100 {
        return Ok(XfsFastScanResult::default());
    }
    if &data[0..4] != b"XFSB" {
        return Ok(XfsFastScanResult::default());
    }

    let block_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let total_blocks = u64::from_be_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);
    let free_blocks = u64::from_be_bytes([
        data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
    ]);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&data[32..48]);
    let volume_name = String::from_utf8_lossy(&data[108..120])
        .trim_matches(char::from(0))
        .trim()
        .to_string();

    Ok(XfsFastScanResult {
        found: true,
        block_size,
        fs_uuid: uuid,
        volume_name,
        total_blocks,
        free_blocks,
    })
}

#[derive(Debug, Clone, Default)]
pub struct XfsFastScanResult {
    pub found: bool,
    pub block_size: u32,
    pub fs_uuid: [u8; 16],
    pub volume_name: String,
    pub total_blocks: u64,
    pub free_blocks: u64,
}

pub fn open_xfs(data: &[u8]) -> Result<XfsFilesystem, ForensicError> {
    let scan = xfs_fast_scan(data)?;
    if !scan.found {
        return Err(ForensicError::UnsupportedFilesystem);
    }
    Ok(XfsFilesystem {
        superblock: XfsSuperblock {
            magic: *b"XFSB",
            block_size: scan.block_size,
            blocks: scan.total_blocks,
            uuid: scan.fs_uuid,
            sb_uuid: scan.fs_uuid,
            ..Default::default()
        },
        ag_headers: vec![],
        image: data.to_vec(),
    })
}

#[derive(Debug, Clone)]
pub struct XfsFilesystem {
    pub superblock: XfsSuperblock,
    pub ag_headers: Vec<XfsAgHeader>,
    pub image: Vec<u8>,
}

impl XfsFilesystem {
    pub fn read_block(&self, block: u64) -> Result<Vec<u8>, ForensicError> {
        let block_size = self.superblock.block_size as u64;
        let start = block
            .checked_mul(block_size)
            .ok_or_else(|| ForensicError::OutOfRange("xfs block overflow".to_string()))?;
        let end = start
            .checked_add(block_size)
            .ok_or_else(|| ForensicError::OutOfRange("xfs block overflow".to_string()))?;
        let start = usize::try_from(start)
            .map_err(|_| ForensicError::OutOfRange("xfs start overflow".to_string()))?;
        let end = usize::try_from(end)
            .map_err(|_| ForensicError::OutOfRange("xfs end overflow".to_string()))?;
        if end > self.image.len() {
            return Err(ForensicError::OutOfRange(
                "xfs block out of range".to_string(),
            ));
        }
        Ok(self.image[start..end].to_vec())
    }

    pub fn read_inode(&self, inode_num: u64) -> Result<XfsInode, ForensicError> {
        let block_size = self.superblock.block_size as u64;
        let inode_size = self.superblock.inodesize as u64;
        let agblocks = self.superblock.agblocks as u64;

        let ag_num = inode_num / agblocks;
        let inode_idx = inode_num % agblocks;

        if ag_num >= self.superblock.agcount as u64 {
            return Err(ForensicError::OutOfRange(format!(
                "AG {} out of range (max {})",
                ag_num, self.superblock.agcount
            )));
        }

        let ag_offset = ag_num * agblocks * block_size;
        let inode_offset = inode_idx * inode_size;

        let total_offset = ag_offset + inode_offset;

        if (total_offset + inode_size) as usize > self.image.len() {
            return Err(ForensicError::OutOfRange(format!(
                "Inode {} at offset {} out of range",
                inode_num, total_offset
            )));
        }

        let inode_data = &self.image[total_offset as usize..(total_offset + inode_size) as usize];
        parse_xfs_inode(inode_data)
    }

    pub fn read_directory(&self, inode: &XfsInode) -> Result<Vec<XfsDirEntry>, ForensicError> {
        let mut entries = Vec::new();
        let size = inode.size as usize;

        if inode.size == 0 {
            return Ok(entries);
        }

        let fork_offset = inode.fork_offset as usize;
        let inode_size = self.superblock.inodesize as usize;

        if fork_offset >= inode_size || fork_offset + size > inode_size {
            return Err(ForensicError::InvalidImageFormat);
        }

        let inode_data_start = 0u64;
        let dir_data_offset = inode_data_start + fork_offset as u64;

        if (dir_data_offset + size as u64) as usize > self.image.len() {
            return Err(ForensicError::OutOfRange(
                "Directory data out of range".to_string(),
            ));
        }

        let dir_data =
            &self.image[dir_data_offset as usize..(dir_data_offset as usize + size.min(256))];

        self.parse_directory_block(dir_data, &mut entries)?;

        Ok(entries)
    }

    fn parse_directory_block(
        &self,
        data: &[u8],
        entries: &mut Vec<XfsDirEntry>,
    ) -> Result<(), ForensicError> {
        if data.len() < 16 {
            return Ok(());
        }

        let magic = u16::from_be_bytes([data[0], data[1]]);

        if magic == 0x3ABE || magic == 0x3BBE {
            return self.parse_xfs_dir3_data(data, entries);
        } else if magic == 0xFEEE {
            return self.parse_xfs_dir2_data(data, entries);
        }

        let mut pos = 16;

        while pos + 8 <= data.len() {
            let inode = u64::from_be_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);

            if inode == 0 {
                break;
            }

            let name_len = data[pos + 8] as usize;
            let entry_type = data[pos + 9];

            pos += 10;

            if pos + name_len > data.len() {
                break;
            }

            let name_bytes = &data[pos..pos + name_len.min(255)];
            let name = String::from_utf8_lossy(name_bytes).trim().to_string();

            if !name.is_empty() && name != "." && name != ".." {
                let xfs_type = match entry_type {
                    1 => XfsFileType::Regular,
                    2 => XfsFileType::Directory,
                    3 => XfsFileType::CharDevice,
                    4 => XfsFileType::BlockDevice,
                    5 => XfsFileType::Fifo,
                    6 => XfsFileType::Socket,
                    7 => XfsFileType::Symlink,
                    _ => XfsFileType::Unknown,
                };

                entries.push(XfsDirEntry {
                    inode,
                    offset: 0,
                    name,
                    entry_type: xfs_type,
                });
            }

            pos += name_len.min(255);
        }

        Ok(())
    }

    fn parse_xfs_dir2_data(
        &self,
        data: &[u8],
        entries: &mut Vec<XfsDirEntry>,
    ) -> Result<(), ForensicError> {
        let mut pos = 16;

        while pos + 8 <= data.len() {
            let inode = u64::from_be_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);

            if inode == 0 {
                break;
            }

            let name_len = data[pos + 8] as usize;
            let entry_type = data[pos + 9];

            pos += 10;

            if pos + name_len > data.len() {
                break;
            }

            let name_bytes = &data[pos..pos + name_len.min(255)];
            let name = String::from_utf8_lossy(name_bytes).trim().to_string();

            if !name.is_empty() && name != "." && name != ".." {
                let xfs_type = match entry_type {
                    1 => XfsFileType::Regular,
                    2 => XfsFileType::Directory,
                    3 => XfsFileType::CharDevice,
                    4 => XfsFileType::BlockDevice,
                    5 => XfsFileType::Fifo,
                    6 => XfsFileType::Socket,
                    7 => XfsFileType::Symlink,
                    _ => XfsFileType::Unknown,
                };

                entries.push(XfsDirEntry {
                    inode,
                    offset: 0,
                    name,
                    entry_type: xfs_type,
                });
            }

            pos += name_len.min(255);
        }

        Ok(())
    }

    fn parse_xfs_dir3_data(
        &self,
        data: &[u8],
        entries: &mut Vec<XfsDirEntry>,
    ) -> Result<(), ForensicError> {
        let mut pos = 16;

        while pos + 8 <= data.len() {
            let inode = u64::from_be_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);

            if inode == 0 {
                break;
            }

            let name_len = data[pos + 8] as usize;
            let entry_type = data[pos + 9];

            pos += 10;

            if pos + name_len > data.len() {
                break;
            }

            let name_bytes = &data[pos..pos + name_len.min(255)];
            let name = String::from_utf8_lossy(name_bytes).trim().to_string();

            if !name.is_empty() && name != "." && name != ".." {
                let xfs_type = match entry_type {
                    1 => XfsFileType::Regular,
                    2 => XfsFileType::Directory,
                    3 => XfsFileType::CharDevice,
                    4 => XfsFileType::BlockDevice,
                    5 => XfsFileType::Fifo,
                    6 => XfsFileType::Socket,
                    7 => XfsFileType::Symlink,
                    _ => XfsFileType::Unknown,
                };

                entries.push(XfsDirEntry {
                    inode,
                    offset: 0,
                    name,
                    entry_type: xfs_type,
                });
            }

            pos += name_len.min(255);
        }

        Ok(())
    }

    pub fn enumerate_root(&self) -> Result<Vec<XfsDirEntry>, ForensicError> {
        let root_inode_num = self.superblock.sb_rootino;
        let inode = self.read_inode(root_inode_num)?;
        self.read_directory(&inode)
    }
}

#[derive(Debug, Clone, Default)]
pub struct XfsSuperblock {
    pub magic: [u8; 4],
    pub block_size: u32,
    pub blocks: u64,
    pub rtext: u32,
    pub agblocks: u32,
    pub agcount: u32,
    pub sectsize: u32,
    pub inodesize: u16,
    pub inopblock: u16,
    pub uuid: [u8; 16],
    pub sb_rootino: u64,
    pub sb_rbmino: u64,
    pub sb_rsumino: u64,
    pub sb_rextents: u64,
    pub sb_uuid: [u8; 16],
    pub sb_unit: u32,
    pub sb_width: u32,
    pub sb_versionnum: u16,
    pub sb_shared_vn: u8,
    pub sb_inoalignmt: u16,
    pub sb_dummy2: [u8; 2],
    pub sb_padding: [u8; 16],
}

#[derive(Debug, Clone, Default)]
pub struct XfsAgHeader {
    pub agf_magicnum: [u8; 4],
    pub agf_versionnum: u32,
    pub agf_seqno: u32,
    pub agf_length: u32,
    pub agf_roots: [u64; 2],
    pub agf_levels: [u32; 2],
}

#[derive(Debug, Clone, Default)]
pub struct XfsInode {
    pub magic: [u8; 4],
    pub mode: u16,
    pub version: u8,
    pub format: u8,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u32,
    pub atime_nsec: u32,
    pub mtime: u32,
    pub mtime_nsec: u32,
    pub ctime: u32,
    pub ctime_nsec: u32,
    pub size_extended: u64,
    pub nblocks: u64,
    pub extsize: u32,
    pub nextents: u16,
    pub aextents: u16,
    pub fork_offset: u16,
    pub da_offset: u64,
    pub da_lastrun: u32,
    pub da_blocks: u64,
    pub da_external_offset: u64,
    pub fork: XfsInodeFork,
}

#[derive(Debug, Clone, Default)]
pub struct XfsInodeFork {
    pub format: XfsInodeFormat,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub enum XfsInodeFormat {
    #[default]
    Local,
    Extents,
    Btree,
    Attr,
}

#[derive(Debug, Clone, Default)]
pub struct XfsDirEntry {
    pub inode: u64,
    pub offset: u64,
    pub name: String,
    pub entry_type: XfsFileType,
}

#[derive(Debug, Clone, Default)]
pub enum XfsFileType {
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

pub fn parse_xfs_inode(data: &[u8]) -> Result<XfsInode, ForensicError> {
    if data.len() < 176 {
        return Err(ForensicError::InvalidImageFormat);
    }

    let magic = [data[0], data[1], data[2], data[3]];
    let mode = u16::from_be_bytes([data[4], data[5]]);
    let version = data[6];
    let format = data[7];
    let nlink = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let uid = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let gid = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    let size = u64::from_be_bytes([
        data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
    ]);
    let atime = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);
    let atime_nsec = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
    let mtime = u32::from_be_bytes([data[36], data[37], data[38], data[39]]);
    let mtime_nsec = u32::from_be_bytes([data[40], data[41], data[42], data[43]]);
    let ctime = u32::from_be_bytes([data[44], data[45], data[46], data[47]]);
    let ctime_nsec = u32::from_be_bytes([data[48], data[49], data[50], data[51]]);
    let size_extended = u64::from_be_bytes([
        data[52], data[53], data[54], data[55], data[56], data[57], data[58], data[59],
    ]);
    let nblocks = u64::from_be_bytes([
        data[60], data[61], data[62], data[63], data[64], data[65], data[66], data[67],
    ]);
    let extsize = u32::from_be_bytes([data[68], data[69], data[70], data[71]]);
    let nextents = u16::from_be_bytes([data[72], data[73]]);
    let aextents = u16::from_be_bytes([data[74], data[75]]);
    let fork_offset = u16::from_be_bytes([data[76], data[77]]);
    let da_offset = u64::from_be_bytes([
        data[104], data[105], data[106], data[107], data[108], data[109], data[110], data[111],
    ]);
    let da_lastrun = u32::from_be_bytes([data[112], data[113], data[114], data[115]]);
    let da_blocks = u64::from_be_bytes([
        data[116], data[117], data[118], data[119], data[120], data[121], data[122], data[123],
    ]);
    let da_external_offset = u64::from_be_bytes([
        data[124], data[125], data[126], data[127], data[128], data[129], data[130], data[131],
    ]);

    Ok(XfsInode {
        magic,
        mode,
        version,
        format,
        nlink,
        uid,
        gid,
        size,
        atime,
        atime_nsec,
        mtime,
        mtime_nsec,
        ctime,
        ctime_nsec,
        size_extended,
        nblocks,
        extsize,
        nextents,
        aextents,
        fork_offset,
        da_offset,
        da_lastrun,
        da_blocks,
        da_external_offset,
        fork: XfsInodeFork {
            format: match format {
                1 => XfsInodeFormat::Local,
                2 => XfsInodeFormat::Extents,
                3 => XfsInodeFormat::Btree,
                _ => XfsInodeFormat::Local,
            },
            data: Vec::new(),
        },
    })
}

pub fn walk_xfs_directory(
    fs: &XfsFilesystem,
    inode: &XfsInode,
) -> Result<Vec<XfsDirEntry>, ForensicError> {
    fs.read_directory(inode)
}

pub fn extract_xfs_timeline(_fs: &XfsFilesystem) -> Result<Vec<XfsTimelineEntry>, ForensicError> {
    Ok(vec![])
}

#[derive(Debug, Clone, Default)]
pub struct XfsTimelineEntry {
    pub timestamp: u64,
    pub inode: u64,
    pub path: String,
    pub action: String,
}

pub struct XfsReader {
    data: Vec<u8>,
    superblock: XfsSuperblock,
}

impl XfsReader {
    pub fn open(data: &[u8]) -> Result<Self, ForensicError> {
        let scan = xfs_fast_scan(data)?;
        if !scan.found {
            return Err(ForensicError::UnsupportedFilesystem);
        }

        let mut sb = XfsSuperblock {
            magic: *b"XFSB",
            block_size: scan.block_size,
            blocks: scan.total_blocks,
            uuid: scan.fs_uuid,
            sb_uuid: scan.fs_uuid,
            ..Default::default()
        };

        if data.len() >= 0x100 {
            sb.rtext = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
            sb.agblocks = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
            sb.agcount = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
            sb.sectsize = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);
            sb.inodesize = u16::from_be_bytes([data[32], data[33]]);
            sb.inopblock = u16::from_be_bytes([data[34], data[35]]);
            sb.sb_rootino = u64::from_be_bytes([
                data[104], data[105], data[106], data[107], data[108], data[109], data[110],
                data[111],
            ]);
            sb.sb_rbmino = u64::from_be_bytes([
                data[112], data[113], data[114], data[115], data[116], data[117], data[118],
                data[119],
            ]);
            sb.sb_rsumino = u64::from_be_bytes([
                data[120], data[121], data[122], data[123], data[124], data[125], data[126],
                data[127],
            ]);
            sb.sb_rextents = u64::from_be_bytes([
                data[128], data[129], data[130], data[131], data[132], data[133], data[134],
                data[135],
            ]);
            sb.sb_uuid.copy_from_slice(&data[32..48]);
            sb.sb_unit = u32::from_be_bytes([data[136], data[137], data[138], data[139]]);
            sb.sb_width = u32::from_be_bytes([data[140], data[141], data[142], data[143]]);
            sb.sb_versionnum = u16::from_be_bytes([data[144], data[145]]);
            sb.sb_shared_vn = data[146];
            sb.sb_inoalignmt = u16::from_be_bytes([data[147], data[148]]);
        }

        // For minimal XFS images, set default values if fields are 0
        if sb.agblocks == 0 {
            sb.agblocks = 0x1000; // 4096 blocks per AG (typical)
        }
        if sb.agcount == 0 {
            sb.agcount = 1;
        }
        if sb.inodesize == 0 {
            sb.inodesize = 256;
        }
        if sb.sectsize == 0 {
            sb.sectsize = 512;
        }
        if sb.sb_rootino == 0 {
            sb.sb_rootino = 128; // Root inode typically at 128
        }

        Ok(Self {
            data: data.to_vec(),
            superblock: sb,
        })
    }

    pub fn get_superblock(&self) -> &XfsSuperblock {
        &self.superblock
    }

    pub fn read_inode(&self, inode_num: u64) -> Result<XfsInode, ForensicError> {
        let block_size = self.superblock.block_size as u64;
        let inode_size = self.superblock.inodesize as u64;
        let agblocks = self.superblock.agblocks as u64;

        if agblocks == 0 {
            return Err(ForensicError::InvalidImageFormat);
        }

        let ag_num = inode_num / agblocks;
        let inode_idx = inode_num % agblocks;

        if ag_num >= self.superblock.agcount as u64 {
            return Err(ForensicError::OutOfRange(format!(
                "AG {} out of range (max {})",
                ag_num, self.superblock.agcount
            )));
        }

        let ag_offset = ag_num * agblocks * block_size;
        let inode_offset = inode_idx * inode_size;

        let total_offset = ag_offset + inode_offset;

        if (total_offset + inode_size) as usize > self.data.len() {
            return Err(ForensicError::OutOfRange(format!(
                "Inode {} at offset {} out of range",
                inode_num, total_offset
            )));
        }

        let inode_data = &self.data[total_offset as usize..(total_offset + inode_size) as usize];
        self.parse_inode(inode_data)
    }

    fn parse_inode(&self, data: &[u8]) -> Result<XfsInode, ForensicError> {
        if data.len() < 176 {
            return Err(ForensicError::InvalidImageFormat);
        }

        let magic = [data[0], data[1], data[2], data[3]];
        let mode = u16::from_be_bytes([data[4], data[5]]);
        let version = data[6];
        let format = data[7];
        let nlink = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let uid = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let gid = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let size = u64::from_be_bytes([
            data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
        ]);
        let atime = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);
        let atime_nsec = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        let mtime = u32::from_be_bytes([data[36], data[37], data[38], data[39]]);
        let mtime_nsec = u32::from_be_bytes([data[40], data[41], data[42], data[43]]);
        let ctime = u32::from_be_bytes([data[44], data[45], data[46], data[47]]);
        let ctime_nsec = u32::from_be_bytes([data[48], data[49], data[50], data[51]]);
        let size_extended = u64::from_be_bytes([
            data[52], data[53], data[54], data[55], data[56], data[57], data[58], data[59],
        ]);
        let nblocks = u64::from_be_bytes([
            data[60], data[61], data[62], data[63], data[64], data[65], data[66], data[67],
        ]);
        let extsize = u32::from_be_bytes([data[68], data[69], data[70], data[71]]);
        let nextents = u16::from_be_bytes([data[72], data[73]]);
        let aextents = u16::from_be_bytes([data[74], data[75]]);
        let fork_offset = u16::from_be_bytes([data[76], data[77]]);
        let da_offset = u64::from_be_bytes([
            data[104], data[105], data[106], data[107], data[108], data[109], data[110], data[111],
        ]);
        let da_lastrun = u32::from_be_bytes([data[112], data[113], data[114], data[115]]);
        let da_blocks = u64::from_be_bytes([
            data[116], data[117], data[118], data[119], data[120], data[121], data[122], data[123],
        ]);
        let da_external_offset = u64::from_be_bytes([
            data[124], data[125], data[126], data[127], data[128], data[129], data[130], data[131],
        ]);

        Ok(XfsInode {
            magic,
            mode,
            version,
            format,
            nlink,
            uid,
            gid,
            size,
            atime,
            atime_nsec,
            mtime,
            mtime_nsec,
            ctime,
            ctime_nsec,
            size_extended,
            nblocks,
            extsize,
            nextents,
            aextents,
            fork_offset,
            da_offset,
            da_lastrun,
            da_blocks,
            da_external_offset,
            fork: XfsInodeFork {
                format: match format {
                    1 => XfsInodeFormat::Local,
                    2 => XfsInodeFormat::Extents,
                    3 => XfsInodeFormat::Btree,
                    _ => XfsInodeFormat::Local,
                },
                data: Vec::new(),
            },
        })
    }

    pub fn read_directory(&self, inode: &XfsInode) -> Result<Vec<XfsDirEntry>, ForensicError> {
        let mut entries = Vec::new();
        let size = inode.size as usize;

        if inode.size == 0 {
            return Ok(entries);
        }

        let fork_offset = inode.fork_offset as usize;
        let inode_size = self.superblock.inodesize as usize;

        if fork_offset >= inode_size || fork_offset + size > inode_size {
            return Err(ForensicError::InvalidImageFormat);
        }

        let ag_offset = 0u64;
        let block_size = self.superblock.block_size as u64;
        let inode_num = (ag_offset / (block_size * self.superblock.agblocks as u64))
            * self.superblock.agblocks as u64;

        let inode_data_start = inode_num * self.superblock.inodesize as u64;
        let dir_data_offset = inode_data_start + fork_offset as u64;

        if (dir_data_offset + size as u64) as usize > self.data.len() {
            return Err(ForensicError::OutOfRange(
                "Directory data out of range".to_string(),
            ));
        }

        let dir_data =
            &self.data[dir_data_offset as usize..(dir_data_offset as usize + size.min(256))];

        self.parse_directory_block(dir_data, &mut entries)?;

        Ok(entries)
    }

    fn parse_directory_block(
        &self,
        data: &[u8],
        entries: &mut Vec<XfsDirEntry>,
    ) -> Result<(), ForensicError> {
        if data.len() < 16 {
            return Ok(());
        }

        let magic = u16::from_be_bytes([data[0], data[1]]);
        if magic == 0x3ABE {
            self.parse_xfs_dir3_data(data, entries)?;
        } else if magic == 0xFEEE || data.len() >= 8 {
            self.parse_xfs_dir2_data(data, entries)?;
        }

        Ok(())
    }

    fn parse_xfs_dir2_data(
        &self,
        data: &[u8],
        entries: &mut Vec<XfsDirEntry>,
    ) -> Result<(), ForensicError> {
        if data.len() < 16 {
            return Ok(());
        }

        let mut offset: u64 = 0;
        let mut pos = if data[1] == 0x30 || data[1] == 0x32 || data[1] == 0x58 || data[0] == 0xFE {
            16
        } else {
            0
        };

        while pos + 8 <= data.len() {
            let inode = u64::from_be_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);

            if inode == 0 {
                break;
            }

            let mut name_len = data[pos + 8] as usize;
            let entry_type = data[pos + 9];

            if name_len > 255 {
                name_len = 255;
            }

            pos += 10;

            if pos + name_len > data.len() {
                break;
            }

            let name_bytes = &data[pos..pos + name_len];
            let name = String::from_utf8_lossy(name_bytes).trim().to_string();

            if !name.is_empty() && name != "." && name != ".." {
                let xfs_type = match entry_type {
                    1 => XfsFileType::Regular,
                    2 => XfsFileType::Directory,
                    3 => XfsFileType::CharDevice,
                    4 => XfsFileType::BlockDevice,
                    5 => XfsFileType::Fifo,
                    6 => XfsFileType::Socket,
                    7 => XfsFileType::Symlink,
                    _ => XfsFileType::Unknown,
                };

                entries.push(XfsDirEntry {
                    inode,
                    offset,
                    name,
                    entry_type: xfs_type,
                });
            }

            pos += name_len;
            offset += 1;
        }

        Ok(())
    }

    fn parse_xfs_dir3_data(
        &self,
        data: &[u8],
        entries: &mut Vec<XfsDirEntry>,
    ) -> Result<(), ForensicError> {
        if data.len() < 16 {
            return Ok(());
        }

        let mut pos = 16;

        while pos + 8 <= data.len() {
            let inode = u64::from_be_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);

            if inode == 0 {
                break;
            }

            let mut name_len = data[pos + 8] as usize;
            let entry_type = data[pos + 9];

            if name_len > 255 {
                name_len = 255;
            }

            pos += 10;

            if pos + name_len > data.len() {
                break;
            }

            let name_bytes = &data[pos..pos + name_len];
            let name = String::from_utf8_lossy(name_bytes).trim().to_string();

            if !name.is_empty() && name != "." && name != ".." {
                let xfs_type = match entry_type {
                    1 => XfsFileType::Regular,
                    2 => XfsFileType::Directory,
                    3 => XfsFileType::CharDevice,
                    4 => XfsFileType::BlockDevice,
                    5 => XfsFileType::Fifo,
                    6 => XfsFileType::Socket,
                    7 => XfsFileType::Symlink,
                    _ => XfsFileType::Unknown,
                };

                entries.push(XfsDirEntry {
                    inode,
                    offset: 0,
                    name,
                    entry_type: xfs_type,
                });
            }

            pos += name_len;
        }

        Ok(())
    }

    pub fn enumerate_root(&self) -> Result<Vec<XfsDirEntry>, ForensicError> {
        let root_inode_num = self.superblock.sb_rootino;
        let inode = self.read_inode(root_inode_num)?;
        self.read_directory(&inode)
    }

    pub fn enumerate_directory_by_inode(
        &self,
        inode_num: u64,
    ) -> Result<Vec<XfsDirEntry>, ForensicError> {
        let inode = self.read_inode(inode_num)?;
        self.read_directory(&inode)
    }
}
