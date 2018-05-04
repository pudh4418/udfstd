use std::env;
use std::io;
use std::io::Cursor;
use std::io::{Seek, SeekFrom};
use std::io::prelude::*;
use std::fs::File;
use std::mem;
use std::slice;
use std::str;
use std::ptr;

#[repr(C)]
#[derive(Debug)]
struct Tag {
    tagid: u16,
    dep_ver: u16,
    tag_checksum: u8,
    rev: u8,
    tagsn: u16,
    depcrc: u16,
    depcrc_len: u16,
    tag_loc: u32,
}

#[repr(C)]
struct TimeStamp {
    type_tz: u16,
    year: i16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    centi_sec: u8,
    hun_mic_sec: u8,
    mic_sec: u8,
}

#[repr(C)]
#[derive(Debug)]
pub struct Short_ad {
    ext_len: u32,
    ext_pos: u32,
}

#[repr(C, packed)]
pub struct LB_addr {
    lbn: u32,
    prn: u16,
}

#[repr(C, packed)]
pub struct Long_ad {
    ext_len: u32,
    ext_pos: LB_addr,
    impl_use: [u8; 6],
}

#[repr(C)]
struct AVDP {
    desp_tag: Tag,
    main_vdse: Short_ad,
    resv_vdse: Short_ad,
    resv: [u8; 480],
}

#[repr(C)]
struct EntityID {
    flags: u8,
    identifier: [u8; 23],
    identifier_suffix: [u8; 8],
}


#[repr(C)]
struct PartitionDescriptor {
    desp_tag: Tag,
    vdsn: u32,
    part_flags: u16,
    part_number: u16,
    part_contents: EntityID,
    pc_use: [u8; 128],
    access_type: u32,
    part_start: u32,
    part_len: u32,
    impl_id: EntityID,
    impl_use: [u8; 128],
    resv: [u8; 156],
}

#[repr(C)]
struct Charspec {
    characterset_type: u8,
    characterset_info: [u8; 63],
}

#[repr(C)]
struct LogicalVolumeDescriptor {
    desp_tag: Tag,
    vdsn: u32,
    desp_charset: Charspec,
    lv_id: [u8; 128],
    lb_size: u32,
    domain_id: EntityID,
    lv_use: Long_ad,
    maptable_len: u32,
    n_partition_maps: u32,
    impl_id: EntityID,
    impl_use: [u8; 128],
    integrity_sequence_extent: Short_ad,
}

#[repr(C)]
struct ICBTag {
    prior_recorded_number_of_direct_entries: u32,
    strategy_type: u16,
    strategy_parameter: [u8; 2],
    max_n_entities: u16,
    resv: u8,
    file_type: u8,
    parent_icb_loc: LB_addr,
    flags: u16,
}

#[repr(C)]
pub struct FileEntry {
    desp_tag: Tag,
    icb_tag: ICBTag,
    uid: u32,
    gid: u32,
    perm: u32,
    link_count: u16,
    rec_format: u8,
    rec_display_attr: u8,
    rec_len: u32,
    info_len: u64,
    lb_recorded: u64,
    access_time: TimeStamp,
    modification_time: TimeStamp,
    attr_time: TimeStamp,
    checkpoint: u32,
    ea_icb: Long_ad,
    impl_id: EntityID,
    unique_id: u64,
    ea_len: u32,
    ad_len: u32,
}

#[repr(C)]
pub struct ExtendedFileEntry {
    desp_tag: Tag,
    icb_tag: ICBTag,
    uid: u32,
    gid: u32,
    perm: u32,
    link_count: u16,
    rec_format: u8,
    rec_display_attr: u8,
    rec_len: u32,
    info_len: u64,
    obj_size: u64,
    lb_recorded: u64,
    access_time: TimeStamp,
    modification_time: TimeStamp,
    creation_time: TimeStamp,
    attr_time: TimeStamp,
    checkpoint: u32,
    resv: u32,
    ea_icb: Long_ad,
    sd_icb: Long_ad,
    impl_id: EntityID,
    unique_id: u64,
    ea_len: u32,
    ad_len: u32,
}

#[repr(C)]
struct FileSetDescriptor {
    desp_tag: Tag,
    rec_time: TimeStamp,
    ix_lv: u16,
    max_ix_lv: u16,
    cs_list: u32,
    max_cs_list: u32,
    fileset_num: u32,
    fileset_desp_num: u32,
    lv_id_charset: Charspec,
    lv_id: [u8; 128],
    fileset_charset: Charspec,
    fileset_id: [u8; 32],
    copyright_id: [u8; 32],
    abstract_id: [u8; 32],
    root_icb: Long_ad,
    domain_id: EntityID,
    next_ext: Long_ad,
    system_stream_dir_icb: Long_ad,
    resv: [u8; 32],
}

#[repr(C, packed)]
struct FileIdentifierDescriptor {
    desp_tag: Tag,
    file_ver: u16,
    file_characteristics: u8,
    file_id_len: u8,
    icb: Long_ad,
    impl_len: u16,
}

#[repr(C)]
struct GenericPM {
    pm_type: u8,
    pm_len: u8,
}

#[repr(C)]
#[derive(Debug)]
struct Type1PM {
    pm_type: u8,
    pm_len: u8,
    vsn: u16,
    part_num: u16,
}

#[repr(C)]
struct MetadataPM {
    pm_type: u8,
    pm_len: u8,
    resv1: u16,
    part_id: EntityID,
    vsn: u16,
    part_num: u16,
    m_file_pos: u32,
    m_mirror_pos: u32,
    m_bitmap_pos: u32,
    alloc_unit_size: u32,
    align_unit_size: u16,
    flags: u8,
    resv2: [u8; 5],
}

pub fn find_anchor(f: &mut File) -> Option<(u32, u32, u32)> {
    let try_size = [2048u32, 512, 4096];
    for size in try_size.iter() {
        f.seek(SeekFrom::Start(*size as u64 * 256)).unwrap();
        let avdp: AVDP = read_struct(f).unwrap();
        if avdp.desp_tag.tagid == 2 {
            return Some((*size, avdp.main_vdse.ext_pos, avdp.main_vdse.ext_len / 2048));
        }
    }
    None
}

fn load_type1_map(f: &mut File, u: &mut UDFstruct, part_num: u16) -> Option<Type1Part> {
    for i in 0..u.anchor_len {
        let seek_len = ((u.anchor_pos + i) * u.sector_size) as u64;
        f.seek(SeekFrom::Start(seek_len)).unwrap();
        let tag: Tag = read_struct(f).unwrap();
        if tag.tagid == 5 {
            let tag_len = mem::size_of::<Tag>() as i64;
            f.seek(SeekFrom::Current(-tag_len)).unwrap();
            let pd: PartitionDescriptor = read_struct(f).unwrap();
            if pd.part_number == part_num {
                return Some(Type1Part {part_start: pd.part_start, part_len: pd.part_len, part_num});
            }
        }
    }
    None
}

fn find_map(u: &mut UDFstruct, part_num: u16) -> Option<usize> {
    for (i, map) in u.maps.iter().enumerate() {
        if let PartMap::Type1(ref m) = *map {
            if m.part_num == part_num {
                return Some(i)
            }
        }
    }
    None
}

fn load_meta_map(pm: MetadataPM, idx: usize) -> Option<MetadataPart> {
    let m = MetadataPart {
        meta_pos: LBA {prn: idx as u16, lbn: pm.m_file_pos},
        meta_mirror_pos: LBA {prn: idx as u16, lbn: pm.m_mirror_pos},
        meta_bitmap_pos: LBA {prn: idx as u16, lbn: pm.m_bitmap_pos},
        base_part: idx,
        alloc_unit_size: pm.alloc_unit_size,
        align_unit_size: pm.align_unit_size,
    };
    Some(m)
}

fn load_part_maps<R: Read + Seek>(map_buf: &mut R, n_pm: u32, u: &mut UDFstruct, f: &mut File) {
    for _i in 0..n_pm {
        let g_pm: GenericPM = read_struct(map_buf).unwrap();
        let buf_len = 2;
        map_buf.seek(SeekFrom::Current(-buf_len)).unwrap();
        if g_pm.pm_type == 1 {
            if g_pm.pm_len != 6 {
            }
            let pm: Type1PM = read_struct(map_buf).unwrap();
            let pm1 = load_type1_map(f, u, pm.part_num).expect("Part not found");
            u.maps.push(PartMap::Type1(pm1));
        }
        else if g_pm.pm_type == 2 {
            if g_pm.pm_len != 64 {
                panic!("File corrupted");
            }
            let pm: MetadataPM = read_struct(map_buf).unwrap();
            let part_index = find_map(u, pm.part_num).unwrap();
            let pm2 = load_meta_map(pm, part_index).unwrap();
            u.maps.push(PartMap::Metadata(pm2));
        }
    }
}

fn load_logical_vol(f: &mut File, u: &mut UDFstruct) {
    for i in 0..u.anchor_len {
        let seek_len = ((u.anchor_pos + i) * u.sector_size) as u64;
        f.seek(SeekFrom::Start(seek_len)).unwrap();
        let tag: Tag = read_struct(f).unwrap();
        if tag.tagid == 6 {
            let tag_len = mem::size_of::<Tag>() as i64;
            f.seek(SeekFrom::Current(-tag_len)).unwrap();
            let lvd: LogicalVolumeDescriptor = read_struct(f).unwrap();
            u.root_fe = From::from(lvd.lv_use.ext_pos);
            println!("FSD_len = {} FSD_loc = ({}, {})", lvd.lv_use.ext_len, u.root_fe.prn, u.root_fe.lbn);
            let mut pm_vec: Vec<u8> = vec![0; lvd.maptable_len as usize];
            f.read_exact(pm_vec.as_mut_slice()).unwrap();
            let mut pm_buf = Cursor::new(pm_vec);
            load_part_maps(&mut pm_buf, lvd.n_partition_maps, u, f);
        }
    }
}

pub fn load_vds(f: &mut File, u: &mut UDFstruct) {
    load_logical_vol(f, u);
}
/* LBA(prn, lbn) */
#[derive(Debug)]
struct LBA {
    lbn: u32,
    prn: u16,
}

impl From<LB_addr> for LBA {
    fn from(x: LB_addr) -> LBA {
        LBA {prn: x.prn, lbn: x.lbn}
    }
}

struct Type1Part {
    part_start: u32,
    part_len: u32,
    part_num: u16,
}

struct MetadataPart {
    meta_pos: LBA,
    meta_mirror_pos: LBA,
    meta_bitmap_pos: LBA,
    base_part: usize,
    alloc_unit_size: u32,
    align_unit_size: u16,
}

enum PartMap {
    Type1(Type1Part),
    Metadata(MetadataPart),
}

pub struct UDFstruct {
    maps: Vec<PartMap>,
    sector_size: u32,
    anchor_pos: u32,
    anchor_len: u32,
    root_fe: LBA,
}

fn get_metadata(m: &MetadataPart, offset: u32, u: &UDFstruct, f: &mut File) -> u64 {
    let seek_pos = m.meta_pos.to_phy(u, f);
    f.seek(SeekFrom::Start(seek_pos)).unwrap();
    let efe: ExtendedFileEntry = read_struct(f).unwrap();
    f.seek(SeekFrom::Current(efe.ea_len as i64)).unwrap();
    let ad: Short_ad = read_struct(f).unwrap();
    let lba = LBA {prn: m.base_part as u16, lbn: ad.ext_pos + offset};
    lba.to_phy(u, f)
}

impl LBA {
    fn to_phy(&self, u: &UDFstruct, f: &mut File) -> u64 {
        let ref m = u.maps[self.prn as usize];
        match *m {
            PartMap::Type1(ref pm) => ((pm.part_start + self.lbn) * u.sector_size) as u64,
            PartMap::Metadata(ref pm) => get_metadata(pm, self.lbn, u, f)
    //        _ => unimplemented!()
        }
    }
}

fn read_struct<T, R: Read>(reader: &mut R) -> io::Result<T>
{
    let buf_len = mem::size_of::<T>();
    unsafe {
        let mut s: T = mem::uninitialized();
        let mut buf = slice::from_raw_parts_mut(&mut s as *mut _ as *mut u8, buf_len);
        reader.read_exact(&mut buf).map(|_| s)
    }
}

fn decode_cs0(input: &[u8]) -> String {
    let comp_id = input[0];
    match comp_id {
        8 | 254 => {
            let vector: Vec<u8> = Vec::from(&input[1..]);
            String::from_utf8(vector).unwrap()
        }
        16 | 255 => {
            let vector: Vec<u16> = input[1..].chunks(2).map(|x| x[0] as u16 * 256 + x[1] as u16).collect();
            String::from_utf16(&vector).unwrap()
        }
        _ => panic!("Unknown charset"),
    }
}

fn read_fileids<R: Read + Seek>(f: &mut R) {
    while let Ok(fid) = read_struct::<FileIdentifierDescriptor, R>(f) {
        let l_fi = fid.file_id_len as usize;
        let l_iu = fid.impl_len as usize;
        let mut fi: Vec<u8> = vec![0; l_fi];
        f.read_exact(fi.as_mut_slice()).unwrap();
        let icb: LBA = From::from(fid.icb.ext_pos);
        let flag = fid.file_characteristics;
        if flag & 0x4 == 0 {
            if flag & 0x8 != 0 {
                print!("Parent dir");
            } else if l_fi > 0 {
                let name = decode_cs0(&fi);
                print!("Name = {}", name);
            }
            println!(" -> ({}, {})", icb.prn, icb.lbn);
        }
        let pad = ((41+l_fi+l_iu)/4*4-(38+l_fi+l_iu)) as i64;
        let loc = f.seek(SeekFrom::Current(pad)).unwrap();
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let filename = &args[1];
    let mut f = File::open(filename).expect("File not find!");
    let (sector_size, anchor_pos, anchor_len) = find_anchor(&mut f).unwrap();
    let mut udf = UDFstruct {
        maps: vec![],
        sector_size,
        anchor_pos,
        anchor_len,
        root_fe: LBA {prn: 0, lbn: 0},
    };
    load_vds(&mut f, &mut udf);
    println!("FSD({}, {}) = {}", udf.root_fe.prn, udf.root_fe.lbn, udf.root_fe.to_phy(&udf, &mut f));
    let seek_loc = udf.root_fe.to_phy(&udf, &mut f);
    f.seek(SeekFrom::Start(seek_loc)).unwrap();
    let fs: FileSetDescriptor = read_struct(&mut f).unwrap();
    println!("Tag = {}, root_icb = ({}, {})", fs.desp_tag.tagid, fs.root_icb.ext_pos.prn, fs.root_icb.ext_pos.lbn);
    let root_lba: LBA = From::from(fs.root_icb.ext_pos);
    let seek_loc = root_lba.to_phy(&udf, &mut f);
    let loc = f.seek(SeekFrom::Start(seek_loc)).unwrap();
    let efe: ExtendedFileEntry = read_struct(&mut f).unwrap();
    println!("Loc = {}, Tag = {}, L_EA = {}, L_AD = {}", loc, efe.desp_tag.tagid, efe.ea_len, efe.ad_len);
    println!("ICB Strategy Type = {}, File type = {}, flags = {}", efe.icb_tag.strategy_type, efe.icb_tag.file_type, efe.icb_tag.flags);
    let mut buf: Vec<u8> = vec![0; efe.ad_len as usize];
    f.seek(SeekFrom::Current(efe.ea_len as i64)).unwrap();
    f.read_exact(buf.as_mut_slice()).unwrap();
    let ad_type = efe.icb_tag.flags & 0x7;
    println!("=====================================");
    match ad_type {
        0 => {
            println!("{:?}", buf);
            let ad: Short_ad = unsafe {ptr::read(buf.as_ptr() as *const Short_ad)};
            let lba = LBA {lbn: ad.ext_pos, prn: udf.root_fe.prn};
            let seek_loc = lba.to_phy(&udf, &mut f);
            let loc = f.seek(SeekFrom::Start(seek_loc)).unwrap();
            let mut fid_buf: Vec<u8> = vec![0; ad.ext_len as usize];
            f.read_exact(fid_buf.as_mut_slice()).unwrap();
            let mut fid_buf = Cursor::new(fid_buf);
            read_fileids(&mut fid_buf);

        }
        1 => println!("Long ad"),
        2 => println!("Ext ad"),
        3 => {
            let mut fid_buf = Cursor::new(buf);
            read_fileids(&mut fid_buf);
        }
        _ => panic!("File corrupted"),
    }
}
