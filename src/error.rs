//! A custom Goblin error
//!

use core::fmt;
use core::num::TryFromIntError;
use core::result;
#[cfg(feature = "std")]
use std::{error, io};

use crate::pe::section_table;

#[non_exhaustive]
#[derive(Debug)]
/// A custom Goblin error
pub enum Error {
    /// The binary is malformed somehow
    Malformed(Malformed),
    /// The binary's magic is unknown or bad
    BadMagic(u64),
    /// An error emanating from reading and interpreting bytes
    Scroll(scroll::Error),
    /// An IO based error
    #[cfg(feature = "std")]
    IO(io::Error),
    /// Buffer is too short to hold N items
    BufferTooShort(usize, &'static str),
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::Malformed(ref malformed) => Some(malformed),
            Error::IO(ref io) => Some(io),
            Error::Scroll(ref scroll) => Some(scroll),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<Malformed> for Error {
    fn from(err: Malformed) -> Error {
        Error::Malformed(err)
    }
}

impl From<TryFromIntError> for Error {
    fn from(err: TryFromIntError) -> Error {
        Error::Malformed(Malformed::from(err))
    }
}

impl From<scroll::Error> for Error {
    fn from(err: scroll::Error) -> Error {
        Error::Scroll(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "std")]
            Error::IO(ref err) => write!(fmt, "{}", err),
            Error::Scroll(ref err) => write!(fmt, "{}", err),
            Error::BadMagic(magic) => write!(fmt, "Invalid magic number: 0x{:x}", magic),
            Error::Malformed(ref msg) => write!(fmt, "Malformed entity: {}", msg),
            Error::BufferTooShort(n, item) => write!(fmt, "Buffer is too short for {} {}", n, item),
        }
    }
}

// #[non_exhaustive]
#[derive(Debug)]
pub enum Malformed {
    IntegerConversion(TryFromIntError),
    TooSmall,
    StrtabOutOfBounds {
        size: usize,
        offset: usize,
        num_bytes: usize,
        overflow: bool,
    },
    BadMemberHeaderSize {
        err: core::num::ParseIntError,
        header: crate::archive::MemberHeader,
    },
    SymdefEntryOutOfBounds {
        symdef: &'static str,
        entry: usize,
        string_offset: u32,
    },
    NameIndexOutOfRange {
        name: String,
    },
    NameIndexNotFound {
        name: String,
    },
    BadNameIndex {
        name: String,
    },
    BadArchiveMemberOffset {
        name: String,
        member_offset: u32,
    },
    MissingArchiveMember {
        member: String,
    },
    InvalidElfPtDynamicSize {
        offset: usize,
        filesz: usize,
    },
    InvalidElfField {
        field: &'static str,
        value: u8,
    },
    InvalidElfDtGnuHash {
        buckets_num: usize,
        min_chain: usize,
        bloom_size: usize,
    },
    UnsupportedElfAlignment {
        alignment: usize,
    },
    ElfSectionOutOfBounds {
        section: usize,
        size: u64,
        kind: &'static str,
        value: u64,
        overflow: bool,
    },
    TooManyElfSymbols {
        offset: usize,
        count: usize,
    },
    MachUnsupportedCpuType {
        cputype: crate::mach::cputype::CpuType,
    },
    MachThreadStateTooLong {
        count: u32,
    },
    MachThreadCommandTooLong {
        thread_state_byte_length: usize,
        num_bytes: usize,
    },
    MachUnknownPlatform {
        cmd: u32,
    },
    MachLoadCommandHeaderTooLong {
        header: crate::mach::load_command::LoadCommandHeader,
        num_bytes: usize,
    },
    MachLcMainNoText {
        offset: u64,
    },
    MachNoParsingContext {
        magic: u32,
    },
    MachBinaryIndexOutOfBounds {
        index: usize,
        num_arches: usize,
    },
    PeMalformedCertificate {
        cert_size: usize,
    },
    PeDataDirectoryCountOutOfBounds {
        count: usize,
        num_data_directories: usize,
    },
    PeInvalidImageDebugDirectoryDataSize {
        size_of_data: u32,
    },
    PeImageDebugDirectoryCorrupted {
        idd: crate::pe::debug::ImageDebugDirectory,
    },
    PeInvalidOpInfo {
        operation_info: u8,
        operation_code: &'static str,
    },
    PeUnknownUnwindOp {
        op: u8,
    },
    PeUnsupportedUnwindVersion {
        version: u8,
    },
    PeInvalidVirtualAddressOffset {
        name: &'static str,
        virtual_address: u32,
    },
    PeInvalidVirtualAddressOffsetFor {
        name: &'static str,
        virtual_address: u32,
        section: String,
    },
    PeVirtualAddressNameNotFound {
        virtual_address: u32,
        sections: Vec<section_table::SectionTable>,
    },
    PeParseFailedAt {
        name: &'static str,
        offset: usize,
    },
    PeCannotParseReexportOrdinal {
        num_bytes: usize,
    },
    PeReexportMalformed {
        reexport: String,
    },
    PeCannotGetExportOrdinalRva {
        ordinal: u16,
    },
    PeCannotGetExportNameEntryOridnal {
        export: usize,
    },
    PeSignatureMalformed {
        name: &'static str,
        signature: usize,
    },
    PeUnsupportedMagic {
        magic: u16,
    },
    PeSectionDataMalformed {
        section: String,
    },
    PeSectionDataPointerTooBig {
        section: String,
    },
    PeInvalidIndirectSectionNameBase64 {
        base64_index: String,
    },
    PeInvalidIndirectSectionNameInt {
        name: String,
        err: core::num::ParseIntError,
    },
    PeInvalidSectionNameOffset {
        offset: usize,
    },
    PeInvlaidSymbolNameOffset {
        offset: usize,
    },
    General(&'static str),
    GeneralString(String),
}

#[cfg(feature = "std")]
impl std::error::Error for Malformed {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Malformed::IntegerConversion(err) => Some(err),
            Malformed::PeInvalidIndirectSectionNameInt { err, .. } => Some(err),
            _ => None,
        }
    }
}

impl From<TryFromIntError> for Malformed {
    fn from(err: TryFromIntError) -> Malformed {
        Malformed::IntegerConversion(err)
    }
}

impl fmt::Display for Malformed {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::IntegerConversion(err) => write!(fmt, "Integer does not fit: {}", err),
            Self::TooSmall => write!(fmt, "Too small"),
            Self::StrtabOutOfBounds {
                size,
                offset,
                num_bytes,
                overflow,
            } => {
                write!(fmt,
                    "Strtable size ({}) + offset ({}) is out of bounds for {} #bytes. Overflowed: {}",
                    size,
                    offset,
                    num_bytes,
                    overflow
                )
            }
            Self::BadMemberHeaderSize { err, header } => {
                write!(fmt, "{:?} Bad file_size in header: {:?}", err, header)
            }
            Self::SymdefEntryOutOfBounds {
                symdef,
                entry,
                string_offset,
            } => {
                write!(
                    fmt,
                    "{} entry {} has string offset {}, which is out of bounds",
                    symdef, entry, string_offset
                )
            }
            Self::NameIndexOutOfRange { name } => {
                write!(fmt, "Name {} is out of range in archive NameIndex", name)
            }
            Self::NameIndexNotFound { name } => {
                write!(fmt, "Could not find {:?} in index", name)
            }
            Self::BadNameIndex { name } => {
                write!(fmt, "Bad name index {:?} in index", name)
            }
            Self::BadArchiveMemberOffset {
                name,
                member_offset,
            } => {
                write!(
                    fmt,
                    "Could not get member {:?} at offset: {}",
                    name, member_offset
                )
            }
            Self::MissingArchiveMember { member } => {
                write!(fmt, "Cannot extract member {:?}", member)
            }
            Self::InvalidElfPtDynamicSize { offset, filesz } => {
                write!(
                    fmt,
                    "Invalid PT_DYNAMIC size (offset {:#x}, filesz {:#x})",
                    offset, filesz
                )
            }
            Self::InvalidElfField { field, value } => {
                write!(fmt, "Invalid ELF {}: {}", field, value)
            }
            Self::InvalidElfDtGnuHash {
                buckets_num,
                min_chain,
                bloom_size,
            } => {
                write!(
                    fmt,
                    "Invalid DT_GNU_HASH: buckets_num={} min_chain={} bloom_size={}",
                    buckets_num, min_chain, bloom_size
                )
            }
            Self::UnsupportedElfAlignment { alignment } => {
                write!(
                    fmt,
                    "Notes has unimplemented alignment requirement: {:#x}",
                    alignment
                )
            }
            Self::ElfSectionOutOfBounds {
                section,
                size,
                kind,
                value,
                overflow,
            } => {
                write!(
                    fmt,
                    "Section {} size ({}) + {} ({}) is out of bounds. Overflowed: {}",
                    section, size, kind, value, overflow
                )
            }
            Self::TooManyElfSymbols { offset, count } => {
                write!(
                    fmt,
                    "Too many ELF symbols (offset {:#x}, count {})",
                    offset, count
                )
            }
            Self::MachUnsupportedCpuType { cputype } => {
                write!(
                    fmt,
                    "unable to find instruction pointer for cputype {:?}",
                    cputype
                )
            }
            Self::MachThreadStateTooLong { count } => {
                write!(
                    fmt,
                    "thread command specifies {} longs for thread state but we handle only 70",
                    count
                )
            }
            Self::MachThreadCommandTooLong {
                thread_state_byte_length,
                num_bytes,
            } => {
                write!(
                    fmt,
                    "thread command specifies {} bytes for thread state but has only {}",
                    thread_state_byte_length, num_bytes
                )
            }
            Self::MachUnknownPlatform { cmd } => {
                write!(fmt, "unknown platform for load command: {:x}", cmd)
            }
            Self::MachLoadCommandHeaderTooLong { header, num_bytes } => {
                write!(
                    fmt,
                    "{} has size larger than remainder of binary: {:?}",
                    header, num_bytes
                )
            }
            Self::MachLcMainNoText { offset } => {
                write!(
                    fmt,
                    "image specifies LC_MAIN offset {} but has no __TEXT segment",
                    offset
                )
            }
            Self::MachNoParsingContext { magic } => {
                write!(
                    fmt,
                    "Correct mach magic {:#x} does not have a matching parsing context!",
                    magic
                )
            }
            Self::MachBinaryIndexOutOfBounds { index, num_arches } => {
                write!(
                    fmt,
                    "Requested the {}-th binary, but there are only {} architectures in this container",
                    index, num_arches
                )
            }
            Self::PeMalformedCertificate { cert_size } => {
                write!(
                    fmt,
                    "Unable to extract certificate. Probably cert_size:{} is malformed",
                    cert_size
                )
            }
            Self::PeDataDirectoryCountOutOfBounds {
                count,
                num_data_directories,
            } => {
                write!(
                    fmt,
                    "data directory count ({}) is greater than maximum number of data directories ({})",
                    count, num_data_directories
                )
            }
            Self::PeInvalidImageDebugDirectoryDataSize { size_of_data } => {
                write!(
                    fmt,
                    "ImageDebugDirectory size of data seems wrong: {:?}",
                    size_of_data
                )
            }
            Self::PeImageDebugDirectoryCorrupted { idd } => {
                write!(fmt, "ImageDebugDirectory seems corrupted: {:?}", idd)
            }
            Self::PeInvalidOpInfo {
                operation_info,
                operation_code,
            } => {
                write!(
                    fmt,
                    "invalid op info ({}) for {}",
                    operation_info, operation_code
                )
            }
            Self::PeUnknownUnwindOp { op } => {
                write!(fmt, "unknown unwind op code ({})", op)
            }
            Self::PeUnsupportedUnwindVersion { version } => {
                write!(fmt, "unsupported unwind code version ({})", version)
            }
            Self::PeInvalidVirtualAddressOffset {
                name,
                virtual_address,
            } => {
                write!(
                    fmt,
                    "cannot map {} rva ({:#x}) into offset",
                    name, virtual_address
                )
            }
            Self::PeInvalidVirtualAddressOffsetFor {
                name,
                virtual_address,
                section,
            } => {
                write!(
                    fmt,
                    "cannot map {} rva ({:#x}) into offset for {}",
                    name, virtual_address, section
                )
            }
            Self::PeVirtualAddressNameNotFound {
                virtual_address,
                sections,
            } => {
                write!(
                    fmt,
                    "Cannot find name from rva {:#x} in sections: {:?}",
                    virtual_address, sections
                )
            }
            Self::PeParseFailedAt { name, offset } => {
                write!(fmt, "cannot parse {} (offset {:#x})", name, offset)
            }
            Self::PeCannotParseReexportOrdinal { num_bytes } => {
                write!(
                    fmt,
                    "Cannot parse reexport ordinal from {} bytes",
                    num_bytes
                )
            }
            Self::PeReexportMalformed { reexport } => {
                write!(fmt, "Reexport {:#} is malformed", reexport)
            }
            Self::PeCannotGetExportOrdinalRva { ordinal } => {
                write!(fmt, "cannot get RVA of export ordinal {}", ordinal)
            }
            Self::PeCannotGetExportNameEntryOridnal { export } => {
                write!(fmt, "cannot get ordinal of export name entry {}", export)
            }
            Self::PeSignatureMalformed { name, signature } => {
                write!(fmt, "{} is malformed (signature {:#x})", name, signature)
            }
            Self::PeUnsupportedMagic { magic } => {
                write!(fmt, "Unsupported header magic ({:#x})", magic)
            }
            Self::PeSectionDataMalformed { section } => {
                write!(fmt, "Section data `{}` is malformed", section)
            }
            Self::PeSectionDataPointerTooBig { section } => {
                write!(
                    fmt,
                    "Section `{}`'s pointer to raw data does not fit in platform `usize`",
                    section
                )
            }
            Self::PeInvalidIndirectSectionNameBase64 { base64_index } => {
                write!(
                    fmt,
                    "Invalid indirect section name //{}: base64 decoding failed",
                    base64_index
                )
            }
            Self::PeInvalidIndirectSectionNameInt { name, err } => {
                write!(fmt, "Invalid indirect section name /{}: {}", name, err)
            }
            Self::PeInvalidSectionNameOffset { offset } => {
                write!(fmt, "Invalid section name offset: {}", offset)
            }
            Self::PeInvlaidSymbolNameOffset { offset } => {
                write!(fmt, "Invalid Symbol name offset {:#x}", offset)
            }
            Self::General(message) => {
                write!(fmt, "{}", message)
            }
            Self::GeneralString(message) => {
                write!(fmt, "{}", message)
            }
        }
    }
}

/// An impish result
pub type Result<T> = result::Result<T, Error>;
