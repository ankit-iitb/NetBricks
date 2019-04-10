use super::EndOffset;
use super::HeaderKind;

use std::fmt;

#[derive(Debug, Default)]
#[repr(C, packed)]
pub struct NullHeader;

impl fmt::Display for NullHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "null")
    }
}

impl EndOffset for NullHeader {
    #[inline]
    fn offset(&self) -> usize {
        0
    }
    #[inline]
    fn size() -> usize {
        0
    }
    #[inline]
    fn payload_size(&self, hint: usize) -> usize {
        hint
    }
    #[inline]
    fn header_kind(&self) -> HeaderKind {
        HeaderKind::Null
    }
}
