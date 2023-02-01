use std::arch::x86_64::{__rdtscp, _mm_pause, _rdtsc};

#[inline]
pub fn cpuid() {
    unimplemented!("cpuid");
}

#[inline]
pub fn rdtsc_unsafe() -> u64 {
    unsafe { _rdtsc() }
}

#[inline]
pub fn rdtscp_unsafe() -> u64 {
    let mut aux: u32 = 0;
    unsafe { __rdtscp(&mut aux) }
}

#[inline]
pub fn pause() {
    unsafe { _mm_pause() };
}
