#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::LpmTrie,
    macros::{btf_map, xdp},
    maps::lpm_trie::Key,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};
use xfw_common::types::{IPv4Addr, IPv6Addr};

#[btf_map]
static XFW_BLOCKED_IP4: LpmTrie<IPv4Addr, u32, 1024> = LpmTrie::new();
#[btf_map]
static XFW_BLOCKED_IP6: LpmTrie<IPv6Addr, u32, 1024> = LpmTrie::new();

#[xdp]
pub fn xfw(ctx: XdpContext) -> u32 {
    match try_xfw(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xfw(ctx: XdpContext) -> Result<u32, ()> {
    info!(ctx, "packet received");

    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };

    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => check_ip4(ctx, EthHdr::LEN),
        Ok(EtherType::Ipv6) => check_ip6(ctx, EthHdr::LEN),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn check_ip4(ctx: XdpContext, offset: usize) -> Result<u32, ()> {
    let ip4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, offset)? };

    let src_addr = unsafe { (*ip4hdr).src_addr };

    match XFW_BLOCKED_IP4.get(&Key::new(32, src_addr)) {
        Some(_) => {
            info!(ctx, "Dropped a packet from: {:i}", src_addr);
            Ok(xdp_action::XDP_DROP)
        }
        None => Ok(xdp_action::XDP_PASS),
    }
}

fn check_ip6(ctx: XdpContext, offset: usize) -> Result<u32, ()> {
    let ip4hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, offset)? };

    let src_addr = unsafe { (*ip4hdr).src_addr };

    match XFW_BLOCKED_IP6.get(&Key::new(128, src_addr)) {
        Some(_) => {
            info!(ctx, "Dropped a packet from: {:i}", src_addr);
            Ok(xdp_action::XDP_DROP)
        }
        None => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(xdp: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = xdp.data();
    let end = xdp.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
