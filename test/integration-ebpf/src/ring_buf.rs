#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
};

#[map]
static RING_BUF: RingBuf = RingBuf::with_max_entries(4096, 0);

#[uprobe]
pub fn ring_buf_test(ctx: ProbeContext) {
    // Write the first argument to the function back out to RING_BUF.
    let Some(arg): Option<u64> = ctx.arg(0) else { return };
    if let Some(mut entry) = RING_BUF.reserve::<u64>(0) {
        entry.write(arg);
        entry.submit(0)
    };
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
