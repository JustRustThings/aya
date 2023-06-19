use aya::{include_bytes_aligned, maps::ringbuf::RingBuf, programs::UProbe, Bpf};

use super::integration_test;

#[integration_test]
fn ring_buf() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/release/ring_buf");
    let mut bpf = Bpf::load(bytes).unwrap();
    let ring_buf = bpf.take_map("RING_BUF").unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf).unwrap();

    let prog: &mut UProbe = bpf
        .program_mut("ring_buf_test")
        .unwrap()
        .try_into()
        .unwrap();
    prog.load().unwrap();
    prog.attach(
        Some("ring_buf_trigger_ebpf_program"),
        0,
        "/proc/self/exe",
        None,
    )
    .unwrap();

    // Generate some random data.
    let data: Vec<u64> = {
        let mut rng = rand::thread_rng();
        use rand::Rng as _;
        let n = rng.gen_range(1..100);
        std::iter::repeat(()).take(n).map(|_| rng.gen()).collect()
    };
    // Call the function that the uprobe is attached to with randomly generated data.
    for val in &data {
        ring_buf_trigger_ebpf_program(*val);
    }
    // Read the data back out of the ring buffer.
    let mut seen = Vec::<u64>::new();
    while seen.len() < data.len() {
        if let Some(data) = ring_buf.next() {
            let data: [u8; 8] = (*data).try_into().unwrap();
            let arg = u64::from_ne_bytes(data);
            seen.push(arg);
        }
    }
    // Ensure that the data that was read matches what was passed.
    assert!(seen == data);
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn ring_buf_trigger_ebpf_program(_arg: u64) {}
