mod bpf {
    include!(concat!(env!("OUT_DIR"), "/stasis_lsm.skel.rs"));
}

use bpf::*;

use libbpf_rs::{
    OpenObject,
    skel::{OpenSkel, SkelBuilder, Skel},
};
use std::mem::MaybeUninit;

fn main() -> anyhow::Result<()> {

    let skel_builder = StasisLsmSkelBuilder::default();

    let mut open_obj = MaybeUninit::<OpenObject>::uninit();

    let open_skel = skel_builder.open(&mut open_obj)?;

    let mut skel = open_skel.load()?;

    let rb_map = &skel.maps.my_ringbuf;

    let mut rb_builder = libbpf_rs::RingBufferBuilder::new();

    // rb_builder.add(ringbuf_map, |data| {
    //     println!("Received data: {}", data);
    //     0
    // });

    skel.attach()?;

    println!("BPF program loaded!");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
