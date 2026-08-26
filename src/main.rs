mod bpf {
    include!("bpf/stasis_lsm.skel.rs");
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

    skel.attach()?;

    let rb_map = &skel.maps.pid_ringbuf;

    let mut rb_builder = libbpf_rs::RingBufferBuilder::new();
    rb_builder.add(rb_map, |data| {
        println!("Received data length: {}", data.len());
        0
    })?;
    let ringbuf = rb_builder.build()?;

    loop {
        ringbuf.poll(std::time::Duration::from_millis(100))?;
    }
}
