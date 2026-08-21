include!(concat!(env!("OUT_DIR"), "/stasis_lsm.skel.rs"));

use libbpf_rs::{OpenObject, skel::{OpenSkel, SkelBuilder}};
use std::mem::MaybeUninit;

fn main() -> anyhow::Result<()> {
    let mut open_obj = MaybeUninit::<OpenObject>::uninit();

    let _skel = StasisLsmSkelBuilder::default()
        .open(&mut open_obj)?   // Required in 0.27.0
        .load()?;

    println!("BPF program loaded!");
    // Attach if needed: skel.progs().my_lsm_prog()?.attach_lsm()?;

    loop { std::thread::sleep(std::time::Duration::from_secs(60)); }
}
