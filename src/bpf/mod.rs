pub mod skeleton {
    include!("stasis_lsm.skel.rs");
}

use plain::Plain;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileOpenSample {
    pub pid: u32,
    pub flags: u32,
    pub timestamp: u64,
    pub path: [u8; 256],
}

unsafe impl Plain for FileOpenSample {}

impl FileOpenSample {
    /// helper to convert raw C-string path to safe Rust string
    pub fn path_str(&self) -> &str {
        let len = self
            .path
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.path.len());
        std::str::from_utf8(&self.path[..len]).unwrap_or("<invalid UTF-8>")
    }
}
