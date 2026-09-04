pub mod skeleton {
    include!("stasis_lsm.skel.rs");
}

use plain::Plain;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FOpenSample {
    pub flags: u32,
    pub path: [u8; 256],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PExecsample {
    pub path: [u8; 256],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SampleData {
    pub fopen_data: FOpenSample,
    pub pexec_data: PExecsample,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventSample {
    pub pid: u32,
    pub event_type: u32,
    pub timestamp: u64,
    pub comm: [u8; 16],
    pub data: SampleData,
}

unsafe impl Plain for FOpenSample {}
unsafe impl Plain for PExecsample {}
unsafe impl Plain for SampleData {}
unsafe impl Plain for EventSample {}

impl EventSample {
    /// Safe helper to extract the path string based on the event type
    pub fn path_str(&self) -> &str {
        let path_bytes = unsafe {
            match self.event_type {
                0 => &self.data.fopen_data.path[..], // EVENT_FILE_OPEN
                1 => &self.data.pexec_data.path[..], // EVENT_PROCESS_EXEC
                _ => &[],
            }
        };

        if path_bytes.is_empty() {
            return "";
        }

        let len = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_bytes.len());
        std::str::from_utf8(&path_bytes[..len]).unwrap_or("<invalid UTF-8>")
    }

    /// Safe helper to extract the executable name
    pub fn comm_str(&self) -> &str {
        let len = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        std::str::from_utf8(&self.comm[..len]).unwrap_or("<invalid UTF-8>")
    }
}
