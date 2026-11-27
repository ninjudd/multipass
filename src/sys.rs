//! System calls the session agent needs that the standard library does not
//! offer, behind safe wrappers: who is on the other end of a Unix socket,
//! leaving the terminal's session, and keeping the vault key out of
//! debuggers, core files, and swap.
//!
//! Every call is in libSystem, which every macOS program links. Elsewhere
//! no agent starts, so the calls that only an agent makes fail.

#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(not(target_os = "macos"))]
pub use other::*;

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{OsString, c_char, c_int, c_void};
    use std::io;
    use std::os::fd::RawFd;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    /// `SOL_LOCAL` and `LOCAL_PEERPID` from `<sys/un.h>`: the process ID of a
    /// Unix socket's peer, as it was when the connection was made.
    const SOL_LOCAL: c_int = 0;
    const LOCAL_PEERPID: c_int = 2;
    /// `PT_DENY_ATTACH` from `<sys/ptrace.h>`.
    const PT_DENY_ATTACH: c_int = 31;
    /// `RLIMIT_CORE` from `<sys/resource.h>`.
    const RLIMIT_CORE: c_int = 4;
    /// `PROC_PIDPATHINFO_MAXSIZE` from `<sys/proc_info.h>`.
    const PID_PATH_MAX: usize = 4 * 1024;

    #[repr(C)]
    struct Rlimit {
        current: u64,
        max: u64,
    }

    unsafe extern "C" {
        fn getuid() -> u32;
        fn getpeereid(fd: c_int, uid: *mut u32, gid: *mut u32) -> c_int;
        fn getsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            value: *mut c_void,
            len: *mut u32,
        ) -> c_int;
        fn proc_pidpath(pid: c_int, buffer: *mut c_char, size: u32) -> c_int;
        fn setsid() -> c_int;
        fn ptrace(request: c_int, pid: c_int, addr: *mut c_char, data: c_int) -> c_int;
        fn setrlimit(resource: c_int, limit: *const Rlimit) -> c_int;
        fn mlock(addr: *const c_void, len: usize) -> c_int;
    }

    /// Turns a C return value of -1 into the error `errno` holds.
    fn check(result: c_int) -> io::Result<c_int> {
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    /// The user ID this process runs as.
    pub fn uid() -> u32 {
        // `getuid` takes nothing and cannot fail.
        unsafe { getuid() }
    }

    /// The user ID of the process on the other end of the Unix socket `fd`.
    pub fn peer_uid(fd: RawFd) -> io::Result<u32> {
        let (mut uid, mut gid) = (0u32, 0u32);
        // `getpeereid` writes two `uid_t`s, both `u32` on macOS, through valid
        // pointers, and fails cleanly when `fd` is not a connected socket.
        check(unsafe { getpeereid(fd, &mut uid, &mut gid) })?;
        Ok(uid)
    }

    /// The process ID of the process on the other end of the Unix socket `fd`.
    pub fn peer_pid(fd: RawFd) -> io::Result<i32> {
        let mut pid: c_int = 0;
        let mut len = std::mem::size_of::<c_int>() as u32;
        // `LOCAL_PEERPID` writes a `pid_t`, an `i32`, into the buffer of the
        // length given, and sets `len` to what it wrote.
        check(unsafe {
            getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERPID,
                (&mut pid as *mut c_int).cast(),
                &mut len,
            )
        })?;
        Ok(pid)
    }

    /// The path of the executable that process `pid` runs.
    pub fn pid_path(pid: i32) -> io::Result<PathBuf> {
        let mut buffer = vec![0u8; PID_PATH_MAX];
        // `proc_pidpath` writes at most `size` bytes and returns how many, or 0
        // with `errno` set when the process is gone or not ours to inspect.
        let written = unsafe { proc_pidpath(pid, buffer.as_mut_ptr().cast(), PID_PATH_MAX as u32) };
        if written <= 0 {
            return Err(io::Error::last_os_error());
        }
        buffer.truncate(written as usize);
        Ok(PathBuf::from(OsString::from_vec(buffer)))
    }

    /// Makes this process the leader of a new session with no controlling
    /// terminal, so closing the terminal that started it does not end it.
    pub fn new_session() -> io::Result<()> {
        // `setsid` takes nothing; it fails only for a process group leader.
        check(unsafe { setsid() }).map(drop)
    }

    /// Refuses debuggers for the rest of this process's life.
    pub fn deny_debuggers() -> io::Result<()> {
        // `PT_DENY_ATTACH` ignores the other arguments.
        check(unsafe { ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) }).map(drop)
    }

    /// Makes a crash leave no core file.
    pub fn no_core_files() -> io::Result<()> {
        let limit = Rlimit { current: 0, max: 0 };
        // `setrlimit` reads one `struct rlimit`, two `rlim_t`s of 64 bits.
        check(unsafe { setrlimit(RLIMIT_CORE, &limit) }).map(drop)
    }

    /// Keeps the pages holding `bytes` out of swap.
    pub fn lock_in_memory(bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        // `mlock` only pins the pages that hold the range; it reads nothing.
        check(unsafe { mlock(bytes.as_ptr().cast(), bytes.len()) }).map(drop)
    }
}

#[cfg(not(target_os = "macos"))]
mod other {
    use std::io;
    use std::os::fd::RawFd;
    use std::path::PathBuf;

    unsafe extern "C" {
        fn getuid() -> u32;
    }

    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "session unlock works only on macOS",
        ))
    }

    pub fn uid() -> u32 {
        // `getuid` takes nothing and cannot fail.
        unsafe { getuid() }
    }

    pub fn peer_uid(_fd: RawFd) -> io::Result<u32> {
        unsupported()
    }

    pub fn peer_pid(_fd: RawFd) -> io::Result<i32> {
        unsupported()
    }

    pub fn pid_path(_pid: i32) -> io::Result<PathBuf> {
        unsupported()
    }

    pub fn new_session() -> io::Result<()> {
        unsupported()
    }

    pub fn deny_debuggers() -> io::Result<()> {
        unsupported()
    }

    pub fn no_core_files() -> io::Result<()> {
        unsupported()
    }

    pub fn lock_in_memory(_bytes: &[u8]) -> io::Result<()> {
        Ok(())
    }
}

/// Overwrites `buffer` with zeros, in a way the compiler may not remove as
/// a dead store.
pub fn wipe(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        // A volatile write through a valid `&mut u8`.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Overwrites a string's bytes with zeros and empties it. Zero bytes are
/// valid UTF-8, so the string stays valid while it is wiped.
pub fn wipe_string(s: &mut String) {
    // Writing zeros keeps every byte a valid UTF-8 code unit.
    wipe(unsafe { s.as_bytes_mut() });
    s.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_leaves_only_zeros() {
        let mut buffer = *b"hunter2 and more";
        wipe(&mut buffer);
        assert_eq!(buffer, [0u8; 16]);

        let mut text = String::from("correct horse");
        let capacity = text.capacity();
        let start = text.as_ptr();
        wipe_string(&mut text);
        assert!(text.is_empty());
        // The buffer the text lived in now reads as zeros.
        let left = unsafe { std::slice::from_raw_parts(start, capacity.min(13)) };
        assert_eq!(left, [0u8; 13]);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn a_socket_pair_names_this_process_and_user() {
        use std::os::fd::AsRawFd;
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(peer_uid(a.as_raw_fd()).unwrap(), uid());
        let pid = peer_pid(a.as_raw_fd()).unwrap();
        assert_eq!(pid as u32, std::process::id());
        assert_eq!(
            pid_path(pid).unwrap().canonicalize().unwrap(),
            std::env::current_exe().unwrap().canonicalize().unwrap()
        );
    }
}
