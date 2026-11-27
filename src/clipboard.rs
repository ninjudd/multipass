//! Copying a secret to the macOS clipboard, and clearing it later.
//!
//! multipass writes through AppKit's `NSPasteboard` instead of `pbcopy`, for
//! two markings `pbcopy` cannot make. The contents are current-host-only, so
//! Universal Clipboard does not send them to your other Apple devices, and
//! they carry `org.nspasteboard.ConcealedType`, which clipboard-history apps
//! that follow nspasteboard.org's conventions skip. Clearing compares the
//! clipboard's change count rather than its contents, so the secret never
//! has to stay in memory to decide whether it is still there.
//!
//! AppKit ships with macOS, so it counts like the standard library under the
//! no-dependencies rule. The binary does not link it: this module loads it
//! with `dlopen` the first time a command touches the clipboard, so every
//! other command runs without AppKit in the process. This module holds the
//! program's only `unsafe` code.

use std::time::Duration;

/// How long a copied secret stays on the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

/// The hidden command the clearing process runs, kept out of `--help`.
pub const CLEAR_COMMAND: &str = "__clear-clipboard";

/// Copies `value` and starts a process that clears it after `CLEAR_AFTER`,
/// unless something else is copied first.
pub fn copy(value: &str) -> Result<(), String> {
    let pasteboard = macos::Pasteboard::general()?;
    let change_count = pasteboard.write_secret(value)?;
    if let Err(e) = spawn_clearer(change_count) {
        pasteboard.clear();
        return Err(format!(
            "could not schedule clearing the clipboard, so it was cleared now: {e}"
        ));
    }
    Ok(())
}

/// Runs in the clearing process: waits, then clears the clipboard if its
/// change count is still `change_count`.
pub fn clear_later(change_count: &str) -> Result<(), String> {
    let change_count: isize = change_count
        .parse()
        .map_err(|_| "the clipboard change count must be a number")?;
    std::thread::sleep(CLEAR_AFTER);
    let pasteboard = macos::Pasteboard::general()?;
    clear_if_unchanged(&pasteboard, change_count);
    Ok(())
}

/// Clears the clipboard only when nothing has been copied since the secret,
/// so a later copy of your own is never wiped. Returns whether it cleared.
fn clear_if_unchanged(pasteboard: &macos::Pasteboard, change_count: isize) -> bool {
    let unchanged = pasteboard.change_count() == change_count;
    if unchanged {
        pasteboard.clear();
    }
    unchanged
}

/// Starts this same program as a detached process that runs `clear_later`.
/// Its own process group keeps closing the terminal from stopping it early.
fn spawn_clearer(change_count: isize) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    Command::new(std::env::current_exe()?)
        .args([CLEAR_COMMAND, &change_count.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map(drop)
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CStr, c_char, c_int, c_void};
    use std::sync::OnceLock;

    type Id = *mut c_void;
    type Sel = *mut c_void;

    /// `NSPasteboardContentsCurrentHostOnly`, which keeps Universal Clipboard
    /// from sending the contents to other devices.
    const CURRENT_HOST_ONLY: usize = 1;
    const NS_UTF8_STRING_ENCODING: usize = 4;
    const PLAIN_TEXT: &str = "public.utf8-plain-text";
    const CONCEALED: &str = "org.nspasteboard.ConcealedType";

    const APPKIT: &CStr = c"/System/Library/Frameworks/AppKit.framework/AppKit";
    const RTLD_LAZY: c_int = 1;

    // From libSystem, which every macOS program links.
    unsafe extern "C" {
        fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
        fn dlerror() -> *mut c_char;
    }

    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Sel;
        fn objc_msgSend();
        fn objc_autoreleasePoolPush() -> *mut c_void;
        fn objc_autoreleasePoolPop(pool: *mut c_void);
    }

    // `objc_msgSend` must be called through a pointer of the method's exact
    // type, because on Apple silicon a variadic call passes arguments in
    // different registers than the method expects.
    unsafe fn send<R>(receiver: Id, selector: &CStr) -> R {
        let f: unsafe extern "C" fn(Id, Sel) -> R =
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        unsafe { f(receiver, sel_registerName(selector.as_ptr())) }
    }

    unsafe fn send1<A, R>(receiver: Id, selector: &CStr, a: A) -> R {
        let f: unsafe extern "C" fn(Id, Sel, A) -> R =
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        unsafe { f(receiver, sel_registerName(selector.as_ptr()), a) }
    }

    unsafe fn send2<A, B, R>(receiver: Id, selector: &CStr, a: A, b: B) -> R {
        let f: unsafe extern "C" fn(Id, Sel, A, B) -> R =
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        unsafe { f(receiver, sel_registerName(selector.as_ptr()), a, b) }
    }

    unsafe fn send3<A, B, C, R>(receiver: Id, selector: &CStr, a: A, b: B, c: C) -> R {
        let f: unsafe extern "C" fn(Id, Sel, A, B, C) -> R =
            unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
        unsafe { f(receiver, sel_registerName(selector.as_ptr()), a, b, c) }
    }

    /// Loads AppKit into the process once, so that `NSPasteboard` exists.
    /// The handle is never closed: AppKit cannot be unloaded once loaded.
    fn load_appkit() -> Result<(), String> {
        static LOADED: OnceLock<Result<(), String>> = OnceLock::new();
        LOADED
            .get_or_init(|| {
                // `dlopen` takes a NUL-terminated path, and `dlerror` returns
                // either null or a NUL-terminated message, valid until the
                // next `dl` call on this thread, so it is copied at once.
                let handle = unsafe { dlopen(APPKIT.as_ptr(), RTLD_LAZY) };
                if !handle.is_null() {
                    return Ok(());
                }
                let reason = unsafe {
                    let message = dlerror();
                    if message.is_null() {
                        "unknown error".to_string()
                    } else {
                        CStr::from_ptr(message).to_string_lossy().into_owned()
                    }
                };
                Err(format!("could not load AppKit for the clipboard: {reason}"))
            })
            .clone()
    }

    fn class(name: &CStr) -> Id {
        unsafe { objc_getClass(name.as_ptr()) }
    }

    /// An `NSString` holding `s`, owned by the caller, who must release it.
    /// It is built from bytes and a length, so a value holding a NUL
    /// character is not cut short.
    unsafe fn new_string(s: &str) -> Id {
        unsafe {
            let allocated: Id = send(class(c"NSString"), c"alloc");
            send3(
                allocated,
                c"initWithBytes:length:encoding:",
                s.as_ptr().cast::<c_void>(),
                s.len(),
                NS_UTF8_STRING_ENCODING,
            )
        }
    }

    unsafe fn release(object: Id) {
        unsafe { send::<()>(object, c"release") }
    }

    /// Runs `f` inside an autorelease pool, so objects AppKit hands back for
    /// the caller to drop are freed before this returns.
    fn with_pool<T>(f: impl FnOnce() -> T) -> T {
        let pool = unsafe { objc_autoreleasePoolPush() };
        let result = f();
        unsafe { objc_autoreleasePoolPop(pool) };
        result
    }

    pub struct Pasteboard {
        handle: Id,
        #[cfg(test)]
        private: bool,
    }

    impl Pasteboard {
        pub fn general() -> Result<Self, String> {
            load_appkit()?;
            let handle: Id =
                with_pool(|| unsafe { send(class(c"NSPasteboard"), c"generalPasteboard") });
            if handle.is_null() {
                return Err("the clipboard is not available".into());
            }
            Ok(Self {
                handle,
                #[cfg(test)]
                private: false,
            })
        }

        /// A new pasteboard that no other program reads, for tests.
        #[cfg(test)]
        pub fn private() -> Self {
            load_appkit().unwrap();
            let handle: Id = unsafe {
                let made: Id = send(class(c"NSPasteboard"), c"pasteboardWithUniqueName");
                send(made, c"retain")
            };
            assert!(!handle.is_null(), "could not create a private pasteboard");
            Self {
                handle,
                private: true,
            }
        }

        /// Replaces the contents with `value`, marked current-host-only and
        /// concealed, and returns the resulting change count.
        pub fn write_secret(&self, value: &str) -> Result<isize, String> {
            with_pool(|| unsafe {
                let _: isize = send1(
                    self.handle,
                    c"prepareForNewContentsWithOptions:",
                    CURRENT_HOST_ONLY,
                );
                let strings = [
                    new_string(value),
                    new_string(PLAIN_TEXT),
                    new_string(""),
                    new_string(CONCEALED),
                ];
                let wrote_text: i8 =
                    send2(self.handle, c"setString:forType:", strings[0], strings[1]);
                let wrote_mark: i8 =
                    send2(self.handle, c"setString:forType:", strings[2], strings[3]);
                for string in strings {
                    release(string);
                }
                if wrote_text == 0 || wrote_mark == 0 {
                    let _: isize = send(self.handle, c"clearContents");
                    return Err("could not write to the clipboard".to_string());
                }
                Ok(send(self.handle, c"changeCount"))
            })
        }

        pub fn change_count(&self) -> isize {
            unsafe { send(self.handle, c"changeCount") }
        }

        pub fn clear(&self) {
            let _: isize = unsafe { send(self.handle, c"clearContents") };
        }

        #[cfg(test)]
        pub fn text(&self) -> Option<String> {
            with_pool(|| unsafe {
                let kind = new_string(PLAIN_TEXT);
                let found: Id = send1(self.handle, c"stringForType:", kind);
                release(kind);
                if found.is_null() {
                    return None;
                }
                let bytes: *const c_char = send(found, c"UTF8String");
                Some(CStr::from_ptr(bytes).to_string_lossy().into_owned())
            })
        }

        #[cfg(test)]
        pub fn types(&self) -> Vec<String> {
            with_pool(|| unsafe {
                let types: Id = send(self.handle, c"types");
                if types.is_null() {
                    return Vec::new();
                }
                let count: usize = send(types, c"count");
                (0..count)
                    .map(|i| {
                        let kind: Id = send1(types, c"objectAtIndex:", i);
                        let bytes: *const c_char = send(kind, c"UTF8String");
                        CStr::from_ptr(bytes).to_string_lossy().into_owned()
                    })
                    .collect()
            })
        }
    }

    #[cfg(test)]
    impl Drop for Pasteboard {
        fn drop(&mut self) {
            if self.private {
                unsafe {
                    send::<()>(self.handle, c"releaseGlobally");
                    release(self.handle);
                }
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod macos {
    pub struct Pasteboard;

    impl Pasteboard {
        pub fn general() -> Result<Self, String> {
            Err("--clip works only on macOS".into())
        }

        pub fn write_secret(&self, _value: &str) -> Result<isize, String> {
            unreachable!("general() never returns a pasteboard off macOS")
        }

        pub fn change_count(&self) -> isize {
            unreachable!("general() never returns a pasteboard off macOS")
        }

        pub fn clear(&self) {
            unreachable!("general() never returns a pasteboard off macOS")
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::macos::Pasteboard;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// The program touches the pasteboard from one thread only, but the test
    /// harness runs tests on several, and Apple does not document AppKit's
    /// pasteboard calls as safe to make from several threads at once. So each
    /// test holds this lock while it uses a pasteboard.
    fn one_at_a_time() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn writes_the_secret_marked_concealed() {
        let _turn = one_at_a_time();
        let pasteboard = Pasteboard::private();
        pasteboard.write_secret("hunter2 ✓").unwrap();
        assert_eq!(pasteboard.text().as_deref(), Some("hunter2 ✓"));
        let types = pasteboard.types();
        assert!(
            types.iter().any(|t| t == "org.nspasteboard.ConcealedType"),
            "{types:?}"
        );
    }

    #[test]
    fn clears_the_secret_when_nothing_else_was_copied() {
        let _turn = one_at_a_time();
        let pasteboard = Pasteboard::private();
        let count = pasteboard.write_secret("hunter2").unwrap();
        assert!(clear_if_unchanged(&pasteboard, count));
        assert_eq!(pasteboard.text(), None);
    }

    #[test]
    fn keeps_a_later_copy_of_your_own() {
        let _turn = one_at_a_time();
        let pasteboard = Pasteboard::private();
        let count = pasteboard.write_secret("hunter2").unwrap();
        pasteboard.write_secret("copied afterwards").unwrap();
        assert!(!clear_if_unchanged(&pasteboard, count));
        assert_eq!(pasteboard.text().as_deref(), Some("copied afterwards"));
    }
}
