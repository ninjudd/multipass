//! Prototype for the session-unlock plan, § 6.5: does LocalAuthentication
//! show its Touch ID sheet for a process that has left the terminal's
//! session, as the agent will?
//!
//! This is the shape `src/touch_id.rs` takes in § 2.11: LocalAuthentication
//! loaded with `dlopen`, as `src/clipboard.rs` loads AppKit, `LAContext`
//! called through typed `objc_msgSend` pointers, and the reply delivered by
//! a global block built by hand, which hands the result to the waiting
//! thread through a channel. It is one file built with `rustc`, outside the
//! crate, so it adds nothing to multipass's build.
//!
//! ```text
//! probe can                         canEvaluatePolicy for each policy
//! probe evaluate <reason>           evaluatePolicy, attached to the terminal
//! probe noui                        evaluatePolicy with interaction not allowed,
//!                                   which fails through the reply block with
//!                                   no sheet, to test the block safely
//! probe spawn setsid|group <mode> <out> [<reason>]
//!                                   start a detached copy that runs <mode>
//!                                   (can, evaluate, or noui) and writes to <out>,
//!                                   then exit at once, as the CLI will
//! ```
//!
//! `spawn setsid` puts the child in a new session with no controlling
//! terminal, as the agent will. `spawn group` only gives it its own process
//! group, as `src/clipboard.rs` does for the clearing process, which is the
//! plan's fallback if `setsid` loses the sheet.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::io::Write;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::{Duration, Instant};

type Id = *mut c_void;
type Sel = *mut c_void;

/// `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch`, which macOS 15
/// renamed `...WithBiometricsOrCompanion` with the same value.
const POLICY_BIOMETRICS_OR_WATCH: isize = 4;
const POLICIES: [(isize, &str); 4] = [
    (1, "WithBiometrics"),
    (
        2,
        "DeviceOwnerAuthentication (falls back to the login password)",
    ),
    (3, "WithWatch (WithCompanion)"),
    (
        4,
        "WithBiometricsOrWatch (WithBiometricsOrCompanion), the plan's policy",
    ),
];
const TIMEOUT: Duration = Duration::from_secs(60);

const LOCAL_AUTHENTICATION: &CStr =
    c"/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication";
const RTLD_LAZY: c_int = 1;
const NS_UTF8_STRING_ENCODING: usize = 4;
/// `BLOCK_IS_GLOBAL` from the block ABI: the runtime never copies or frees
/// the block, which suits one that captures nothing and lives forever.
const BLOCK_IS_GLOBAL: i32 = 1 << 28;

// From libSystem, which every macOS program links.
unsafe extern "C" {
    fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
    fn dlerror() -> *mut c_char;
    fn setsid() -> c_int;
    fn getsid(pid: c_int) -> c_int;
    fn getpid() -> c_int;
    fn getppid() -> c_int;
    /// The block runtime's class for global blocks; only its address is used.
    static _NSConcreteGlobalBlock: *const c_void;
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
// different registers than the method expects. Each caller must pass a
// receiver that responds to the selector with exactly these argument and
// return types.
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

fn load() -> Result<(), String> {
    // `dlopen` takes a NUL-terminated path. `dlerror` returns null or a
    // NUL-terminated message valid until the next `dl` call on this thread,
    // so it is copied at once.
    let handle = unsafe { dlopen(LOCAL_AUTHENTICATION.as_ptr(), RTLD_LAZY) };
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
    Err(format!("could not load LocalAuthentication: {reason}"))
}

fn with_pool<T>(f: impl FnOnce() -> T) -> T {
    let pool = unsafe { objc_autoreleasePoolPush() };
    let result = f();
    unsafe { objc_autoreleasePoolPop(pool) };
    result
}

/// A new `LAContext`, owned by the caller, who must release it.
unsafe fn new_context() -> Id {
    unsafe {
        let class = objc_getClass(c"LAContext".as_ptr());
        let allocated: Id = send(class, c"alloc");
        send(allocated, c"init")
    }
}

/// An `NSString` holding `s`, owned by the caller, who must release it.
unsafe fn new_string(s: &str) -> Id {
    unsafe {
        let class = objc_getClass(c"NSString".as_ptr());
        let allocated: Id = send(class, c"alloc");
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

/// The code and description of an `NSError`, which must be null or a valid
/// `NSError` for the length of the call.
unsafe fn describe(error: Id) -> (isize, String) {
    if error.is_null() {
        return (0, String::new());
    }
    unsafe {
        let code: isize = send(error, c"code");
        let text: Id = send(error, c"localizedDescription");
        let utf8: *const c_char = if text.is_null() {
            std::ptr::null()
        } else {
            send(text, c"UTF8String")
        };
        let text = if utf8.is_null() {
            String::new()
        } else {
            CStr::from_ptr(utf8).to_string_lossy().into_owned()
        };
        (code, text)
    }
}

fn error_name(code: isize) -> &'static str {
    match code {
        0 => "",
        -1 => "LAErrorAuthenticationFailed",
        -2 => "LAErrorUserCancel",
        -3 => "LAErrorUserFallback",
        -4 => "LAErrorSystemCancel",
        -5 => "LAErrorPasscodeNotSet",
        -6 => "LAErrorBiometryNotAvailable",
        -7 => "LAErrorBiometryNotEnrolled",
        -8 => "LAErrorBiometryLockout",
        -9 => "LAErrorAppCancel",
        -10 => "LAErrorInvalidContext",
        -11 => "LAErrorWatchNotAvailable (CompanionNotAvailable)",
        -12 => "LAErrorBiometryNotPaired",
        -13 => "LAErrorBiometryDisconnected",
        -14 => "LAErrorInvalidDimensions",
        -1004 => "LAErrorNotInteractive",
        _ => "unknown",
    }
}

fn biometry_name(kind: isize) -> &'static str {
    match kind {
        0 => "none",
        1 => "Touch ID",
        2 => "Face ID",
        4 => "Optic ID",
        _ => "unknown",
    }
}

fn can() -> Result<String, String> {
    load()?;
    let mut out = String::new();
    with_pool(|| unsafe {
        let context = new_context();
        for (policy, name) in POLICIES {
            // `canEvaluatePolicy:error:` takes an `NSInteger` policy and an
            // `NSError **`, and returns a `BOOL`, one byte on both
            // architectures. The error it writes is autoreleased, so the
            // pool frees it.
            let mut error: Id = std::ptr::null_mut();
            let ok: u8 = send2(
                context,
                c"canEvaluatePolicy:error:",
                policy,
                &mut error as *mut Id,
            );
            let (code, text) = describe(error);
            if ok != 0 {
                out.push_str(&format!("can-evaluate   policy {policy} {name}: yes\n"));
            } else {
                out.push_str(&format!(
                    "can-evaluate   policy {policy} {name}: no, {code} {} ({text})\n",
                    error_name(code)
                ));
            }
        }
        // `biometryType` is set only after a `canEvaluatePolicy` call.
        let kind: isize = send(context, c"biometryType");
        out.push_str(&format!("biometry       {}\n", biometry_name(kind)));
        release(context);
    });
    Ok(out)
}

/// What `evaluatePolicy`'s reply carried: success, and the error's code and
/// description when it failed.
type Reply = (bool, isize, String);

/// Where the reply block sends its result. The block captures nothing, so
/// the one waiting request leaves its sender here.
static REPLY: Mutex<Option<mpsc::Sender<Reply>>> = Mutex::new(None);

#[repr(C)]
struct BlockDescriptor {
    reserved: usize,
    size: usize,
}

/// A block literal laid out as the block ABI defines it.
#[repr(C)]
struct Block {
    isa: *const c_void,
    flags: i32,
    reserved: i32,
    invoke: unsafe extern "C" fn(*const Block, u8, Id),
    descriptor: *const BlockDescriptor,
}

/// The reply block's body. LocalAuthentication calls it once, on a queue of
/// its own, with the block, a `BOOL`, and a null or valid `NSError`.
unsafe extern "C" fn on_reply(_block: *const Block, success: u8, error: Id) {
    let (code, text) = with_pool(|| unsafe { describe(error) });
    if let Some(sender) = REPLY.lock().unwrap().take() {
        let _ = sender.send((success != 0, code, text));
    }
}

/// The reply block, built once and never freed, as a global block must be.
fn reply_block() -> *const Block {
    static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
        reserved: 0,
        size: std::mem::size_of::<Block>(),
    };
    let block = Box::new(Block {
        isa: (&raw const _NSConcreteGlobalBlock).cast(),
        flags: BLOCK_IS_GLOBAL,
        reserved: 0,
        invoke: on_reply,
        descriptor: &DESCRIPTOR,
    });
    Box::leak(block)
}

fn evaluate(reason: &str, interactive: bool) -> Result<String, String> {
    load()?;
    let (sender, receiver) = mpsc::channel();
    *REPLY.lock().unwrap() = Some(sender);
    let started = Instant::now();
    let context = unsafe { new_context() };
    if !interactive {
        // `setInteractionNotAllowed:` takes a `BOOL`. With `YES` the evaluation
        // fails with LAErrorNotInteractive through the reply block instead of
        // showing a sheet, which tests the block without asking for a touch.
        unsafe { send1::<u8, ()>(context, c"setInteractionNotAllowed:", 1) };
    }
    with_pool(|| unsafe {
        let text = new_string(reason);
        // `evaluatePolicy:localizedReason:reply:` takes an `NSInteger`, an
        // `NSString`, which it copies, and a block it calls exactly once.
        send3::<isize, Id, *const Block, ()>(
            context,
            c"evaluatePolicy:localizedReason:reply:",
            POLICY_BIOMETRICS_OR_WATCH,
            text,
            reply_block(),
        );
        release(text);
    });
    let result = match receiver.recv_timeout(TIMEOUT) {
        Ok((true, _, _)) => format!(
            "evaluate       approved after {} ms\n",
            started.elapsed().as_millis()
        ),
        Ok((false, code, text)) => format!(
            "evaluate       refused after {} ms: {code} {} ({text})\n",
            started.elapsed().as_millis(),
            error_name(code)
        ),
        Err(_) => {
            // `invalidate` cancels the pending evaluation; the reply then
            // arrives with LAErrorAppCancel, which this waits for briefly.
            unsafe { send::<()>(context, c"invalidate") };
            let late = receiver.recv_timeout(Duration::from_secs(5));
            format!(
                "evaluate       timeout: no answer in {} s, invalidated; late reply {late:?}\n",
                TIMEOUT.as_secs()
            )
        }
    };
    unsafe { release(context) };
    Ok(result)
}

fn session_report() -> String {
    let (pid, sid, ppid) = unsafe { (getpid(), getsid(0), getppid()) };
    let tty = match std::fs::File::open("/dev/tty") {
        Ok(_) => "opens".to_string(),
        Err(e) => format!("does not open ({e})"),
    };
    let manager = std::process::Command::new("/bin/launchctl")
        .arg("managername")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|e| format!("unknown ({e})"));
    format!(
        "process        pid {pid}, session {sid}{}, parent {ppid}\n\
         tty            /dev/tty {tty}\n\
         launchd        {manager} session\n",
        if sid == pid { " (its own)" } else { "" }
    )
}

fn run(mode: &str, reason: &str) -> Result<String, String> {
    let mut out = session_report();
    out.push_str(&match mode {
        "can" => can()?,
        "evaluate" => evaluate(reason, true)?,
        "noui" => evaluate(reason, false)?,
        other => return Err(format!("unknown mode {other}")),
    });
    Ok(out)
}

fn spawn(how: &str, mode: &str, out: &str, reason: &str) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .args(["__child", how, mode, out, reason])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match how {
        // `setsid` is async-signal-safe and takes no arguments, so it may run
        // between `fork` and `exec`. It fails only for a group leader, which
        // a freshly forked child never is.
        "setsid" => unsafe {
            command.pre_exec(|| {
                if setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        },
        "group" => {
            command.process_group(0);
        }
        other => return Err(format!("unknown spawn {other}; use setsid or group")),
    }
    let child = command.spawn().map_err(|e| e.to_string())?;
    println!("spawned        pid {} ({how}), writing {out}", child.id());
    Ok(())
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let default_reason = "test the multipass session-unlock prototype";
    let result = match args.as_slice() {
        ["can"] => run("can", "").map(|s| print!("{s}")),
        ["evaluate"] => run("evaluate", default_reason).map(|s| print!("{s}")),
        ["evaluate", reason] => run("evaluate", reason).map(|s| print!("{s}")),
        ["noui"] => run("noui", default_reason).map(|s| print!("{s}")),
        ["spawn", how, mode, out] => spawn(how, mode, out, default_reason),
        ["spawn", how, mode, out, reason] => spawn(how, mode, out, reason),
        ["__child", how, mode, out, reason] => {
            // Give the parent time to exit, so the child runs orphaned, as
            // the agent will once the command that started it returns.
            // `PROBE_DELAY` seconds, when set, leave time to close the
            // terminal first.
            let delay = std::env::var("PROBE_DELAY")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .map_or(Duration::from_millis(500), Duration::from_secs);
            std::thread::sleep(delay);
            let text = match run(mode, reason) {
                Ok(s) => format!("spawn          {how}\n{s}"),
                Err(e) => format!("spawn          {how}\nerror          {e}\n"),
            };
            let written = std::fs::File::create(out)
                .and_then(|mut f| f.write_all(format!("{text}done\n").as_bytes()));
            written.map_err(|e| e.to_string())
        }
        _ => Err(
            "usage: probe can | evaluate [<reason>] | spawn setsid|group can|evaluate|noui <out> [<reason>]"
                .to_string(),
        ),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("probe: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
