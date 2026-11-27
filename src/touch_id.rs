//! Approval with Touch ID or an Apple Watch, through LocalAuthentication.
//!
//! The session agent asks here before it answers each request. The policy
//! is `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch`: a finger on
//! the sensor or a press on a paired watch, never the login password, which
//! a program that captured it could type. LocalAuthentication ships with
//! macOS and is loaded with `dlopen` only when an agent starts, so no other
//! command has it in its process. It needs no entitlement, so it works from
//! an unsigned command-line program.

use crate::objc::{self, Block, Id, release, send, send2, send3, with_pool};
use std::ffi::CStr;
use std::sync::{Mutex, OnceLock, mpsc};
use std::time::Duration;

/// `LAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch`, which macOS 15
/// renamed `...WithBiometricsOrCompanion` with the same value.
const POLICY: isize = 4;

const LOCAL_AUTHENTICATION: &CStr =
    c"/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication";

/// The `LAError` codes that mean nobody can approve right now, rather than
/// that someone declined: no biometry or it is locked out, not enrolled,
/// not paired or disconnected, or no watch in reach.
const UNAVAILABLE: [isize; 6] = [-6, -7, -8, -11, -12, -13];

/// How a request for approval ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    Approved,
    /// Cancelled, failed, or not answered in time.
    Denied,
    /// Neither Touch ID nor a watch can approve at the moment.
    Unavailable,
}

/// Touch ID or an Apple Watch on this Mac.
pub struct TouchId;

fn load() -> Result<(), String> {
    static LOADED: OnceLock<Result<(), String>> = OnceLock::new();
    LOADED
        .get_or_init(|| objc::load(LOCAL_AUTHENTICATION, "LocalAuthentication"))
        .clone()
}

/// A new `LAContext`, owned by the caller, who must release it. `load` must
/// have succeeded, so the class exists.
unsafe fn new_context() -> Id {
    unsafe {
        let allocated: Id = send(objc::class(c"LAContext"), c"alloc");
        send(allocated, c"init")
    }
}

/// Where the reply block sends its result. The block captures nothing, so
/// the one waiting request leaves its sender here, and `ONE_AT_A_TIME`
/// keeps a second request from replacing it.
static REPLY: Mutex<Option<mpsc::Sender<(bool, isize)>>> = Mutex::new(None);
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// The reply block's body. LocalAuthentication calls it once, on a queue of
/// its own, with the block, a `BOOL`, and a null or valid `NSError`.
unsafe extern "C" fn on_reply(_block: *const Block, success: u8, error: Id) {
    let code = unsafe { objc::error_code(error) };
    let sender = REPLY.lock().unwrap_or_else(|p| p.into_inner()).take();
    if let Some(sender) = sender {
        let _ = sender.send((success != 0, code));
    }
}

impl TouchId {
    /// True when Touch ID or a watch can approve requests on this Mac.
    pub fn available() -> bool {
        if load().is_err() {
            return false;
        }
        with_pool(|| unsafe {
            let context = new_context();
            // `canEvaluatePolicy:error:` takes an `NSInteger` and an
            // `NSError **`, which may be null, and returns a one-byte `BOOL`.
            let ok: u8 = send2(
                context,
                c"canEvaluatePolicy:error:",
                POLICY,
                std::ptr::null_mut::<Id>(),
            );
            release(context);
            ok != 0
        })
    }

    /// Shows the sheet "multipass is trying to <reason>" and waits up to
    /// `timeout` for a touch.
    pub fn approve(reason: &str, timeout: Duration) -> Approval {
        if load().is_err() {
            return Approval::Unavailable;
        }
        let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
        let (sender, receiver) = mpsc::channel();
        *REPLY.lock().unwrap_or_else(|p| p.into_inner()) = Some(sender);
        let context = unsafe { new_context() };
        with_pool(|| unsafe {
            let text = objc::new_string(reason);
            // `evaluatePolicy:localizedReason:reply:` takes an `NSInteger`,
            // an `NSString`, which it copies, and a block it calls once.
            send3::<isize, Id, *const Block, ()>(
                context,
                c"evaluatePolicy:localizedReason:reply:",
                POLICY,
                text,
                objc::global_block(on_reply),
            );
            release(text);
        });
        let approval = match receiver.recv_timeout(timeout) {
            Ok((true, _)) => Approval::Approved,
            Ok((false, code)) if UNAVAILABLE.contains(&code) => Approval::Unavailable,
            Ok((false, _)) => Approval::Denied,
            Err(_) => {
                // The late reply, with `LAErrorAppCancel` once `invalidate`
                // below takes the sheet down, finds no sender and is dropped.
                REPLY.lock().unwrap_or_else(|p| p.into_inner()).take();
                Approval::Denied
            }
        };
        // `invalidate` takes nothing and ends any evaluation still showing.
        // The context is ours from `new_context`, so it is then released.
        unsafe {
            send::<()>(context, c"invalidate");
            release(context);
        }
        approval
    }
}
