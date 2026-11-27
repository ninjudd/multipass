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

/// How long a request that timed out waits for the reply `invalidate`
/// sends, so that reply cannot reach a later request.
const LATE_REPLY_WAIT: Duration = Duration::from_secs(5);

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
    /// `timeout` for a touch. `Unavailable` comes only from asking, before
    /// any sheet shows, whether Touch ID or a watch can approve. Once a sheet
    /// has shown, anything but a touch is `Denied`, whatever error code
    /// LocalAuthentication gives, because a person may have cancelled it,
    /// and a cancel must never fall back to the passphrase prompt.
    pub fn approve(reason: &str, timeout: Duration) -> Approval {
        if load().is_err() {
            return Approval::Unavailable;
        }
        let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
        let context = unsafe { new_context() };
        // `canEvaluatePolicy:error:` takes an `NSInteger` and an `NSError **`,
        // which may be null, and returns a one-byte `BOOL`.
        let can: u8 = with_pool(|| unsafe {
            send2(
                context,
                c"canEvaluatePolicy:error:",
                POLICY,
                std::ptr::null_mut::<Id>(),
            )
        });
        let approval = if can == 0 {
            Approval::Unavailable
        } else {
            let (sender, receiver) = mpsc::channel();
            *REPLY.lock().unwrap_or_else(|p| p.into_inner()) = Some(sender);
            with_pool(|| unsafe {
                let text = objc::new_string(reason);
                // `evaluatePolicy:localizedReason:reply:` takes an
                // `NSInteger`, an `NSString`, which it copies, and a block it
                // calls once.
                send3::<isize, Id, *const Block, ()>(
                    context,
                    c"evaluatePolicy:localizedReason:reply:",
                    POLICY,
                    text,
                    objc::global_block(on_reply),
                );
                release(text);
            });
            let reply = receiver.recv_timeout(timeout).ok();
            if reply.is_none() {
                // `invalidate` takes nothing and takes the sheet down. Its
                // reply is drained here, while this request still holds the
                // slot, so it can never answer a later request.
                unsafe { send::<()>(context, c"invalidate") };
                let _ = receiver.recv_timeout(LATE_REPLY_WAIT);
            }
            REPLY.lock().unwrap_or_else(|p| p.into_inner()).take();
            after_sheet(reply)
        };
        // The context is ours from `new_context`: `invalidate` ends anything
        // it still shows, and then it is released.
        unsafe {
            send::<()>(context, c"invalidate");
            release(context);
        }
        approval
    }
}

/// How a request ends once its sheet has shown: approved only when the reply
/// says it succeeded, and denied for every failure and for no reply at all.
fn after_sheet(reply: Option<(bool, isize)>) -> Approval {
    match reply {
        Some((true, _)) => Approval::Approved,
        _ => Approval::Denied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cancel (-2), a system cancel (-4), an app cancel (-9), no companion
    /// device (-11), and a lockout (-8) all come after a sheet may have
    /// shown, so none of them may approve or fall back to the passphrase.
    #[test]
    fn only_a_touch_approves_once_a_sheet_has_shown() {
        assert_eq!(after_sheet(Some((true, 0))), Approval::Approved);
        for code in [-1, -2, -3, -4, -6, -7, -8, -9, -11, -12, -13, -1004] {
            assert_eq!(after_sheet(Some((false, code))), Approval::Denied, "{code}");
        }
        assert_eq!(after_sheet(None), Approval::Denied);
    }
}
