//! Calls into Apple's frameworks through the Objective-C runtime, shared by
//! the modules that use a framework.
//!
//! A framework is loaded with `dlopen` only when a command needs it, so a
//! command that never uses it runs without it in the process.
//!
//! These are the unsafe building blocks, not a safe interface. `send`
//! through `send3`, `new_string`, and `release` are `unsafe`: the runtime
//! cannot check that a receiver answers a selector with the argument and
//! return types the caller names, so the caller must know that it does, and
//! must own any object it releases. `load` is `unsafe` because `dlopen`
//! runs the library's initializers, so the caller must name a system
//! framework. `class` and `with_pool` are safe. The modules that call these,
//! such as `src/clipboard.rs`, wrap them in safe interfaces.

use std::ffi::{CStr, c_char, c_int, c_void};

pub type Id = *mut c_void;
type Sel = *mut c_void;

const RTLD_LAZY: c_int = 1;
const NS_UTF8_STRING_ENCODING: usize = 4;

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

/// Loads the framework at `path` into the process, naming it as `what` in
/// the error. The handle is never closed, because a framework that defines
/// Objective-C classes cannot be unloaded.
///
/// # Safety
///
/// `dlopen` runs the library's initializers in this process, so `path` must
/// be the absolute path of a system framework under
/// `/System/Library/Frameworks`.
pub unsafe fn load(path: &CStr, what: &str) -> Result<(), String> {
    // `dlopen` takes a NUL-terminated path, and `dlerror` returns either
    // null or a NUL-terminated message, valid until the next `dl` call on
    // this thread, so it is copied at once.
    let handle = unsafe { dlopen(path.as_ptr(), RTLD_LAZY) };
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
    Err(format!("could not load {what}: {reason}"))
}

// `objc_msgSend` must be called through a pointer of the method's exact
// type, because on Apple silicon a variadic call passes arguments in
// different registers than the method expects. Each caller must pass a
// receiver that responds to `selector` with exactly these argument and
// return types.

pub unsafe fn send<R>(receiver: Id, selector: &CStr) -> R {
    let f: unsafe extern "C" fn(Id, Sel) -> R =
        unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe { f(receiver, sel_registerName(selector.as_ptr())) }
}

pub unsafe fn send1<A, R>(receiver: Id, selector: &CStr, a: A) -> R {
    let f: unsafe extern "C" fn(Id, Sel, A) -> R =
        unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe { f(receiver, sel_registerName(selector.as_ptr()), a) }
}

pub unsafe fn send2<A, B, R>(receiver: Id, selector: &CStr, a: A, b: B) -> R {
    let f: unsafe extern "C" fn(Id, Sel, A, B) -> R =
        unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe { f(receiver, sel_registerName(selector.as_ptr()), a, b) }
}

pub unsafe fn send3<A, B, C, R>(receiver: Id, selector: &CStr, a: A, b: B, c: C) -> R {
    let f: unsafe extern "C" fn(Id, Sel, A, B, C) -> R =
        unsafe { std::mem::transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe { f(receiver, sel_registerName(selector.as_ptr()), a, b, c) }
}

/// The class named `name`, or null when no loaded framework defines it.
pub fn class(name: &CStr) -> Id {
    // `objc_getClass` takes a NUL-terminated name and only looks it up.
    unsafe { objc_getClass(name.as_ptr()) }
}

/// An `NSString` holding `s`, owned by the caller, who must release it.
/// It is built from bytes and a length, so a value holding a NUL character
/// is not cut short.
pub unsafe fn new_string(s: &str) -> Id {
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

/// Releases an object the caller owns, which must not be used afterwards.
pub unsafe fn release(object: Id) {
    unsafe { send::<()>(object, c"release") }
}

/// Runs `f` inside an autorelease pool, so objects a framework hands back
/// for the caller to drop are freed before this returns.
pub fn with_pool<T>(f: impl FnOnce() -> T) -> T {
    // The pool is pushed and popped on this thread, in order, as the
    // runtime requires.
    let pool = unsafe { objc_autoreleasePoolPush() };
    let result = f();
    unsafe { objc_autoreleasePoolPop(pool) };
    result
}

/// `BLOCK_IS_GLOBAL` from the block ABI: the runtime never copies or frees
/// the block, which suits one that captures nothing and lives forever.
const BLOCK_IS_GLOBAL: i32 = 1 << 28;

unsafe extern "C" {
    /// The block runtime's class for global blocks; only its address is used.
    static _NSConcreteGlobalBlock: *const c_void;
}

#[repr(C)]
struct BlockDescriptor {
    reserved: usize,
    size: usize,
}

/// A block literal laid out as the block ABI defines it, for a block that
/// takes a `BOOL` and an `NSError *`, as completion handlers often do.
#[repr(C)]
pub struct Block {
    isa: *const c_void,
    flags: i32,
    reserved: i32,
    pub(crate) invoke: unsafe extern "C" fn(*const Block, u8, Id),
    descriptor: *const BlockDescriptor,
}

/// A global block that calls `invoke`, leaked so it outlives every call to
/// it, as a global block must. It captures nothing, so `invoke` finds its
/// state elsewhere, such as in a static.
pub fn global_block(invoke: unsafe extern "C" fn(*const Block, u8, Id)) -> *const Block {
    static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
        reserved: 0,
        size: std::mem::size_of::<Block>(),
    };
    Box::leak(Box::new(Block {
        isa: (&raw const _NSConcreteGlobalBlock).cast(),
        flags: BLOCK_IS_GLOBAL,
        reserved: 0,
        invoke,
        descriptor: &DESCRIPTOR,
    }))
}

/// The code of an `NSError`, or 0 for null. `error` must be null or a valid
/// `NSError` for the length of the call.
pub unsafe fn error_code(error: Id) -> isize {
    if error.is_null() {
        return 0;
    }
    unsafe { send(error, c"code") }
}
