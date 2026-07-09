//! Service-scan runtime options passed explicitly into workers.
use std::cell::RefCell;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedisRuntimeOptions {
    pub redis_file: Option<PathBuf>,
    pub redis_shell: Option<String>,
    pub disable_redis: bool,
    pub redis_write_path: Option<String>,
    pub redis_write_content: Option<String>,
    pub redis_write_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthRuntimeOptions {
    pub domain: Option<String>,
    pub hashes: Vec<String>,
    pub disable_brute: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ms17010RuntimeOptions {
    pub shellcode: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionRuntimeOptions {
    pub max_retries: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceScanRuntimeOptions {
    pub module_threads: u16,
    pub global_timeout_secs: u64,
    pub log_errors: bool,
}

impl Default for ServiceScanRuntimeOptions {
    fn default() -> Self {
        Self {
            module_threads: 10,
            global_timeout_secs: 180,
            log_errors: false,
        }
    }
}

/// Explicit runtime options passed into service-scan workers (no post-spawn
/// thread-local side effects required at the orchestration boundary).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceRuntimeBundle {
    pub auth: AuthRuntimeOptions,
    pub redis: RedisRuntimeOptions,
    pub ms17010: Ms17010RuntimeOptions,
    pub connection: ConnectionRuntimeOptions,
    pub service: ServiceScanRuntimeOptions,
}

pub fn set_redis_runtime_options(options: RedisRuntimeOptions) {
    REDIS_RUNTIME_OPTIONS.with(|current| *current.borrow_mut() = options);
}

pub fn set_auth_runtime_options(options: AuthRuntimeOptions) {
    AUTH_RUNTIME_OPTIONS.with(|current| *current.borrow_mut() = options);
}

pub fn set_ms17010_runtime_options(options: Ms17010RuntimeOptions) {
    MS17010_RUNTIME_OPTIONS.with(|current| *current.borrow_mut() = options);
}

pub fn set_connection_runtime_options(options: ConnectionRuntimeOptions) {
    CONNECTION_RUNTIME_OPTIONS.with(|current| *current.borrow_mut() = options);
}

pub fn set_service_scan_runtime_options(options: ServiceScanRuntimeOptions) {
    SERVICE_SCAN_RUNTIME_OPTIONS.with(|current| *current.borrow_mut() = options);
}

pub(crate) fn current_redis_runtime_options() -> RedisRuntimeOptions {
    REDIS_RUNTIME_OPTIONS.with(|options| options.borrow().clone())
}

pub(crate) fn current_auth_runtime_options() -> AuthRuntimeOptions {
    AUTH_RUNTIME_OPTIONS.with(|options| options.borrow().clone())
}

pub(crate) fn brute_force_disabled() -> bool {
    current_auth_runtime_options().disable_brute
}

pub(crate) fn current_ms17010_runtime_options() -> Ms17010RuntimeOptions {
    MS17010_RUNTIME_OPTIONS.with(|options| options.borrow().clone())
}

pub(crate) fn current_connection_runtime_options() -> ConnectionRuntimeOptions {
    CONNECTION_RUNTIME_OPTIONS.with(|options| options.borrow().clone())
}

#[allow(dead_code)]
pub(crate) fn current_service_scan_runtime_options() -> ServiceScanRuntimeOptions {
    SERVICE_SCAN_RUNTIME_OPTIONS.with(|options| options.borrow().clone())
}

thread_local! {
    static REDIS_RUNTIME_OPTIONS: RefCell<RedisRuntimeOptions> = RefCell::new(RedisRuntimeOptions::default());
    static AUTH_RUNTIME_OPTIONS: RefCell<AuthRuntimeOptions> = RefCell::new(AuthRuntimeOptions::default());
    static MS17010_RUNTIME_OPTIONS: RefCell<Ms17010RuntimeOptions> = RefCell::new(Ms17010RuntimeOptions::default());
    static CONNECTION_RUNTIME_OPTIONS: RefCell<ConnectionRuntimeOptions> = RefCell::new(ConnectionRuntimeOptions::default());
    static SERVICE_SCAN_RUNTIME_OPTIONS: RefCell<ServiceScanRuntimeOptions> = RefCell::new(ServiceScanRuntimeOptions::default());
}
