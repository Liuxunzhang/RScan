//! Per-protocol service plugins.
//!
//! Each submodule owns the scan entry point (`scan_<name>`) together with the
//! protocol-specific login and wire helpers it needs. Scan entry points are
//! `pub(crate)` and are dispatched from the crate root `scan_service_task`.

pub(crate) mod cassandra;
pub(crate) mod elasticsearch;
pub(crate) mod ftp;
pub(crate) mod memcached;
pub(crate) mod modbus;
pub(crate) mod mongodb;
pub(crate) mod neo4j;
pub(crate) mod postgres;
pub(crate) mod redis;
pub(crate) mod smbghost;
pub(crate) mod ssh;
pub(crate) mod telnet;
pub(crate) mod vnc;
