use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use error_chain;
use glob::glob;
use log::{trace, info};
use nix::sys::stat::{lstat, SFlag};

/// Newtype pattern to avoid type errors.
/// https://www.gnu.org/software/libc/manual/html_node/Process-Identification.html
#[derive(Debug, Clone, Copy)]
pub struct Pid(u32);

/// Socket types
#[derive(Debug, PartialEq)]
pub enum Socket {
    /// Tcp + IPv4
    Tcp4,
    /// Tcp + IPv6
    Tcp6
}

#[derive(Debug)]
struct Inode(u64);

impl From<Pid> for u32 {
    fn from(pid: Pid) -> u32 {
        pid.0
    }
}

impl Inode {
    pub fn contained_in(&self, other: &str) -> bool {
        //let num_str: String = other.chars().filter(|x| x.is_numeric()).collect();
        //match num_str.parse::<u64>() {
        //    Ok(n) => n == self.0,
        //    Err(_) => false,
        //}
        let str_repr = self.0.to_string();
        other.contains(&str_repr)
    }
}

error_chain::error_chain! {
    foreign_links {
        Io(::std::io::Error);
        Nix(nix::Error);
        ParseInt(::std::num::ParseIntError);
        Parse(::std::string::ParseError);
    }

    errors {
        InodeNotFound(t: String) {
            description("Inode not found")
            display("Inode not found: '{}'", t)
        }
    }
}

macro_rules! unwrap_or_continue {
    ($e:expr) => {{
        if let Ok(x) = $e {
            x
        } else {
            continue;
        }
    }};
}

/// Given a single `line` from `/proc/net/unix`, return the Inode.
///
/// See man 5 proc.
fn extract_socket_inode(line: &str) -> Result<Inode> {
    let elements: Vec<&str> = line.split(' ').collect();
    let inode = Inode(elements[6].parse::<u64>()?);

    Ok(inode)
}

fn extract_inode(line: &str) -> Result<Inode> {
    let trim = line.trim_end_matches(']');
    let trim = trim.trim_start_matches("socket:[");
    Ok(Inode(trim.parse::<u64>()?))
}

/// Search `/proc/net/unix` for the line containing `path_buf` and return the inode given
/// by the system.
fn socket_file_to_inode(path_buf: &PathBuf) -> Result<Inode> {
    let f = File::open("/proc/net/unix")?;
    let f = BufReader::new(f);

    for line in f.lines() {
        if let Ok(l) = line {
            info!("line: {:?}", l);
            if l.contains(path_buf.to_str().unwrap()) {
                let inode = extract_socket_inode(&l)?;
                return Ok(inode);
            }
        }
    }

    Err(Error::from_kind(ErrorKind::InodeNotFound(
        path_buf.to_str().unwrap().to_string(),
    )))
}

/// Search `/proc/net` for the socket corresponding to `inode`.
fn inode_to_socket(inode: Inode) -> Result<Socket> {
    let f = File::open("/proc/net/tcp")?;
    let f = BufReader::new(f);

    for line in f.lines() {
        if let Ok(l) = line {
            eprintln!("Looking for {:?}", inode);
            eprintln!("line: {:?}", l);
            if inode.contained_in(&l) {
                return Ok(Socket::Tcp4)
            }
        }
    }

    Err(Error::from_kind(ErrorKind::InodeNotFound(
        format!("inode: {:?}", inode),
    )))
}

/// (DEPRICATED) Given a file path, return the process id of any processes that have an open file descriptor
/// pointing to the given file.
#[deprecated]
pub fn opath<P: AsRef<Path>>(path: P) -> Result<Vec<Pid>> {
    pids_of_path(path)
}

/// Given a file path, return the process id of any processes that have an open file descriptor
/// pointing to the given file.
pub fn pids_of_path<P: AsRef<Path>>(path: P) -> Result<Vec<Pid>> {
    let mut path_buf = PathBuf::new();
    path_buf.push(path);
    let mut pids: Vec<Pid> = Vec::new();
    let stat_info = lstat(&path_buf)?;
    info!("stat info: {:?}", stat_info);

    let mut target_path = PathBuf::new();
    target_path.push(fs::canonicalize(&path_buf)?);
    info!("Target path: {:?}", target_path);

    // FIXME: not sure what the *right* way to do this is. Revisit later.
    if SFlag::S_IFMT.bits() & stat_info.st_mode == SFlag::S_IFREG.bits() {
        info!("stat info reg file: {:?}", stat_info.st_mode);
        for entry in glob("/proc/*/fd/*").expect("Failed to read glob pattern") {
            let e = unwrap_or_continue!(entry);
            let real = unwrap_or_continue!(fs::read_link(&e));

            if real == target_path {
                let pbuf = e.to_str().unwrap().split('/').collect::<Vec<&str>>()[2];
                let pid = unwrap_or_continue!(pbuf.parse::<u32>());
                pids.push(Pid(pid));
                info!("process: {:?} -> real: {:?}", pid, real);
            }
        }
    } else if SFlag::S_IFMT.bits() & stat_info.st_mode == SFlag::S_IFSOCK.bits() {
        info!("stat info socket file: {:?}", stat_info.st_mode);
        let inode = socket_file_to_inode(&target_path)?;
        info!("inode: {:?}", inode);
        for entry in glob("/proc/*/fd/*").expect("Failed to read glob pattern") {
            let e = unwrap_or_continue!(entry);
            let real = unwrap_or_continue!(fs::read_link(&e));
            let real = real.as_path().display().to_string();
            trace!("real: {:?} vs {}", real, inode.0);
            if inode.contained_in(&real) {
                info!("real found: {:?}", real);
                let pbuf = e.to_str().unwrap().split('/').collect::<Vec<&str>>()[2];
                let pid = unwrap_or_continue!(pbuf.parse::<u32>());
                pids.push(Pid(pid));
            }
        }
    } else if SFlag::S_IFMT.bits() & stat_info.st_mode == SFlag::S_IFDIR.bits() {
        info!("Got a directory!");
        for entry in glob("/proc/*/fd/*").expect("Failed to read glob pattern") {
            let e = unwrap_or_continue!(entry);
            let real = unwrap_or_continue!(fs::read_link(&e));
            trace!("Real: {:?}", real);

            if real == target_path {
                info!("Found target: {:?}", target_path);
                let pbuf = e.to_str().unwrap().split('/').collect::<Vec<&str>>()[2];
                let pid = unwrap_or_continue!(pbuf.parse::<u32>());
                pids.push(Pid(pid));
                info!("process: {:?} -> real: {:?}", pid, real);
            }
        }
    } else {
        return Err(crate::ErrorKind::InodeNotFound(format!("Unknown file {:?}", stat_info)).into());
    }

    Ok(pids)
}

/// Given a process id, return a vector of file paths the process has open.
pub fn paths_of_pid(pid: u32) -> Result<Vec<PathBuf>> {
    let proc_path = format!("/proc/{}/fd/*", pid);
    let mut paths = Vec::new();
    for entry in glob(&proc_path).expect("Failed to read glob pattern") {
        let e = unwrap_or_continue!(entry);
        let real = unwrap_or_continue!(fs::read_link(&e));
        trace!("Real path: {:?}", real);
        paths.push(real);
    }

    Ok(paths)
}

/// Given a process id, return a vector of sockets the process has open.
pub fn sockets_of_pid(pid: u32) -> Result<Vec<Socket>> {
    let proc_path = format!("/proc/{}/fd/*", pid);
    let mut sockets = Vec::new();

    for entry in glob(&proc_path).expect("Failed to read glob pattern") {
        let e = unwrap_or_continue!(entry);
        let real = unwrap_or_continue!(fs::read_link(&e));
        trace!("Real path: {:?}", real);
        eprintln!("Real path: {:?}", real);
        if let Some(real_str) = real.to_str() {
            if real_str.contains("socket:[") {
                let inode = extract_inode(real_str)?;
                eprintln!("Inode: {:?}", inode);
                let socket = inode_to_socket(inode)?;
                sockets.push(socket);
            }
        }
    }

    Ok(sockets)
}

#[cfg(test)]
mod tests {
    use super::{opath, paths_of_pid, Socket, sockets_of_pid};
    use super::Inode;
    use std::net::TcpListener;
    use std::fs::File;
    use std::io::Write;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    use env_logger;
    use nix::unistd::{fork, ForkResult};
    use rusty_fork::rusty_fork_id;
    use rusty_fork::rusty_fork_test;
    use rusty_fork::rusty_fork_test_name;
    use tempfile::{NamedTempFile, TempDir};
    use nix::unistd::symlinkat;

    // TODO: test socket file, fifo

    #[test]
    fn test_sockets_of_pid_basic() {
        let expected = Socket::Tcp4;
        let sock = TcpListener::bind("127.0.0.1:9090");

        let pid_socks = sockets_of_pid(std::process::id()).unwrap();

        assert!(pid_socks.contains(&expected));
    }

    #[test]
    fn test_files_of_pid_basic() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "T").unwrap();

        let p = file.path().to_path_buf();

        let paths = paths_of_pid(std::process::id()).unwrap();

        eprintln!("Paths: {:?}", paths);
        eprintln!("Expecting to find: {:?}", p);
        assert!(paths.contains(&p));
    }

    #[test]
    fn test_inode_contained_in() {
        let inode = Inode(1234);
        let buf = "socket:[1234]";

        assert!(inode.contained_in(buf));
    }

    rusty_fork_test! {
    #[test]
    fn test_ofile_other_process_unix_socket() {
        env_logger::init();
        let path = "/tmp/.opath_socket";

        match fork() {
            Ok(ForkResult::Parent { child, .. }) => {
                eprintln!("Child pid: {}", child);
                let mut spawn = Command::new("nc")
                                .arg("-U")
                                .arg(&path)
                                .arg("-l")
                                .spawn()
                                .unwrap();
                thread::sleep(Duration::from_millis(500));
                let pid = opath(&path).unwrap().pop().unwrap();

                assert_eq!(pid.0, spawn.id() as u32);
                spawn.kill().unwrap();
                std::fs::remove_file(&path).unwrap();
            },
            Ok(ForkResult::Child) => {
                thread::sleep(Duration::from_millis(5000));
            },
            Err(_) => panic!("Fork failed"),
        }
    }
    }

    #[test]
    fn test_ofile_basic() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "T").unwrap();

        let p = file.path();

        let ofile_pid = opath(p).unwrap().pop().unwrap();

        assert_eq!(ofile_pid.0, std::process::id());
    }

    #[test]
    fn test_directory_basic() {
        let tmp_dir = TempDir::new().unwrap();
        let p = tmp_dir.path();
        let _dir = File::open(&p).unwrap();

        let ofile_pid = opath(p).unwrap().pop().unwrap();

        assert_eq!(ofile_pid.0, std::process::id());
    }

    rusty_fork_test! {
    #[test]
    fn test_file_other_process() {
        let path = "/tmp/.opath_tmp";

        match fork() {
            Ok(ForkResult::Parent { child, .. }) => {
                thread::sleep(Duration::from_millis(100));
                eprintln!("Child pid: {}", child);
                let pid = opath(&path).unwrap().pop().unwrap();

                assert_eq!(pid.0, child.as_raw() as u32);
            },
            Ok(ForkResult::Child) => {
                let mut f = File::create(&path).unwrap();
                writeln!(f, "test").unwrap();

                thread::sleep(Duration::from_millis(500));
            },
            Err(_) => panic!("Fork failed"),
        }
    }
    }

    rusty_fork_test! {
    #[test]
    fn test_directory_other_process() {
        let path = ".";

        match fork() {
            Ok(ForkResult::Parent { child, .. }) => {
                thread::sleep(Duration::from_millis(100));
                eprintln!("Child pid: {}", child);
                let pid = opath(&path).unwrap().pop().unwrap();

                assert_eq!(pid.0, child.as_raw() as u32);
            },
            Ok(ForkResult::Child) => {
                let _dir = File::open(&path).unwrap();

                thread::sleep(Duration::from_millis(500));
            },
            Err(_) => panic!("Fork failed"),
        }
    }
    }

    #[test]
    fn test_symlink_basic() {
        let orig = "/tmp/.ofile_orig";
        let sym = "/tmp/.symlink";

        {
            std::fs::remove_file(orig);
            std::fs::remove_file(sym);
            let _orig_file = File::create(orig).unwrap();
            symlinkat(orig, None, sym).unwrap();
        }

        let _sym_file = File::open(sym).unwrap();

        let ofile_pid = opath(orig).unwrap().pop().unwrap();

        assert_eq!(ofile_pid.0, std::process::id());
    }
}
