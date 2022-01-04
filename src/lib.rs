use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use error_chain;
use glob::glob;
use log::{info, trace};
use nix::sys::stat::{lstat, SFlag};

/// Newtype pattern to avoid type errors.
/// https://www.gnu.org/software/libc/manual/html_node/Process-Identification.html
#[derive(Debug, Clone, Copy)]
pub struct Pid(u32);

#[derive(Debug)]
struct Inode(u64);

impl From<Pid> for u32 {
    fn from(pid: Pid) -> u32 {
        pid.0
    }
}

impl Inode {
    pub fn contained_in(&self, other: &str) -> bool {
        let num_str: String = other.chars().filter(|x| x.is_numeric()).collect();
        match num_str.parse::<u64>() {
            Ok(n) => n == self.0,
            Err(_) => false,
        }
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

/// Search `/proc/net/unix` for the line containing `path_buf` and return the inode given
/// by the system.
fn socket_file_to_inode(path_buf: &PathBuf) -> Result<Option<Inode>> {
    let f = File::open("/proc/net/unix")?;
    let f = BufReader::new(f);

    for line in f.lines() {
        if let Ok(l) = line {
            info!("line: {:?}", l);
            if l.contains(path_buf.to_str().unwrap()) {
                let inode = extract_socket_inode(&l)?;
                return Ok(Some(inode));
            }
        }
    }

    Ok(None)
}

fn lookup_pids<F>(pids: &mut Vec<Pid>, matcher: F)
where
    F: Fn(&PathBuf) -> bool,
{
    for entry in glob("/proc/*/fd/*").expect("Failed to read glob pattern") {
        let e = unwrap_or_continue!(entry);
        let real = unwrap_or_continue!(fs::read_link(&e));

        if matcher(&real) {
            let pbuf = e.to_str().unwrap().split('/').collect::<Vec<&str>>()[2];
            let pid = unwrap_or_continue!(pbuf.parse::<u32>());
            pids.push(Pid(pid));
            info!("process: {:?} -> real: {:?}", pid, real);
        }
    }
}

/// Returns the PIDs that currently have the given file or directory open.
pub fn ofile<P: AsRef<Path>>(path: P) -> Result<Vec<Pid>> {
    let mut pids: Vec<Pid> = Vec::new();
    let mut target_path = PathBuf::new();
    target_path.push(fs::canonicalize(&path)?);
    lookup_pids(&mut pids, |real| *real == target_path);
    return Ok(pids);
}

/// Returns the PIDs attached to the given socket.
pub fn osocket<P: AsRef<Path>>(path: P) -> Result<Vec<Pid>> {
    let mut pids: Vec<Pid> = Vec::new();
    let mut target_path = PathBuf::new();
    target_path.push(fs::canonicalize(&path)?);
    let inode = match socket_file_to_inode(&target_path)? {
        Some(inode) => inode,
        None => return Ok(pids),
    };
    info!("inode: {:?}", inode);
    lookup_pids(&mut pids, |real| {
        inode.contained_in(&real.as_path().display().to_string())
    });
    return Ok(pids);
}

/// Given a file path, return the process id of any processes that have an open file descriptor
/// pointing to the given file.
pub fn opath<P: AsRef<Path>>(path: P) -> Result<Vec<Pid>> {
    let mut path_buf = PathBuf::new();
    path_buf.push(&path);
    let mut pids: Vec<Pid> = Vec::new();
    let stat_info = lstat(&path_buf)?;
    info!("stat info: {:?}", stat_info);

    if SFlag::S_IFMT.bits() & stat_info.st_mode == SFlag::S_IFREG.bits() {
        info!("stat info reg file: {:?}", stat_info.st_mode);
        pids.extend(ofile(&path)?);
    } else if SFlag::S_IFMT.bits() & stat_info.st_mode == SFlag::S_IFSOCK.bits() {
        info!("stat info socket file: {:?}", stat_info.st_mode);
        pids.extend(osocket(&path)?);
    } else if SFlag::S_IFMT.bits() & stat_info.st_mode == SFlag::S_IFDIR.bits() {
        info!("Got a directory!");
        pids.extend(ofile(&path)?);
    } else {
        return Err(
            crate::ErrorKind::InodeNotFound(format!("Unknown file {:?}", stat_info)).into(),
        );
    }
    Ok(pids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    use env_logger;
    use nix::unistd::symlinkat;
    use nix::unistd::{fork, ForkResult};
    use rusty_fork::rusty_fork_id;
    use rusty_fork::rusty_fork_test;
    use rusty_fork::rusty_fork_test_name;
    use tempfile::{NamedTempFile, TempDir};

    // TODO: test socket file, fifo

    #[test]
    fn test_inode_contained_in() {
        let inode = Inode(1234);
        let buf = "socket:[1234]";

        assert!(inode.contained_in(buf));
    }

    #[test]
    fn test_ofile_unix_socket() {
        let path = "/tmp/.opath_socket";
        std::fs::remove_file(&path).unwrap_or(());

        let sock = nix::sys::socket::socket(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Datagram,
            nix::sys::socket::SockFlag::empty(),
            None,
        )
        .unwrap();
        nix::sys::socket::bind(sock, &nix::sys::socket::SockAddr::new_unix(path).unwrap()).unwrap();
        let pid = opath(&path).unwrap().pop().unwrap();
        assert_eq!(opath(&path).unwrap().len(), 1);

        assert_eq!(u32::from(pid), std::process::id() as u32);
        nix::unistd::close(sock).unwrap();
        drop(sock);
        assert_eq!(opath(&path).unwrap().len(), 0);
        std::fs::remove_file(&path).unwrap();
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
    fn test_non_existant_file_basic() {
        let p = "/tmp/non-existant-file";
        match opath(p) {
            Ok(_) => unreachable!(),
            Err(e) => assert_eq!(
                format!("{:?}", e),
                "Error(Nix(Sys(ENOENT)), State { next_error: None, backtrace: InternalBacktrace })"
            ),
        };
        match osocket(p) {
            Ok(_) => unreachable!(),
            Err(e) => assert_eq!(format!("{:?}", e), "Error(Io(Os { code: 2, kind: NotFound, message: \"No such file or directory\" }), State { next_error: None, backtrace: InternalBacktrace })"),
        };
    }

    #[test]
    fn test_not_a_socket() {
        let p = "/tmp/.not_a_socket";
        std::fs::write(p, "foo").unwrap();
        match osocket(p) {
            Ok(pids) => assert_eq!(pids.len(), 0),
            Err(e) => unreachable!(),
        };
        std::fs::remove_file(&p).unwrap();
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
            let orig_file = File::create(orig).unwrap();
            symlinkat(orig, None, sym).unwrap();
        }

        let sym_file = File::open(sym).unwrap();

        let ofile_pid = opath(orig).unwrap().pop().unwrap();

        assert_eq!(ofile_pid.0, std::process::id());
    }
}
