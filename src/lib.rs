use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use error_chain;
use glob::glob;
use log::*;
use nix::sys::stat::{lstat, SFlag};

/// Newtype pattern to avoid type errors.
/// https://www.gnu.org/software/libc/manual/html_node/Process-Identification.html
#[derive(Debug)]
pub struct Pid(u32);

#[derive(Debug)]
struct Inode(u64);

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

//fn extract_pid_from_proc<P: AsRef<Path>>(proc_entry: P) -> Result<Pid> {
//
//    let vec: Vec<&str> = proc_entry.as_os_string()?
//                        .split('/')
//                        .collect();
//
//    eprintln!("vec: {:?}", vec);
//    Ok(Pid(0))
////                        .collect::<Vec<&str>>()[2]
////                        .parse::<u32>().unwrap();
////            pids.push(Pid(pid));
//}

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

    Err(Error::from_kind(ErrorKind::InodeNotFound(path_buf.to_str().unwrap().to_string())))
}

/// Given a file path, return the process id of any processes that have an open file descriptor
/// pointing to the given file.
pub fn opath<P: AsRef<Path>>(path: P) -> Result<Vec<Pid>> {
    let mut path_buf = PathBuf::new();
    path_buf.push(path);
    let mut pids: Vec<Pid> = Vec::new();
    let stat_info = lstat(&path_buf)?;
    info!("stat info: {:?}", stat_info);

    let mut target_path = PathBuf::new();
    target_path.push(fs::canonicalize(&path_buf)?);

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
    }

    Ok(pids)
}

#[cfg(test)]
mod tests {
    use super::Inode;
    use super::opath;
    use std::fs::File;
    use std::io::Write;
    use std::thread;
    use std::time::Duration;
    use std::process::Command;

    use env_logger;
    use nix::unistd::{fork, ForkResult};
    use rusty_fork::rusty_fork_id;
    use rusty_fork::rusty_fork_test;
    use rusty_fork::rusty_fork_test_name;
    use tempfile::NamedTempFile;

    // TODO: test symlink, socket file, directory, fifo

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
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

    rusty_fork_test! {
    #[test]
    fn test_ofile_other_process() {
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
}
