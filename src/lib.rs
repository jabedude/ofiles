use std::path::Path;

/// Newtype pattern to avoid type errors.
/// https://www.gnu.org/software/libc/manual/html_node/Process-Identification.html
pub struct Pid(u32);

pub fn ofile<P: AsRef<Path>>(path: P) -> Option<Vec<Pid>> {
    None
}

#[cfg(test)]
mod tests {
    use super::ofile;
    use std::io::{self, Write};

    use nix::unistd::{fork, ForkResult};
    use rusty_fork::rusty_fork_id;
    use rusty_fork::rusty_fork_test;
    use rusty_fork::rusty_fork_test_name;
    use tempfile::NamedTempFile;


    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn test_ofile_basic() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "T").unwrap();

        let p = file.path();
        
        let ofile_pid = ofile(p).unwrap().pop().unwrap();

        assert_eq!(ofile_pid.0, std::process::id());
    }

    rusty_fork_test! {
    #[test]
    fn test_ofile_other_process() {
        match fork() {
            Ok(ForkResult::Parent { child: child, .. }) => {
                eprintln!("Child pid: {}", child);
            },
            Ok(ForkResult::Child) => {
            },
            Err(_) => panic!("Fork failed"),
        }
    }
    }
}
