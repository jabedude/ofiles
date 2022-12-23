# ofiles

[![crates.io](https://img.shields.io/crates/v/ofiles.svg)](https://crates.io/crates/ofiles)
![Rust](https://github.com/jabedude/ofiles/workflows/Rust/badge.svg)
[![Documentation](https://docs.rs/ofiles/badge.svg)](https://docs.rs/ofiles/)
[![license](https://img.shields.io/badge/license-BSD3.0-blue.svg)](https://github.com/jabedude/ofiles/LICENSE)

A tiny library for determining what process has a file/directory opened for reading/writing/etc. 
I wrote this for another project but I hope will be useful in other applications.

Example:

```rust
use ofiles::opath;

let mut pids = opath("/path/to/a/file-or-directory").unwrap();

// Now we have a Vec of process ID's that have the `/path/to/a/file-or-directory` open
for pid in pids {
    println!("Process {:?} has {} open!", pid, "/path/to/a/file-or-directory");
}
```
