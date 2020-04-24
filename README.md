# ofiles

[![Build Status](https://travis-ci.org/jabedude/ofiles.svg?branch=master)](https://travis-ci.org/jabedude/ofiles)


A tiny library for determining what process has a file opened for reading/writing/etc. I wrote this for another project but I hope will be useful in other applications.

Example:

```rust
use ofiles::opath;

let mut pids = opath("/path/to/a/file").unwrap();

// Now we have a Vec of process ID's that have the `/path/to/a/file` open
for pid in pids {
    println!("Process {} has {} open!", pid, "/path/to/a/file");
}
```
