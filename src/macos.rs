use std::path::Path;
use crate::*;

pub fn opath<P: AsRef<Path>>(path: P) -> Result<Vec<Pid>> {
    let pids: Vec<Pid> = Vec::new();
    Ok(pids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example() {
        assert!(true);
    }
}
