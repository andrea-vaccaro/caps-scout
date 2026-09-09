use std::path::Path;

/// Abstracts "does this path exist" / "what's in this file" so probes can
/// be tested against a fake filesystem instead of the real one.
pub trait FileSystem {
    fn exists(&self, path: &str) -> bool;

    /// Reads a file's content. `None` on any I/O error (missing file, no
    /// permission, not valid UTF-8, ...) — probes treat all of those as
    /// "nothing to detect" rather than distinguishing the reason.
    fn read_to_string(&self, path: &str) -> Option<String>;
}

pub struct RealFileSystem;

impl FileSystem for RealFileSystem {
    fn exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }

    fn read_to_string(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }
}

/// A fake filesystem for testing `detect_*` probes without touching the
/// real one. Shared across the `probes` module tree, not just this file's
/// own tests. Existence-only — `read_to_string` always returns `None`; use
/// `FakeFileContents` for probes that need actual file content.
#[cfg(test)]
pub struct FakeFileSystem(pub Vec<&'static str>);

#[cfg(test)]
impl FileSystem for FakeFileSystem {
    fn exists(&self, path: &str) -> bool {
        self.0.contains(&path)
    }

    fn read_to_string(&self, _path: &str) -> Option<String> {
        None
    }
}

/// A fake filesystem of (path, content) pairs, for probes that read a
/// file's content rather than just checking it exists.
#[cfg(test)]
pub struct FakeFileContents(pub Vec<(&'static str, &'static str)>);

#[cfg(test)]
impl FileSystem for FakeFileContents {
    fn exists(&self, path: &str) -> bool {
        self.0.iter().any(|(p, _)| *p == path)
    }

    fn read_to_string(&self, path: &str) -> Option<String> {
        self.0
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(_, content)| content.to_string())
    }
}
