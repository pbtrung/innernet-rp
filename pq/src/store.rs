//! Owner-only, locked, atomic private storage. No secret enters an error message.
use serde::{Serialize, de::DeserializeOwned};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_BYTES: u64 = 16 * 1024 * 1024;
const STATE: &std::ffi::CStr = c"state.json";

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("private storage I/O failure: {0}")]
    Io(#[from] io::Error),
    #[error("private storage has unsafe ownership, permissions, links, or type")]
    Unsafe,
    #[error("another process owns this interface")]
    Busy,
    #[error("private state is missing or corrupt; explicit recovery is required")]
    Corrupt,
    #[error("private state has a newer unsupported format")]
    Newer,
    #[error("private state changed unexpectedly; reopen and reconcile before retrying")]
    Conflict,
}
type Result<T> = std::result::Result<T, StoreError>;

#[derive(Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    version: u8,
    generation: u64,
    value: T,
}

/// One handle owns the interface lock for its entire lifetime. The lock inode is
/// never renamed/deleted; state replacement cannot detach it from other owners.
pub struct Store {
    directory: File,
    _lock: File,
    generation: u64,
    fresh: bool,
    digest: Option<[u8; 32]>,
}

fn open_at(directory: &File, name: &std::ffi::CStr, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: the directory descriptor and NUL-terminated name remain live;
    // a successful returned descriptor is transferred to exactly one File.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn owned_file(file: &File) -> Result<()> {
    let meta = file.metadata()?;
    // SAFETY: geteuid has no pointer or memory preconditions.
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
    {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}
fn c_name(name: &OsStr) -> Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| StoreError::Unsafe)
}

impl Store {
    /// Traverse every component with O_NOFOLLOW and directory descriptors.
    /// Existing state directories must already be 0700; never "repair" an
    /// attacker-selected path by chmodding it. Sticky root-owned /tmp is a
    /// permitted parent, but never a permitted private-state directory.
    pub fn open(path: &Path, create: bool) -> Result<Self> {
        if !path.is_absolute() {
            return Err(StoreError::Unsafe);
        }
        let parts: Vec<_> = path.components().collect();
        if parts.len() < 2 {
            return Err(StoreError::Unsafe);
        }
        let mut directory = File::open("/")?;
        let mut fresh = false;
        for (index, part) in parts.iter().enumerate().skip(1) {
            let Component::Normal(name) = part else {
                return Err(StoreError::Unsafe);
            };
            let name = c_name(name)?;
            let final_part = index == parts.len() - 1;
            let opened = open_at(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0);
            let child = match opened {
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    // SAFETY: descriptor and C string are valid for the syscall.
                    let result =
                        unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
                    if result != 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::AlreadyExists {
                            return Err(error.into());
                        }
                    } else {
                        directory.sync_all()?;
                        fresh = final_part;
                    }
                    open_at(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
                },
                value => value?,
            };
            let meta = child.metadata()?;
            // SAFETY: geteuid has no pointer or memory preconditions.
            let uid = unsafe { libc::geteuid() };
            if final_part {
                if meta.uid() != uid || meta.mode() & 0o7777 != 0o700 {
                    return Err(StoreError::Unsafe);
                }
            } else if (meta.uid() != 0 && meta.uid() != uid)
                || (meta.mode() & 0o022 != 0 && !(meta.uid() == 0 && meta.mode() & 0o1000 != 0))
            {
                return Err(StoreError::Unsafe);
            }
            directory = child;
        }
        let lock = open_at(
            &directory,
            c"owner.lock",
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
            0o600,
        )?;
        owned_file(&lock)?;
        // SAFETY: a live owned regular-file descriptor is passed to flock.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            return Err(if error.kind() == io::ErrorKind::WouldBlock {
                StoreError::Busy
            } else {
                error.into()
            });
        }
        directory.sync_all()?;
        Ok(Self {
            directory,
            _lock: lock,
            generation: 0,
            fresh,
            digest: None,
        })
    }

    fn bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let file = open_at(&self.directory, STATE, libc::O_RDONLY | libc::O_NONBLOCK, 0).map_err(
            |error| {
                if error.kind() == io::ErrorKind::NotFound {
                    StoreError::Corrupt
                } else {
                    error.into()
                }
            },
        )?;
        owned_file(&file)?;
        let length = file.metadata()?.len();
        if length == 0 || length > MAX_BYTES {
            return Err(StoreError::Corrupt);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(length as usize));
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(StoreError::Corrupt);
        }
        Ok(bytes)
    }

    pub fn load<T: DeserializeOwned>(&mut self) -> Result<T> {
        let bytes = self.bytes()?;
        // First inspect only the envelope version; parsing errors never include
        // private field values in diagnostics or logs.
        #[derive(serde::Deserialize)]
        struct Version {
            version: u8,
        }
        let version: Version = serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
        if version.version > 1 {
            return Err(StoreError::Newer);
        }
        if version.version != 1 {
            return Err(StoreError::Corrupt);
        }
        let value: Envelope<T> = serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
        if value.generation == 0 {
            return Err(StoreError::Corrupt);
        }
        self.generation = value.generation;
        self.fresh = false;
        self.digest = Some(crate::crypto::hash(&bytes).map_err(|_| StoreError::Corrupt)?);
        Ok(value.value)
    }

    pub fn save<T: Serialize>(&mut self, value: &T) -> Result<()> {
        self.save_checked(value, |_| Ok(()))
    }

    pub fn is_fresh(&self) -> bool {
        self.fresh
    }

    /// Export an authenticated-out-of-band artifact inside the protected store.
    /// Retries may reuse identical bytes, but never overwrite a different secret.
    pub fn export(&self, filename: &str, bytes: &[u8]) -> Result<()> {
        if filename.is_empty()
            || filename.len() > 128
            || filename.starts_with('.')
            || !filename
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            || matches!(filename, "state.json" | "owner.lock")
            || bytes.len() > 1024 * 1024
        {
            return Err(StoreError::Unsafe);
        }
        let name = CString::new(filename).map_err(|_| StoreError::Unsafe)?;
        let mut file = match open_at(
            &self.directory,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let file = open_at(&self.directory, &name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
                owned_file(&file)?;
                let mut prior = Zeroizing::new(Vec::new());
                file.take(1024 * 1024 + 1).read_to_end(&mut prior)?;
                return if prior.as_slice() == bytes {
                    Ok(())
                } else {
                    Err(StoreError::Conflict)
                };
            },
            Err(error) => return Err(error.into()),
        };
        owned_file(&file)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.directory.sync_all()?;
        Ok(())
    }

    fn save_checked<T: Serialize>(
        &mut self,
        value: &T,
        mut fault: impl FnMut(Boundary) -> io::Result<()>,
    ) -> Result<()> {
        let generation = self.generation.checked_add(1).ok_or(StoreError::Conflict)?;
        if self.fresh {
            match open_at(&self.directory, STATE, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                _ => return Err(StoreError::Conflict),
            }
        } else {
            #[derive(serde::Deserialize)]
            struct Generation {
                version: u8,
                generation: u64,
            }
            let current_bytes = self.bytes()?;
            let current: Generation =
                serde_json::from_slice(&current_bytes).map_err(|_| StoreError::Corrupt)?;
            if current.version > 1 {
                return Err(StoreError::Newer);
            }
            if current.version != 1 {
                return Err(StoreError::Corrupt);
            }
            if current.generation != self.generation {
                return Err(StoreError::Conflict);
            }
            if self.digest
                != Some(crate::crypto::hash(&current_bytes).map_err(|_| StoreError::Corrupt)?)
            {
                return Err(StoreError::Conflict);
            }
        }
        let bytes = Zeroizing::new(
            serde_json::to_vec(&Envelope {
                version: 1,
                generation,
                value,
            })
            .map_err(|_| StoreError::Corrupt)?,
        );
        if bytes.len() as u64 > MAX_BYTES {
            return Err(StoreError::Corrupt);
        }
        let suffix = crate::crypto::random::<16>(&mut crate::crypto::SystemRandom)
            .map_err(|_| StoreError::Corrupt)?;
        let name = CString::new(format!(
            ".pending-{}",
            suffix
                .0
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
        .map_err(|_| StoreError::Unsafe)?;
        let mut file = open_at(
            &self.directory,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
            0o600,
        )?;
        owned_file(&file)?;
        let result = (|| {
            fault(Boundary::BeforeWrite)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fault(Boundary::AfterFileSync)?;
            // SAFETY: both live descriptors refer to the same private directory;
            // this renames the file itself and never follows the target path.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    self.directory.as_raw_fd(),
                    STATE.as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            fault(Boundary::AfterRename)?;
            self.directory.sync_all()?;
            fault(Boundary::AfterDirectorySync)
        })();
        if result.is_err() {
            // SAFETY: remove only our exact, randomly named temporary file. After
            // rename this name is absent; the durable state is never removed.
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        result?;
        self.generation = generation;
        self.fresh = false;
        self.digest = Some(crate::crypto::hash(&bytes).map_err(|_| StoreError::Corrupt)?);
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Boundary {
    BeforeWrite,
    AfterFileSync,
    AfterRename,
    AfterDirectorySync,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn private_storage_is_locked_owner_only_and_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private");
        let mut store = Store::open(&path, true).unwrap();
        store.save(&vec![1u64, 2, 3]).unwrap();
        assert!(matches!(Store::open(&path, false), Err(StoreError::Busy)));
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            std::fs::metadata(path.join("state.json")).unwrap().mode() & 0o777,
            0o600
        );
        drop(store);
        let mut store = Store::open(&path, false).unwrap();
        assert_eq!(store.load::<Vec<u64>>().unwrap(), vec![1, 2, 3]);
        store.save(&vec![4u64]).unwrap();
        drop(store);
        assert_eq!(
            Store::open(&path, false)
                .unwrap()
                .load::<Vec<u64>>()
                .unwrap(),
            vec![4]
        );
    }

    #[test]
    fn private_storage_refuses_symlinks_hardlinks_permissions_and_missing_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private");
        let mut store = Store::open(&path, true).unwrap();
        store.save(&1).unwrap();
        drop(store);
        symlink(&path, dir.path().join("alias")).unwrap();
        assert!(Store::open(&dir.path().join("alias"), false).is_err());
        let state = path.join("state.json");
        let target = path.join("copy");
        std::fs::rename(&state, &target).unwrap();
        symlink(&target, &state).unwrap();
        assert!(Store::open(&path, false).unwrap().load::<u64>().is_err());
        std::fs::remove_file(&state).unwrap();
        std::fs::hard_link(&target, &state).unwrap();
        assert!(matches!(
            Store::open(&path, false).unwrap().load::<u64>(),
            Err(StoreError::Unsafe)
        ));
        std::fs::remove_file(&target).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Store::open(&path, false).unwrap().load::<u64>(),
            Err(StoreError::Unsafe)
        ));
        std::fs::remove_file(&state).unwrap();
        let mut store = Store::open(&path, true).unwrap();
        assert!(matches!(store.load::<u64>(), Err(StoreError::Corrupt)));
        assert!(store.save(&2).is_err());
    }

    #[test]
    fn private_storage_crash_boundaries_preserve_old_or_complete_new_state() {
        for boundary in [
            Boundary::BeforeWrite,
            Boundary::AfterFileSync,
            Boundary::AfterRename,
            Boundary::AfterDirectorySync,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("private");
            let mut store = Store::open(&path, true).unwrap();
            store.save(&1u64).unwrap();
            assert!(
                store
                    .save_checked(&2u64, |at| if at == boundary {
                        Err(io::Error::other("injected storage fault"))
                    } else {
                        Ok(())
                    })
                    .is_err()
            );
            drop(store);
            let loaded = Store::open(&path, false).unwrap().load::<u64>().unwrap();
            assert_eq!(
                loaded,
                if matches!(boundary, Boundary::BeforeWrite | Boundary::AfterFileSync) {
                    1
                } else {
                    2
                }
            );
        }
    }
}
