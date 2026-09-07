//! Small durable-file helpers for confidential configurations and invitations.
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};
use zeroize::Zeroizing;

fn unsafe_file() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unsafe confidential file or directory",
    )
}
fn open_at(dir: &File, name: &CStr, flags: i32) -> io::Result<File> {
    // SAFETY: live directory descriptor and NUL-terminated filename; ownership
    // of a successful returned descriptor transfers to the File.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn parent(path: &Path) -> io::Result<(File, CString)> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let name = CString::new(path.file_name().ok_or_else(unsafe_file)?.as_bytes())
        .map_err(|_| unsafe_file())?;
    let mut dir = File::open("/")?;
    for part in path.parent().ok_or_else(unsafe_file)?.components().skip(1) {
        let Component::Normal(name) = part else {
            return Err(unsafe_file());
        };
        dir = open_at(
            &dir,
            &CString::new(name.as_bytes()).map_err(|_| unsafe_file())?,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let metadata = dir.metadata()?;
        // SAFETY: geteuid has no pointer or memory preconditions.
        let uid = unsafe { libc::geteuid() };
        if (metadata.uid() != 0 && metadata.uid() != uid)
            || (metadata.mode() & 0o022 != 0
                && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0))
        {
            return Err(unsafe_file());
        }
    }
    // A writable shared parent is not safe for atomic replacement, even /tmp.
    if dir.metadata()?.mode() & 0o022 != 0 {
        return Err(unsafe_file());
    }
    Ok((dir, name))
}
fn validate(file: &File, strict: bool) -> io::Result<()> {
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no pointer or memory preconditions.
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || (strict && metadata.mode() & 0o7777 != 0o600)
    {
        return Err(unsafe_file());
    }
    Ok(())
}

pub fn read(path: &Path, strict: bool) -> io::Result<Zeroizing<String>> {
    let (dir, name) = parent(path)?;
    let file = open_at(&dir, &name, libc::O_RDONLY)?;
    validate(&file, strict)?;
    if file.metadata()?.len() > 1024 * 1024 {
        return Err(io::Error::other("configuration exceeds size limit"));
    }
    let mut text = Zeroizing::new(String::new());
    file.take(1024 * 1024 + 1).read_to_string(&mut text)?;
    if text.len() > 1024 * 1024 {
        return Err(io::Error::other("configuration exceeds size limit"));
    }
    Ok(text)
}

pub fn write(path: &Path, bytes: &[u8], new: bool) -> io::Result<()> {
    let (dir, name) = parent(path)?;
    if new {
        let mut file = open_at(&dir, &name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
        validate(&file, true)?;
        let result = file
            .write_all(bytes)
            .and_then(|_| file.sync_all())
            .and_then(|_| dir.sync_all());
        if result.is_err() {
            // SAFETY: remove only the new file this call created, never an old config.
            unsafe {
                libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        return result;
    }
    match open_at(&dir, &name, libc::O_RDONLY) {
        Ok(file) => validate(&file, true)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err(error),
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let temp = CString::new(format!(
        ".innernet-{}",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
    .map_err(|_| unsafe_file())?;
    let mut file = open_at(&dir, &temp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
    validate(&file, true)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        // SAFETY: both names and the private parent descriptor remain live.
        if unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                temp.as_ptr(),
                dir.as_raw_fd(),
                name.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        dir.sync_all()
    })();
    if result.is_err() {
        // SAFETY: exact temporary name created by this call; never follow a link.
        unsafe {
            libc::unlinkat(dir.as_raw_fd(), temp.as_ptr(), 0);
        }
    }
    result
}

pub fn write_toml(path: &Path, value: &impl serde::Serialize, new: bool) -> io::Result<()> {
    let text = Zeroizing::new(
        toml::to_string(value)
            .map_err(|_| io::Error::other("failed to serialize confidential configuration"))?,
    );
    write(path, text.as_bytes(), new)
}
