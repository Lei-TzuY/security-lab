use crate::SandboxError;

#[cfg(target_os = "linux")]
mod imp {
    use super::SandboxError;
    use std::io;
    use std::os::unix::io::RawFd;
    use std::sync::Arc;

    #[derive(Debug)]
    struct Inner {
        fd: RawFd,
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    /// Cloneable launcher control-plane token used to request asynchronous
    /// cancellation of a cancellable sandbox run.
    ///
    /// Cancellation is one-way: once any clone signals the token, future runs
    /// using the same token observe it as already cancelled.
    #[derive(Clone, Debug)]
    pub struct CancellationToken {
        inner: Arc<Inner>,
    }

    impl CancellationToken {
        /// Create a Linux eventfd-backed cancellation token.
        pub fn new() -> Result<Self, SandboxError> {
            let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            if fd == -1 {
                let error = io::Error::last_os_error();
                return if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES)
                ) {
                    Err(SandboxError::UnsupportedPlatform(format!(
                        "external cancellation requires eventfd support: {error}"
                    )))
                } else {
                    Err(SandboxError::SetupFailed(format!(
                        "cannot create external cancellation eventfd: {error}"
                    )))
                };
            }
            Ok(Self {
                inner: Arc::new(Inner { fd }),
            })
        }

        /// Request cancellation. Repeated calls are harmless; the eventfd is
        /// intentionally never drained by the launcher, so readiness persists.
        pub fn cancel(&self) -> Result<(), SandboxError> {
            let value = 1u64;
            loop {
                let written = unsafe {
                    libc::write(
                        self.inner.fd,
                        (&value as *const u64).cast::<libc::c_void>(),
                        std::mem::size_of::<u64>(),
                    )
                };
                if written == std::mem::size_of::<u64>() as isize {
                    return Ok(());
                }
                if written == -1 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(SandboxError::SetupFailed(format!(
                        "cannot signal external cancellation eventfd: {error}"
                    )));
                }
                return Err(SandboxError::SetupFailed(
                    "external cancellation eventfd accepted a short write".to_owned(),
                ));
            }
        }

        pub(crate) fn raw_fd(&self) -> RawFd {
            self.inner.fd
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::SandboxError;

    #[derive(Clone, Debug)]
    pub struct CancellationToken;

    impl CancellationToken {
        pub fn new() -> Result<Self, SandboxError> {
            Err(SandboxError::UnsupportedPlatform(
                "external cancellation currently requires Linux eventfd".to_owned(),
            ))
        }

        pub fn cancel(&self) -> Result<(), SandboxError> {
            Err(SandboxError::UnsupportedPlatform(
                "external cancellation currently requires Linux eventfd".to_owned(),
            ))
        }

        pub(crate) fn raw_fd(&self) -> i32 {
            -1
        }
    }
}

pub use imp::CancellationToken;
