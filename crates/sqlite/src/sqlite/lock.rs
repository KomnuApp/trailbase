use std::ops::{Deref, DerefMut};

const CLOSED: &str = "connection closed";

#[derive(thiserror::Error, Debug)]
pub enum LockError {
  #[error("Timeout")]
  Timeout,
  #[error("Shutdown")]
  Shutdown,
  #[error("NotSupported")]
  NotSupported,
}

/// Exclusive access to the writer connection. Readers keep running on their own connections.
pub struct LockGuard<'a>(parking_lot::MutexGuard<'a, Option<rusqlite::Connection>>);

impl<'a> LockGuard<'a> {
  pub(super) fn new(guard: parking_lot::MutexGuard<'a, Option<rusqlite::Connection>>) -> Self {
    return Self(guard);
  }
}

impl Deref for LockGuard<'_> {
  type Target = rusqlite::Connection;

  #[inline]
  fn deref(&self) -> &Self::Target {
    return self.0.as_ref().expect(CLOSED);
  }
}

impl DerefMut for LockGuard<'_> {
  #[inline]
  fn deref_mut(&mut self) -> &mut Self::Target {
    return self.0.as_mut().expect(CLOSED);
  }
}

/// Owned exclusive access to the writer connection, e.g. for a WASM guest transaction.
pub struct ArcLockGuard {
  pub(super) guard: parking_lot::ArcMutexGuard<parking_lot::RawMutex, Option<rusqlite::Connection>>,
}

impl Deref for ArcLockGuard {
  type Target = rusqlite::Connection;

  #[inline]
  fn deref(&self) -> &Self::Target {
    return self.guard.as_ref().expect(CLOSED);
  }
}

impl DerefMut for ArcLockGuard {
  #[inline]
  fn deref_mut(&mut self) -> &mut Self::Target {
    return self.guard.as_mut().expect(CLOSED);
  }
}
