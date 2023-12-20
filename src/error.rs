use core::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug)]
pub struct MessageTooLong;

impl Display for MessageTooLong {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("Message too long to be processed by the SHA2 algorithm!")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MessageTooLong {}
