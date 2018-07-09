//! Error and Result module

use serde_json;
use std::{io, result};

pub type Result<T> = result::Result<T, Error>;

// General error the crate
#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Invalid header protocol")]
    InvalidHeader,
    #[fail(display = "IO error: {}", _0)]
    IoError(#[cause] io::Error),
    #[fail(display = "deserializing JSON error: {}", _0)]
    JError(#[cause] serde_json::error::Error),
}

impl From<io::Error> for Error {
    fn from(other: io::Error) -> Error {
        Error::IoError(other)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(other: serde_json::error::Error) -> Error {
        Error::JError(other)
    }
}
