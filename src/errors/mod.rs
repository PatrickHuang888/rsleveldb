use std;

#[derive(Debug)]
pub enum DbError {
    IoError(String),
}

impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, DbError>;
