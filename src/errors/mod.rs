use std;

#[derive(Debug)]
pub struct DbError {
    reason: String,
}

impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self {
        Self {
            reason: e.to_string(),
        }
    }
}

impl From<String> for DbError {
    fn from(s: String) -> Self {
        Self { reason: s }
    }
}

impl Clone for DbError {
    fn clone(&self) -> Self {
        Self {
            reason: self.reason.clone(),
        }
    }
}

pub type Result<T> = std::result::Result<T, DbError>;
