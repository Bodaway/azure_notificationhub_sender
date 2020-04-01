// ParsingError
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct ParsingError {
    details: String
}

impl ParsingError {
    pub fn new(msg: &str) -> ParsingError {
        ParsingError{details: msg.to_string()}
    }
    pub fn from_string(msg: String) -> ParsingError {
        ParsingError{details: msg}
    }
}

impl fmt::Display for ParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.details)
    }
}

impl Error for ParsingError {
    fn description(&self) -> &str {
        &self.details
    }
}

// SendingError

#[derive(Debug)]
pub struct SendingError {
    details: String
}

impl SendingError {
    pub fn new(msg: &str) -> SendingError {
        SendingError{details: msg.to_string()}
    }
    pub fn from_string(msg: String) -> SendingError {
        SendingError{details: msg}
    }
}

impl fmt::Display for SendingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.details)
    }
}

impl Error for SendingError {
    fn description(&self) -> &str {
        &self.details
    }
}