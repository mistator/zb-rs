use embassy_time::Duration;


pub const fn from_octets(octets: u64) -> Duration {
    Duration::from_millis(octets * (8 / 250))
}

#[macro_export]
macro_rules! unwrap_or_return {
    ($e:expr, $default:expr) => {
        match $e {
            Some(val) => val,
            None => return $default,
        }
    };
    ($e: expr) => {
        match $e {
            Some(val) => val,
            None => return,
        }
    };
}

#[macro_export]
macro_rules! unwrap_or {
    ($e:expr, $or:expr) => {
        match $e {
            Some(value) => value,
            None => $or,
        }
    };
}
