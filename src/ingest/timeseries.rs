use std::fmt::{Display, Formatter};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::publish::range::ResponseRangeData;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PeriodicTimeSeries {
    pub id: String,
    pub data: Vec<f64>,
}

impl Display for PeriodicTimeSeries {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.data)
    }
}

impl ResponseRangeData for PeriodicTimeSeries {
    fn response_data(&self, timestamp: i64, sensor: &str) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(&Some((timestamp, sensor, &self.data)))
    }
    fn response_done() -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize::<Option<(i64, String, Vec<f64>)>>(&None)
    }
}
