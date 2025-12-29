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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_periodic_time_series_display() {
        let pts = PeriodicTimeSeries {
            id: "test".to_string(),
            data: vec![1.0, 2.0, 3.0],
        };
        assert_eq!(format!("{pts}"), "[1.0, 2.0, 3.0]");
    }

    #[test]
    fn test_periodic_time_series_response_data() {
        let pts = PeriodicTimeSeries {
            id: "test".to_string(),
            data: vec![1.0, 2.0, 3.0],
        };
        let res = pts.response_data(100, "sensor").unwrap();
        let decoded: Option<(i64, String, Vec<f64>)> = bincode::deserialize(&res).unwrap();
        let (timestamp, sensor, data) = decoded.unwrap();
        assert_eq!(timestamp, 100);
        assert_eq!(sensor, "sensor");
        assert_eq!(data, vec![1.0, 2.0, 3.0]);
    }
}
