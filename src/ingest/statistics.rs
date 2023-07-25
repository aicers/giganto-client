use super::RecordType;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Statistics {
    pub core: u32,
    pub period: u16,
    pub stats: Vec<(RecordType, u64, u64)>, // protocol, packet count, packet size
}

impl Display for Statistics {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let stats = self
            .stats
            .iter()
            .map(|(rt, cnt, size)| format!("{rt:?}/{size}/{cnt}"))
            .collect::<Vec<_>>();
        write!(f, "{}\t{}\t{}", self.core, self.period, stats.join(","))
    }
}
