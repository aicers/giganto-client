use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use super::RawEventKind;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Statistics {
    pub core: u32,
    pub period: u16,
    pub stats: Vec<(RawEventKind, u64, u64)>, // protocol, packet count, packet size
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::RawEventKind;

    #[test]
    fn test_statistics_display() {
        let stats = Statistics {
            core: 1,
            period: 60,
            stats: vec![
                (RawEventKind::Dns, 100, 1024),
                (RawEventKind::Http, 200, 2048),
            ],
        };
        let display = format!("{stats}");
        assert_eq!(display, "1\t60\tDns/1024/100,Http/2048/200");
    }
}
