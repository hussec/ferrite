//! Display-only timezone conversion. Captured timestamps remain Unix milliseconds.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisplayTimezone {
    #[default]
    Utc,
    Local,
    Named(chrono_tz::Tz),
}

impl DisplayTimezone {
    pub fn label(self) -> &'static str {
        match self {
            Self::Utc => "UTC",
            Self::Local => "System local",
            Self::Named(zone) => zone.name(),
        }
    }

    pub fn format(self, milliseconds: u64) -> String {
        let Some(date) = i64::try_from(milliseconds)
            .ok()
            .and_then(chrono::DateTime::from_timestamp_millis)
        else {
            return milliseconds.to_string();
        };
        match self {
            Self::Utc => date.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string(),
            Self::Local => date
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S%.3f %Z")
                .to_string(),
            Self::Named(zone) => date
                .with_timezone(&zone)
                .format("%Y-%m-%d %H:%M:%S%.3f %Z")
                .to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_zones_apply_historical_daylight_saving_and_date_rollovers() {
        let winter = chrono::DateTime::parse_from_rfc3339("2026-07-01T00:00:00.123Z")
            .unwrap()
            .timestamp_millis() as u64;
        let summer = chrono::DateTime::parse_from_rfc3339("2026-12-01T00:00:00.123Z")
            .unwrap()
            .timestamp_millis() as u64;
        let sydney = DisplayTimezone::Named(chrono_tz::Australia::Sydney);
        assert_eq!(sydney.format(winter), "2026-07-01 10:00:00.123 AEST");
        assert_eq!(sydney.format(summer), "2026-12-01 11:00:00.123 AEDT");
        assert_eq!(
            DisplayTimezone::Utc.format(summer),
            "2026-12-01 00:00:00.123 UTC"
        );
        assert_eq!(
            DisplayTimezone::Named(chrono_tz::Asia::Kolkata).format(summer),
            "2026-12-01 05:30:00.123 IST"
        );
        assert_eq!(
            DisplayTimezone::Named(chrono_tz::America::New_York).format(summer),
            "2026-11-30 19:00:00.123 EST"
        );
        assert_eq!(DisplayTimezone::Utc.format(u64::MAX), u64::MAX.to_string());
    }
}
