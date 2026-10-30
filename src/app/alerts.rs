use super::{compact_rows, timestamp};
use crate::display_timezone::DisplayTimezone;
use eframe::egui;
use std::{
    collections::VecDeque,
    time::{SystemTime, UNIX_EPOCH},
};

const CAPACITY: usize = 500;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Level {
    Info,
    Error,
}

struct Alert {
    timestamp_ms: u64,
    level: Level,
    source: String,
    message: String,
}

#[derive(Default)]
pub(super) struct Alerts {
    entries: VecDeque<Alert>,
    unread: usize,
    search: String,
    errors_only: bool,
}

impl Alerts {
    pub fn push(&mut self, level: Level, source: &str, message: String) {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.push_at(timestamp_ms, level, source, message);
    }

    pub fn push_at(&mut self, timestamp_ms: u64, level: Level, source: &str, message: String) {
        if self.entries.len() == CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(Alert {
            timestamp_ms,
            level,
            source: source.into(),
            message,
        });
        self.unread = (self.unread + 1).min(CAPACITY);
    }

    pub fn label(&self) -> String {
        if self.unread == 0 {
            "Alerts".into()
        } else {
            format!("Alerts ({})", self.unread)
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.unread = 0;
    }

    pub fn show(&mut self, ui: &mut egui::Ui, timezone: DisplayTimezone) {
        self.unread = 0;
        ui.heading("Alerts");
        ui.horizontal_wrapped(|ui| {
            ui.label("Search");
            ui.text_edit_singleline(&mut self.search);
            ui.checkbox(&mut self.errors_only, "Errors only");
            if ui.button("Clear alerts").clicked() {
                self.clear();
            }
            ui.label(format!("{} / {CAPACITY} alerts", self.entries.len()));
        });
        ui.separator();
        let query = self.search.to_lowercase();
        compact_rows(ui);
        egui::ScrollArea::vertical()
            .id_salt("alerts-log")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for alert in self.entries.iter().rev().filter(|alert| {
                    (!self.errors_only || alert.level == Level::Error)
                        && (query.is_empty()
                            || alert.source.to_lowercase().contains(&query)
                            || alert.message.to_lowercase().contains(&query))
                }) {
                    ui.horizontal_top(|ui| {
                        let text = timestamp(alert.timestamp_ms, timezone);
                        ui.label(super::theme::timestamp_text(
                            ui,
                            &text,
                            egui::TextStyle::Monospace.resolve(ui.style()),
                            ui.visuals().text_color(),
                        ));
                        let (label, color) = match alert.level {
                            Level::Info => ("Info", ui.visuals().hyperlink_color),
                            Level::Error => ("Error", ui.visuals().error_fg_color),
                        };
                        ui.colored_label(color, label);
                        ui.strong(&alert.source);
                        ui.add(egui::Label::new(&alert.message).wrap());
                    });
                    ui.separator();
                }
                if self.entries.is_empty() {
                    ui.label("No alerts.");
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_errors_are_retained_and_old_entries_are_bounded() {
        let mut alerts = Alerts::default();
        for index in 0..CAPACITY + 2 {
            alerts.push_at(
                index as u64,
                Level::Error,
                "Connection",
                "Repeated failure".into(),
            );
        }
        assert_eq!(alerts.entries.len(), CAPACITY);
        assert_eq!(alerts.entries.front().unwrap().timestamp_ms, 2);
        assert_eq!(
            alerts.entries.back().unwrap().timestamp_ms,
            (CAPACITY + 1) as u64
        );
        assert_eq!(alerts.unread, CAPACITY);
        alerts.clear();
        assert!(alerts.entries.is_empty());
        assert_eq!(alerts.label(), "Alerts");
    }
}
