//! Application-wide appearance and CA identity, independent of project files.
use crate::{
    display_timezone::DisplayTimezone, model::ColorScheme, project::Project, tls::Authority,
};
use anyhow::{Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
struct Stored {
    color_scheme: ColorScheme,
    ca_key: Vec<u8>,
    #[serde(default)]
    timezone: DisplayTimezone,
}

pub struct Preferences {
    path: PathBuf,
    stored: Stored,
}

impl Preferences {
    pub fn load(project: &Project) -> Result<Self> {
        let dir = dirs::config_dir()
            .context("Cannot locate the application configuration directory")?
            .join("ferrite");
        Self::load_at(&dir.join("settings.json"), project)
    }

    pub fn load_at(path: &Path, project: &Project) -> Result<Self> {
        Self::with_lock(path, || {
            if path.exists() {
                return Self::read(path);
            }
            let stored = Stored {
                color_scheme: project.workspace.color_scheme,
                timezone: DisplayTimezone::default(),
                ca_key: match project.ca_key() {
                    Some(key) => key,
                    None => Authority::generate_key()?,
                },
            };
            Authority::from_key(&stored.ca_key).context("Invalid CA key in initial project")?;
            let preferences = Self {
                path: path.to_owned(),
                stored,
            };
            preferences.write(false)?;
            Ok(preferences)
        })
    }

    fn with_lock<T>(path: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
        let dir = path.parent().context("Settings file has no parent")?;
        std::fs::create_dir_all(dir)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(dir.join("settings.lock"))?;
        lock.lock_exclusive()?;
        action()
    }

    fn read(path: &Path) -> Result<Self> {
        let stored: Stored = serde_json::from_reader(std::fs::File::open(path)?)
            .with_context(|| format!("Read settings {}", path.display()))?;
        Authority::from_key(&stored.ca_key).context("Invalid saved CA key")?;
        Ok(Self {
            path: path.to_owned(),
            stored,
        })
    }

    fn write(&self, replace: bool) -> Result<()> {
        let dir = self.path.parent().context("Settings file has no parent")?;
        std::fs::create_dir_all(dir)?;
        let mut temp = tempfile::NamedTempFile::new_in(dir)?;
        serde_json::to_writer(&mut temp, &self.stored)?;
        temp.flush()?;
        temp.as_file().sync_all()?;
        if replace {
            temp.persist(&self.path)?;
        } else {
            temp.persist_noclobber(&self.path)?;
        }
        Ok(())
    }

    pub fn scheme(&self) -> ColorScheme {
        self.stored.color_scheme
    }
    pub fn ca_key(&self) -> &[u8] {
        &self.stored.ca_key
    }
    pub fn timezone(&self) -> DisplayTimezone {
        self.stored.timezone
    }
    pub fn set_timezone(&mut self, timezone: DisplayTimezone) -> Result<()> {
        let updated = Self::with_lock(&self.path, || {
            let mut latest = Self::read(&self.path)?;
            latest.stored.timezone = timezone;
            latest.write(true)?;
            Ok(latest.stored)
        })?;
        self.stored = updated;
        Ok(())
    }
    pub fn set_scheme(&mut self, scheme: ColorScheme) -> Result<()> {
        let updated = Self::with_lock(&self.path, || {
            let mut latest = Self::read(&self.path)?;
            latest.stored.color_scheme = scheme;
            latest.write(true)?;
            Ok(latest.stored)
        })?;
        self.stored = updated;
        Ok(())
    }
    pub fn regenerate_ca(&mut self) -> Result<Authority> {
        let key = Authority::generate_key()?;
        let authority = Authority::from_key(&key)?;
        let updated = Self::with_lock(&self.path, || {
            let mut latest = Self::read(&self.path)?;
            latest.stored.ca_key = key;
            latest.write(true)?;
            Ok(latest.stored)
        })?;
        self.stored = updated;
        Ok(authority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn app_settings_keep_ca_and_theme_across_projects_and_regeneration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let mut legacy = Project::temporary();
        legacy.workspace.color_scheme = ColorScheme::PaleBlue;
        let legacy_ca = Authority::load(&mut legacy).unwrap().fingerprint();
        let mut preferences = Preferences::load_at(&path, &legacy).unwrap();
        assert_eq!(preferences.timezone(), DisplayTimezone::Utc);
        preferences
            .set_timezone(DisplayTimezone::Named(chrono_tz::Australia::Sydney))
            .unwrap();
        assert_eq!(preferences.scheme(), ColorScheme::PaleBlue);
        assert_eq!(
            Authority::from_key(preferences.ca_key())
                .unwrap()
                .fingerprint(),
            legacy_ca
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        preferences.set_scheme(ColorScheme::Nord).unwrap();
        let engine = Engine::new_with_key(Project::temporary(), preferences.ca_key()).unwrap();
        let old_config = engine.authority.server_config("example.test").unwrap();
        let reloaded = Preferences::load_at(&path, &Project::temporary()).unwrap();
        assert_eq!(reloaded.scheme(), ColorScheme::Nord);
        assert_eq!(
            reloaded.timezone(),
            DisplayTimezone::Named(chrono_tz::Australia::Sydney)
        );
        assert_eq!(
            Authority::from_key(reloaded.ca_key())
                .unwrap()
                .fingerprint(),
            legacy_ca
        );
        let replacement = preferences.regenerate_ca().unwrap();
        let new_fingerprint = replacement.fingerprint();
        assert_ne!(new_fingerprint, legacy_ca);
        engine.authority.replace(replacement);
        assert!(!std::sync::Arc::ptr_eq(
            &old_config,
            &engine.authority.server_config("example.test").unwrap()
        ));
        let reloaded = Preferences::load_at(&path, &legacy).unwrap();
        assert_eq!(
            reloaded.timezone(),
            DisplayTimezone::Named(chrono_tz::Australia::Sydney)
        );
        assert_eq!(reloaded.scheme(), ColorScheme::Nord);
        assert_eq!(
            Authority::from_key(reloaded.ca_key())
                .unwrap()
                .fingerprint(),
            new_fingerprint
        );
        assert_eq!(
            Engine::new_with_key(Project::temporary(), reloaded.ca_key())
                .unwrap()
                .authority
                .fingerprint(),
            new_fingerprint
        );
    }

    #[test]
    fn invalid_settings_do_not_silently_replace_the_ca() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "broken").unwrap();
        assert!(Preferences::load_at(&path, &Project::temporary()).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "broken");
    }

    #[test]
    fn old_application_settings_default_to_utc_and_updates_preserve_other_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let project = Project::temporary();
        let old = Preferences::load_at(&path, &project).unwrap();
        let fingerprint = Authority::from_key(old.ca_key()).unwrap().fingerprint();
        let mut saved = serde_json::to_value(&old.stored).unwrap();
        saved.as_object_mut().unwrap().remove("timezone");
        std::fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        let mut first = Preferences::load_at(&path, &project).unwrap();
        let mut second = Preferences::load_at(&path, &project).unwrap();
        assert_eq!(first.timezone(), DisplayTimezone::Utc);
        first
            .set_timezone(DisplayTimezone::Named(chrono_tz::Asia::Kolkata))
            .unwrap();
        second.set_scheme(ColorScheme::Light).unwrap();
        let reloaded = Preferences::load_at(&path, &Project::temporary()).unwrap();
        assert_eq!(
            reloaded.timezone(),
            DisplayTimezone::Named(chrono_tz::Asia::Kolkata)
        );
        assert_eq!(reloaded.scheme(), ColorScheme::Light);
        assert_eq!(
            Authority::from_key(reloaded.ca_key())
                .unwrap()
                .fingerprint(),
            fingerprint
        );
    }
}
