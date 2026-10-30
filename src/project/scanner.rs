use super::*;
use crate::scanner::{Finding, ScanJob, ScanStatus};

const JOBS: TableDefinition<u64, &[u8]> = TableDefinition::new("scanner_jobs");
const FINDINGS: TableDefinition<u64, &[u8]> = TableDefinition::new("scanner_findings");

impl Project {
    pub(super) fn load_scanner(&mut self) -> Result<()> {
        let Some(db) = &self.db else {
            return Ok(());
        };
        let tx = db.begin_write()?;
        tx.open_table(JOBS)?;
        tx.open_table(FINDINGS)?;
        tx.commit()?;
        {
            let tx = db.begin_read()?;
            for item in tx.open_table(JOBS)?.iter()? {
                let (key, value) = item?;
                let job: ScanJob = serde_json::from_slice(value.value())?;
                job.settings.validate()?;
                self.scan_jobs.insert(key.value(), job);
            }
            for item in tx.open_table(FINDINGS)?.iter()? {
                let (key, value) = item?;
                self.findings
                    .insert(key.value(), serde_json::from_slice(value.value())?);
            }
        }
        let interrupted: Vec<_> = self
            .scan_jobs
            .values()
            .filter(|j| j.status.unfinished())
            .cloned()
            .collect();
        for mut job in interrupted {
            job.status = ScanStatus::Interrupted;
            job.message =
                "Scan interrupted when the project was closed; resume explicitly to continue"
                    .into();
            job.updated_ms = crate::scanner::now();
            for item in &mut job.items {
                if item.status.unfinished() {
                    item.status = ScanStatus::Interrupted;
                }
            }
            self.put_scan_job(job)?;
        }
        Ok(())
    }
    pub fn allocate_scan_id(&self) -> u64 {
        self.scan_jobs
            .last_key_value()
            .map_or(1, |(id, _)| id.saturating_add(1))
    }
    pub fn scan_jobs(&self) -> Vec<ScanJob> {
        self.scan_jobs.values().rev().cloned().collect()
    }
    pub fn scan_job(&self, id: u64) -> Option<ScanJob> {
        self.scan_jobs.get(&id).cloned()
    }
    pub fn put_scan_job(&mut self, job: ScanJob) -> Result<()> {
        job.settings.validate()?;
        if let Some(db) = &self.db {
            let bytes = serde_json::to_vec(&job)?;
            let tx = db.begin_write()?;
            tx.open_table(JOBS)?.insert(job.id, bytes.as_slice())?;
            tx.commit()?;
        }
        self.scan_jobs.insert(job.id, job);
        Ok(())
    }
    pub fn findings(&self) -> Vec<Finding> {
        self.findings.values().rev().cloned().collect()
    }
    pub fn finding_count(&self, scan_id: Option<u64>) -> usize {
        self.findings
            .values()
            .filter(|f| scan_id.is_none_or(|id| f.scan_ids.contains(&id)))
            .count()
    }
    pub fn finding(&self, id: u64) -> Option<Finding> {
        self.findings.get(&id).cloned()
    }
    pub fn put_finding(&mut self, finding: Finding) -> Result<()> {
        if let Some(db) = &self.db {
            let bytes = serde_json::to_vec(&finding)?;
            let tx = db.begin_write()?;
            tx.open_table(FINDINGS)?
                .insert(finding.id, bytes.as_slice())?;
            tx.commit()?;
        }
        self.findings.insert(finding.id, finding);
        Ok(())
    }
    pub fn upsert_finding(&mut self, mut incoming: Finding) -> Result<Finding> {
        fn location(f: &Finding) -> String {
            url::Url::parse(&f.url)
                .map(|mut u| {
                    u.set_query(None);
                    u.set_fragment(None);
                    u.to_string()
                })
                .unwrap_or_else(|_| f.url.clone())
        }
        let existing = self
            .findings
            .values()
            .find(|f| {
                f.issue_id == incoming.issue_id
                    && f.method == incoming.method
                    && f.insertion_point == incoming.insertion_point
                    && location(f) == location(&incoming)
            })
            .cloned();
        if let Some(mut finding) = existing {
            finding.last_seen_ms = incoming.last_seen_ms;
            finding.occurrences = finding.occurrences.saturating_add(1);
            finding.confidence = finding.confidence.max(incoming.confidence);
            for origin in incoming.origins {
                if !finding.origins.contains(&origin) {
                    finding.origins.push(origin);
                }
            }
            for id in incoming.scan_ids {
                if !finding.scan_ids.contains(&id) {
                    finding.scan_ids.push(id);
                }
            }
            for evidence in incoming.evidence {
                finding.evidence.push(evidence);
            }
            self.put_finding(finding.clone())?;
            Ok(finding)
        } else {
            incoming.id = self
                .findings
                .last_key_value()
                .map_or(1, |(id, _)| id.saturating_add(1));
            self.put_finding(incoming.clone())?;
            Ok(incoming)
        }
    }
    pub(super) fn copy_scanner(&self, dest: &mut Project) -> Result<()> {
        for job in self.scan_jobs.values() {
            dest.put_scan_job(job.clone())?;
        }
        for finding in self.findings.values() {
            dest.put_finding(finding.clone())?;
        }
        Ok(())
    }
}
