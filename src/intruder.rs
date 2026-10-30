use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackType {
    #[default]
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Attack {
    pub destination: String,
    pub template: String,
    pub kind: AttackType,
    pub payload_sets: Vec<Vec<String>>,
    pub concurrency: usize,
    pub delay_ms: u64,
}

pub async fn run(
    engine: std::sync::Arc<crate::engine::Engine>,
    attack: Attack,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) -> Result<usize> {
    let destination = crate::model::Destination::from_url(&attack.destination)?;
    let concurrency = attack.concurrency;
    let delay = std::time::Duration::from_millis(attack.delay_ms);
    let plan = Plan::new(attack)?;
    let mut tasks = tokio::task::JoinSet::new();
    let mut next = 0;
    let mut completed = 0;
    let mut next_start = tokio::time::Instant::now();
    loop {
        if *cancel.borrow() {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            return Ok(completed);
        }
        if next == plan.count && tasks.is_empty() {
            return Ok(completed);
        }
        tokio::select! {
            result = cancel.changed() => {
                if result.is_err() || *cancel.borrow() {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Ok(completed);
                }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = result { result??; completed += 1; }
            }
            _ = tokio::time::sleep_until(next_start), if next < plan.count && tasks.len() < concurrency => {
                let message = crate::http::from_editor(&plan.request(next)?)?;
                let engine = engine.clone();
                let destination = destination.clone();
                let tool = format!("Intruder #{}", next + 1);
                tasks.spawn(async move { engine.execute(message, destination, &tool, false).await });
                next += 1;
                next_start = tokio::time::Instant::now() + delay;
            }
        }
    }
}
impl Default for Attack {
    fn default() -> Self {
        Self {
            destination: "https://example.com".into(),
            template: "GET /?q=§test§ HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
            kind: AttackType::Sniper,
            payload_sets: vec![vec!["one".into(), "two".into()]],
            concurrency: 5,
            delay_ms: 0,
        }
    }
}
/// Lazy index-based generation: cluster-bomb combinations never become a huge allocation.
pub struct Plan {
    parts: Vec<String>,
    originals: Vec<String>,
    attack: Attack,
    pub count: usize,
}
impl Plan {
    pub fn new(attack: Attack) -> Result<Self> {
        let parts: Vec<String> = attack.template.split('§').map(str::to_string).collect();
        ensure!(
            parts.len() >= 3 && parts.len() % 2 == 1,
            "Use paired § markers around at least one position"
        );
        let originals = parts.iter().skip(1).step_by(2).cloned().collect::<Vec<_>>();
        let n = originals.len();
        ensure!(n <= 20, "Maximum 20 payload positions");
        ensure!(
            (1..=128).contains(&attack.concurrency),
            "Concurrency must be 1..128"
        );
        let sets = &attack.payload_sets;
        let multi = matches!(attack.kind, AttackType::Pitchfork | AttackType::ClusterBomb);
        ensure!(
            sets.len() >= if multi { n } else { 1 },
            "Provide one payload set per position"
        );
        ensure!(
            sets.iter()
                .take(if multi { n } else { 1 })
                .all(|s| !s.is_empty()),
            "Payload sets cannot be empty"
        );
        let count = match attack.kind {
            AttackType::Sniper => sets[0].len().checked_mul(n),
            AttackType::BatteringRam => Some(sets[0].len()),
            AttackType::Pitchfork => sets.iter().take(n).map(Vec::len).min(),
            AttackType::ClusterBomb => sets
                .iter()
                .take(n)
                .try_fold(1usize, |acc, s| acc.checked_mul(s.len())),
        }
        .ok_or_else(|| anyhow::anyhow!("Attack size overflows this platform"))?;
        Ok(Self {
            parts,
            originals,
            attack,
            count,
        })
    }
    pub fn request(&self, index: usize) -> Result<String> {
        ensure!(index < self.count, "Payload index out of range");
        let mut selected = self.originals.clone();
        let sets = &self.attack.payload_sets;
        match self.attack.kind {
            AttackType::Sniper => {
                selected[index / sets[0].len()] = sets[0][index % sets[0].len()].clone()
            }
            AttackType::BatteringRam => selected.fill(sets[0][index].clone()),
            AttackType::Pitchfork => {
                for (i, value) in selected.iter_mut().enumerate() {
                    *value = sets[i][index].clone();
                }
            }
            AttackType::ClusterBomb => {
                let mut rem = index;
                for i in (0..selected.len()).rev() {
                    selected[i] = sets[i][rem % sets[i].len()].clone();
                    rem /= sets[i].len();
                }
            }
        }
        let mut out = self.parts[0].clone();
        for (i, value) in selected.iter().enumerate() {
            out.push_str(value);
            out.push_str(&self.parts[2 * i + 2]);
        }
        Ok(out)
    }
}
