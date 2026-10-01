//! Bounded, one-use admission tickets. Only the private API may mint these.
use anyhow::{Result, bail};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const PREFACE: &[u8; 4] = b"TMX1";
pub const TICKET_TTL: Duration = Duration::from_secs(60);
const MAX_TICKETS: usize = 1024;

#[derive(Serialize)]
pub struct AdmissionTicket {
    pub ticket: String,
    pub expires_in: u64,
}
struct Ticket {
    subject: String,
    expires: Instant,
}
#[derive(Default)]
struct State {
    tickets: HashMap<[u8; 32], Ticket>,
    active: HashMap<String, usize>,
    peers: HashMap<IpAddr, usize>,
}
#[derive(Clone, Default)]
pub struct Admission {
    state: Arc<Mutex<State>>,
}

impl Admission {
    pub fn issue(&self, subject: String) -> Result<AdmissionTicket> {
        self.issue_at(subject, Instant::now())
    }
    fn issue_at(&self, subject: String, now: Instant) -> Result<AdmissionTicket> {
        if subject.is_empty() || subject.len() > 128 {
            bail!("invalid subject");
        }
        let mut state = self.state.lock().unwrap();
        state.tickets.retain(|_, t| t.expires > now);
        if state.tickets.len() >= MAX_TICKETS
            || state.active.contains_key(&subject)
            || state.tickets.values().any(|t| t.subject == subject)
        {
            bail!("admission capacity unavailable");
        }
        let mut token = rand::random::<[u8; 32]>();
        while state.tickets.contains_key(&token) {
            token = rand::random();
        }
        state.tickets.insert(
            token,
            Ticket {
                subject,
                expires: now + TICKET_TTL,
            },
        );
        Ok(AdmissionTicket {
            ticket: hex::encode(token),
            expires_in: TICKET_TTL.as_secs(),
        })
    }
    pub fn consume(&self, token: [u8; 32]) -> Result<SubjectPermit> {
        self.consume_at(token, Instant::now())
    }
    fn consume_at(&self, token: [u8; 32], now: Instant) -> Result<SubjectPermit> {
        let mut state = self.state.lock().unwrap();
        let Some(ticket) = state.tickets.remove(&token) else {
            bail!("invalid admission");
        };
        if ticket.expires <= now || state.active.contains_key(&ticket.subject) {
            bail!("invalid admission");
        }
        state.active.insert(ticket.subject.clone(), 1);
        Ok(SubjectPermit {
            state: self.state.clone(),
            subject: ticket.subject,
        })
    }
    /// Tracks only live connections; addresses never accumulate after disconnect.
    pub fn peer(&self, ip: IpAddr, max: usize) -> Option<PeerPermit> {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        let mut state = self.state.lock().unwrap();
        let count = state.peers.entry(ip).or_default();
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(PeerPermit {
            state: self.state.clone(),
            ip,
        })
    }
}
pub struct SubjectPermit {
    state: Arc<Mutex<State>>,
    subject: String,
}
impl Drop for SubjectPermit {
    fn drop(&mut self) {
        self.state.lock().unwrap().active.remove(&self.subject);
    }
}
pub struct PeerPermit {
    state: Arc<Mutex<State>>,
    ip: IpAddr,
}
impl Drop for PeerPermit {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        if let Some(count) = state.peers.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                state.peers.remove(&self.ip);
            }
        }
    }
}

/// Limits task creation under fast connection churn without an address cache.
pub(crate) struct StartBudget {
    available: f64,
    updated: Instant,
}
impl StartBudget {
    pub fn new() -> Self {
        Self {
            available: 64.0,
            updated: Instant::now(),
        }
    }
    pub fn take(&mut self, now: Instant) -> bool {
        self.available = (self.available
            + now.saturating_duration_since(self.updated).as_secs_f64() * 64.0)
            .min(64.0);
        self.updated = now;
        if self.available < 1.0 {
            return false;
        }
        self.available -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn token(t: &AdmissionTicket) -> [u8; 32] {
        hex::decode(&t.ticket).unwrap().try_into().unwrap()
    }
    #[test]
    fn connection_churn_has_a_global_fixed_memory_budget() {
        let mut budget = StartBudget::new();
        let now = budget.updated;
        for _ in 0..64 {
            assert!(budget.take(now));
        }
        for _ in 0..1000 {
            assert!(!budget.take(now));
        }
        assert!(budget.take(now + Duration::from_secs(1)));
        for _ in 0..63 {
            assert!(budget.take(now + Duration::from_secs(1)));
        }
        assert!(!budget.take(now + Duration::from_secs(1)));
    }

    #[test]
    fn tickets_are_single_use_and_subject_limited() {
        let gate = Admission::default();
        let ticket = gate.issue("alice".into()).unwrap();
        assert!(gate.issue("alice".into()).is_err());
        let permit = gate.consume(token(&ticket)).unwrap();
        assert!(gate.consume(token(&ticket)).is_err());
        assert!(gate.issue("alice".into()).is_err());
        drop(permit);
        assert!(gate.issue("alice".into()).is_ok());
    }
    #[test]
    fn expired_tickets_cannot_authorize_and_capacity_is_reclaimed() {
        let gate = Admission::default();
        let now = Instant::now();
        let ticket = gate.issue_at("alice".into(), now).unwrap();
        assert!(gate.consume_at(token(&ticket), now + TICKET_TTL).is_err());
        for i in 0..MAX_TICKETS {
            gate.issue_at(i.to_string(), now).unwrap();
        }
        assert!(gate.issue_at("overflow".into(), now).is_err());
        assert!(gate.issue_at("renewed".into(), now + TICKET_TTL).is_ok());
        assert_eq!(gate.state.lock().unwrap().tickets.len(), 1);
    }
    #[test]
    fn invalid_ticket_and_subject_do_not_allocate_state() {
        let gate = Admission::default();
        assert!(gate.consume([0; 32]).is_err());
        assert!(gate.issue(String::new()).is_err());
        assert!(gate.issue("x".repeat(129)).is_err());
        assert!(gate.state.lock().unwrap().tickets.is_empty());
    }
    #[test]
    fn per_ip_limit_normalizes_mapped_ipv4_and_releases_state() {
        let gate = Admission::default();
        let permit = gate.peer("127.0.0.1".parse().unwrap(), 1).unwrap();
        assert!(gate.peer("::ffff:127.0.0.1".parse().unwrap(), 1).is_none());
        let other = gate.peer("127.0.0.2".parse().unwrap(), 1).unwrap();
        drop((permit, other));
        assert!(gate.state.lock().unwrap().peers.is_empty());
    }
}
