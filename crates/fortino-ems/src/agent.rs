//! The agent's exchanges with one EMS server: probe, register, keepalive, tag report and
//! deregistration.

use std::net::Ipv4Addr;

use fortino_platform::facts::Facts;
use fortino_proto_ems::blob;
use fortino_proto_ems::ids::{EmsSerial, Mac, Tenant, Uid};
use fortino_proto_ems::message::{self, Header, Kind, TagRequest, User};
use fortino_proto_ems::reply::{
    KeepaliveReply, KeyNotes, ProbeReply, Pushed, RegStatus, RegisterReply, TagReply,
};
use fortino_proto_ems::tags::Bits;

use crate::report::{self, Compat};
use crate::store::{Received, Registration, Store, server_key};
use crate::transport::Connection;
use crate::{Error, unix_now};

/// What a keepalive changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Keepalive {
    /// Still registered.
    Kept {
        /// Tags after this keepalive.
        tags: String,
        /// The server wants a new registration (`RENEW_REG`).
        renew: bool,
    },
    /// The server no longer knows this endpoint (`CONT|0`). The local registration was removed
    /// because its serial must not be presented any more.
    Dropped,
}

/// One machine's agent. Holds no per-server state itself: that lives in the [`Store`].
#[derive(Debug)]
pub struct Agent {
    /// Declared compatibility profile.
    pub compat: Compat,
    /// Facts about this machine.
    pub facts: Facts,
    /// Default endpoint UID for new registrations.
    pub uid: Uid,
    /// Registrations.
    pub store: Store,
    /// Debug only: SYSINFO overrides applied to register/keepalive reports. Empty in normal
    /// use; see [`crate::debug_override`].
    pub overrides: std::collections::BTreeMap<String, String>,
}

fn log_notes(what: &str, notes: &KeyNotes) {
    if !notes.refused.is_empty() {
        tracing::warn!(reply = what, keys = ?notes.refused, "EMS sent fields Fortino refuses");
    }
    if !notes.unknown.is_empty() {
        tracing::debug!(reply = what, keys = ?notes.unknown, "EMS sent unknown fields");
    }
}

fn received(slot: &mut Received, pushed: Option<&(String, String)>, compressed: bool) {
    let Some((data, sum)) = pushed else { return };
    let content = if compressed {
        match blob::decode(data, blob::DEFAULT_MAX_INFLATED) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => {
                tracing::warn!(error = %e, "EMS sent an unreadable profile object");
                return;
            }
        }
    } else {
        // UNVERIFIED: whether ONNET/OFFCONF are compressed like the Z fields.
        data.clone()
    };
    slot.content = Some(content);
    slot.checksum = sum.clone();
}

fn apply_pushed(reg: &mut Registration, p: &Pushed) {
    received(&mut reg.conf, p.conf.as_ref(), true);
    received(&mut reg.host_rules, p.host_rules.as_ref(), true);
    received(&mut reg.server_list, p.server_list.as_ref(), true);
    received(&mut reg.on_net, p.on_net.as_ref(), false);
    received(&mut reg.off_net, p.off_net.as_ref(), false);
}

impl Agent {
    /// `IP` and `MAC`: FortiClient reports the default-route interface. `local` (the address
    /// that reached the EMS) is the fallback when no default route is known.
    fn address(&self, local: Ipv4Addr) -> (Ipv4Addr, Mac) {
        let iface = self
            .facts
            .interfaces
            .iter()
            .find(|i| i.gateway.is_some() && !i.is_vpn)
            .or_else(|| self.facts.interfaces.iter().find(|i| i.ip == local));
        match iface {
            Some(i) => (i.ip, Mac(i.mac)),
            None => (local, Mac::default()),
        }
    }

    fn header(&self, uid: &Uid, local: Ipv4Addr, reg: Option<&Registration>) -> Header {
        let (ip, mac) = self.address(local);
        Header {
            uid: uid.clone(),
            version: self.compat.version.clone(),
            serial: reg.and_then(|r| EmsSerial::parse(&r.serial).ok()),
            ip,
            mac,
            on_net: false,
            caps: self.compat.caps,
            vdom: reg.map_or_else(|| "default".to_owned(), |r| r.vdom.clone()),
            quarantined: reg.is_some_and(|r| r.quarantined),
        }
    }

    fn uid_for(&self, reg: &Registration) -> Result<Uid, Error> {
        Uid::parse(&reg.uid).map_err(|_| Error::Store("stored endpoint UID is invalid".into()))
    }

    /// The registration for the connection's server, if any.
    pub fn registration(&self, conn: &Connection) -> Result<Option<Registration>, Error> {
        self.store.load(&server_key(conn.server()))
    }

    /// PROBE: checks that the server is an EMS and reads its serial. Registers nothing.
    pub async fn probe(&self, conn: &Connection) -> Result<ProbeReply, Error> {
        let reply = conn
            .exchange(|ip| {
                message::encode(
                    &self.header(&self.uid, ip, None),
                    Kind::Probe,
                    &message::probe(),
                )
            })
            .await?;
        let p = ProbeReply::from_reply(&reply)?;
        log_notes("probe", &p.notes);
        Ok(p)
    }

    /// PROBE then REGISTER. Creates a device record on the server: call only when the user or
    /// the profile asked for it.
    pub async fn register(
        &self,
        conn: &Connection,
        key: Option<&str>,
    ) -> Result<Registration, Error> {
        let probe = self.probe(conn).await?;
        let sysinfo = report::full(&self.facts, &self.compat, None)?;
        let sysinfo = crate::debug_override::apply(sysinfo, &self.overrides);
        let body = message::register(&sysinfo, key)?;
        let reply = conn
            .exchange(|ip| {
                message::encode(&self.header(&self.uid, ip, None), Kind::Register, &body)
            })
            .await?;
        let rr = RegisterReply::from_reply(&reply)?;
        tracing::debug!(
            rules_field_present = reply.fields.get("ZHVR").is_some(),
            rules_field_populated = rr.pushed.host_rules.is_some(),
            "EMS registration policy fields"
        );
        log_notes("register", &rr.notes);
        let r = match rr.outcome {
            Ok(r) => r,
            Err(status) => {
                let detail = rr.message.map(|m| format!(" ({m})")).unwrap_or_default();
                let reason = format!("{status}{detail}");
                return Err(if status == RegStatus::KeyMismatch {
                    Error::KeyRefused(reason)
                } else {
                    Error::Refused(reason)
                });
            }
        };
        if r.serial != probe.serial {
            return Err(Error::Protocol(
                "server serial changed between probe and register".into(),
            ));
        }
        let uid = match rr.new_uid.as_deref().map(Uid::parse) {
            Some(Ok(u)) => {
                tracing::info!("EMS assigned a new endpoint UID for this server");
                u
            }
            Some(Err(_)) => return Err(Error::Protocol("NEW_GUID is not a UID".into())),
            None => self.uid.clone(),
        };
        let mut reg = Registration {
            server: server_key(conn.server()),
            uid: uid.to_string(),
            serial: r.serial.to_string(),
            host: r.host,
            tenant: None,
            vdom: if r.vdom.is_empty() {
                "default".into()
            } else {
                r.vdom
            },
            ka_interval: r.mini_ka.filter(|s| *s > 0).unwrap_or(60),
            full_ka_interval: r.full_ka.filter(|s| *s > 0).unwrap_or(43_230),
            tags: String::new(),
            rules_sent: String::new(),
            quarantined: false,
            conf: Received::default(),
            host_rules: Received::default(),
            server_list: Received::default(),
            on_net: Received::default(),
            off_net: Received::default(),
            install_uid: self.compat.install_uid.clone(),
            registered_at: unix_now(),
            last_keepalive: None,
        };
        apply_pushed(&mut reg, &rr.pushed);
        self.store.save(&reg)?;
        Ok(reg)
    }

    /// The existing registration for this server, or a new one.
    pub async fn ensure(
        &self,
        conn: &Connection,
        key: Option<&str>,
    ) -> Result<Registration, Error> {
        match self.registration(conn)? {
            Some(r) => Ok(r),
            None => self.register(conn, key).await,
        }
    }

    /// One keepalive. `full` sends the full SYSINFO.
    pub async fn keepalive(&self, conn: &Connection, full: bool) -> Result<Keepalive, Error> {
        let mut reg = self.registration(conn)?.ok_or(Error::NotRegistered)?;
        let uid = self.uid_for(&reg)?;
        let sysinfo = if full {
            report::full(&self.facts, &self.compat, Some(&reg))?
        } else {
            report::mini(&self.facts, Some(&reg))?
        };
        let sysinfo = crate::debug_override::apply(sysinfo, &self.overrides);
        let body = message::keepalive(&sysinfo, &User::default())?;
        let reply = conn
            .exchange(|ip| {
                message::encode(&self.header(&uid, ip, Some(&reg)), Kind::Keepalive, &body)
            })
            .await?;
        let ka = KeepaliveReply::from_reply(&reply)?;
        log_notes("keepalive", &ka.notes);
        if !ka.keep {
            self.store.remove(&reg.server)?;
            return Ok(Keepalive::Dropped);
        }
        if let Some(sn) = &ka.serial {
            if sn.as_str() != reg.serial {
                return Err(Error::Protocol(
                    "keepalive reply names another server".into(),
                ));
            }
        }
        if let Some(t) = &ka.tags {
            reg.tags = t.to_string();
        }
        if let Some(t) = ka.tenant {
            reg.tenant = Some(t.as_str().to_owned());
        }
        if let Some(i) = ka.interval.filter(|i| *i > 0) {
            reg.ka_interval = i;
        }
        if ka.quarantine.is_some() {
            reg.quarantined = true;
        } else if ka.unquarantined {
            reg.quarantined = false;
        }
        apply_pushed(&mut reg, &ka.pushed);
        reg.last_keepalive = Some(unix_now());
        self.store.save(&reg)?;
        Ok(Keepalive::Kept {
            tags: reg.tags,
            renew: ka.renew,
        })
    }

    /// Reports host-verification results (`RULES`) in an `X-FCCK-TAG` and stores the tags the
    /// server returns.
    pub async fn report_rules(&self, conn: &Connection, rules: &Bits) -> Result<String, Error> {
        let mut reg = self.registration(conn)?.ok_or(Error::NotRegistered)?;
        let uid = self.uid_for(&reg)?;
        let serial = EmsSerial::parse(&reg.serial)
            .map_err(|_| Error::Store("stored serial is invalid".into()))?;
        let nwifs = fortino_proto_ems::sysinfo::nwifs(&report::interfaces(&self.facts));
        let reply = conn
            .exchange(|local| {
                let (ip, mac) = self.address(local);
                message::encode_tag(&TagRequest {
                    uid: uid.clone(),
                    version: self.compat.version.clone(),
                    serial: serial.clone(),
                    vdom: reg.vdom.clone(),
                    ip,
                    mac,
                    nwifs: nwifs.clone(),
                    rules: rules.to_string(),
                    caps: self.compat.caps,
                })
            })
            .await?;
        let t = TagReply::from_reply(&reply)?;
        log_notes("tag", &t.notes);
        if let Some(e) = t.error {
            return Err(Error::Refused(e));
        }
        if let Some(tags) = t.tags {
            reg.tags = tags.to_string();
        }
        reg.rules_sent = rules.to_string();
        self.store.save(&reg)?;
        Ok(reg.tags)
    }

    /// Evaluates the stored host-verification rules and reports them if the result changed.
    /// Returns the tags after the report, or `None` when nothing needed sending.
    pub async fn check_host(&self, conn: &Connection) -> Result<Option<String>, Error> {
        let reg = self.registration(conn)?.ok_or(Error::NotRegistered)?;
        let Some(xml) = reg.host_rules.content.as_deref() else {
            return Ok(None);
        };
        let rules =
            fortino_proto_ems::hv::parse(xml).map_err(|e| Error::Protocol(e.to_string()))?;
        let bits = crate::hostcheck::evaluate(&rules, &self.facts);
        if bits.to_string() == reg.rules_sent {
            return Ok(None);
        }
        self.report_rules(conn, &bits).await.map(Some)
    }

    /// Deregisters and removes the local registration. Refused while quarantined.
    pub async fn deregister(&self, conn: &Connection) -> Result<(), Error> {
        let reg = self.registration(conn)?.ok_or(Error::NotRegistered)?;
        if reg.quarantined {
            return Err(Error::Refused("the EMS has quarantined this device".into()));
        }
        let uid = self.uid_for(&reg)?;
        let body = message::deregister(&self.facts.hostname, &uid)?;
        let reply = conn
            .exchange(|ip| {
                message::encode(&self.header(&uid, ip, Some(&reg)), Kind::Keepalive, &body)
            })
            .await?;
        let ka = KeepaliveReply::from_reply(&reply)?;
        if ka.keep {
            return Err(Error::Refused("the EMS kept the registration".into()));
        }
        self.store.remove(&reg.server)?;
        Ok(())
    }

    /// The identity a gateway owned by this EMS gets on SSL VPN requests (`FSV_EMS_SN` and the
    /// tenant header). `None` unless registered to this server.
    pub fn gateway_identity(
        &self,
        conn: &Connection,
    ) -> Result<Option<(EmsSerial, Tenant)>, Error> {
        let Some(reg) = self.registration(conn)? else {
            return Ok(None);
        };
        let serial = EmsSerial::parse(&reg.serial)
            .map_err(|_| Error::Store("stored serial is invalid".into()))?;
        let tenant = reg
            .tenant
            .as_deref()
            .and_then(|t| Tenant::parse(t).ok())
            .unwrap_or_else(Tenant::on_premises);
        Ok(Some((serial, tenant)))
    }
}
