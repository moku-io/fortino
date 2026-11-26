#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The agent against the mock EMS: registration per server, keepalives, tags, deregistration.

use fortino_config::EmsServer;
use fortino_ems::{Agent, Connection, Error, Keepalive, Store};
use fortino_mock::ems::{self, EmsScenario, MockEms, RuleTag};
use fortino_platform::facts::{Facts, Interface};
use fortino_proto_ems::ids::Uid;
use fortino_proto_ems::message::SIZE_DELTA;
use fortino_proto_ems::tags::Bits;
use fortino_tls::Trust;

/// Rule 1 matches the agent's synthetic macOS 15.6 and grants tag 8; rule 2 needs a sandbox
/// Fortino doesn't have and must never match, even negated.
const HV: &str = "<forticlient_configuration><host_verification>\
<max_tag_flag>9</max_tag_flag><max_rule_flag>2</max_rule_flag><rules>\
<rule><rule_flag>1</rule_flag><name>os</name><os>mac</os><criteria><feature>os_version</feature>\
<criterion><content>macOS Sequoia</content><negative>0</negative><operator>=</operator></criterion></criteria>\
<tag><tag_name>OS-OK</tag_name><tag_flag>8</tag_flag></tag></rule>\
<rule><rule_flag>2</rule_flag><name>sb</name><os>mac</os><criteria><feature>sandbox</feature>\
<criterion><content>x</content><negative>1</negative><operator/></criterion></criteria>\
<tag><tag_name>SB</tag_name><tag_flag>9</tag_flag></tag></rule>\
</rules></host_verification></forticlient_configuration>";

fn agent(dir: &std::path::Path) -> Agent {
    Agent {
        compat: Default::default(),
        facts: Facts {
            hostname: "mac-01".into(),
            os_version: "macOS 15.6".into(),
            arch: "ARM",
            interfaces: vec![Interface {
                name: "lo0".into(),
                ip: "127.0.0.1".parse().unwrap(),
                mac: [0xaa, 0, 0, 0, 0, 1],
                gateway: None,
                up: true,
                is_vpn: false,
            }],
            ..Facts::default()
        },
        uid: Uid::parse("0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9").unwrap(),
        store: Store::open(dir).unwrap(),
        overrides: Default::default(),
    }
}

fn conn(m: &MockEms, name: &str) -> Connection {
    let server: EmsServer = format!("{name}:8013").parse().unwrap();
    Connection::new(server, &Trust::Roots(vec![m.handle.cert_der.clone()]))
        .unwrap()
        .connect_to(m.handle.addr)
}

#[tokio::test]
async fn register_keepalive_tag_deregister() {
    let sc = EmsScenario {
        key: Some("k3y".into()),
        host_rules: Some(HV.into()),
        rule_tags: vec![RuleTag { rule: 1, tag: 8 }, RuleTag { rule: 2, tag: 9 }],
        ..EmsScenario::default()
    };
    let m = ems::start(&sc).await.unwrap();
    let d = tempfile::tempdir().unwrap();
    let a = agent(d.path());
    let c = conn(&m, "ems.test");

    let p = a.probe(&c).await.unwrap();
    assert_eq!(p.serial.as_str(), "FCTEMS0000000001");
    assert!(
        a.registration(&c).unwrap().is_none(),
        "probe registers nothing"
    );

    match a.register(&c, Some("wrong")).await {
        Err(Error::KeyRefused(m)) => assert!(m.contains("key")),
        other => panic!("{other:?}"),
    }
    let reg = a.register(&c, Some("k3y")).await.unwrap();
    assert_eq!(reg.serial, "FCTEMS0000000001");
    assert_eq!(reg.host_rules.content.as_deref(), Some(HV));
    assert_eq!(reg.host_rules.checksum, ems::rules_checksum(HV));
    assert!(a.gateway_identity(&c).unwrap().is_some());

    assert_eq!(
        a.keepalive(&c, true).await.unwrap(),
        Keepalive::Kept {
            tags: "0000000000".into(),
            renew: false
        }
    );
    if cfg!(target_os = "macos") {
        assert_eq!(
            a.check_host(&c).await.unwrap().as_deref(),
            Some("0000000010")
        );
        assert_eq!(
            a.check_host(&c).await.unwrap(),
            None,
            "unchanged rules are not resent"
        );
    } else {
        let mut rules = Bits::zeros(3);
        rules.set(1, true);
        assert_eq!(a.report_rules(&c, &rules).await.unwrap(), "0000000010");
    }
    assert_eq!(
        a.keepalive(&c, false).await.unwrap(),
        Keepalive::Kept {
            tags: "0000000010".into(),
            renew: false
        }
    );

    {
        let st = m.state.lock().unwrap();
        let kinds: Vec<_> = st.seen.iter().map(|s| s.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "PROBE", "PROBE", "REGISTER", "PROBE", "REGISTER", "KA", "TAG", "KA"
            ]
        );
        for s in &st.seen {
            // SIZE is the exact length; TAG carries no SIZE at all.
            let want = (s.kind != "TAG").then_some(SIZE_DELTA as i64);
            assert_eq!(s.size_delta, want);
            assert_eq!(s.uid.as_deref(), Some("0A1B2C3D4E5F60718293A4B5C6D7E8F9"));
            // The serial goes only on requests made once registered.
            assert_eq!(s.serial.is_some(), s.kind == "KA" || s.kind == "TAG");
        }
        // The echoed checksum stops the server from resending the rules.
        let ka = st.seen.iter().rfind(|s| s.kind == "KA").unwrap();
        assert!(ka.sysinfo_keys.iter().any(|k| k == "EP_RULECHKSUM"));
        assert!(
            st.endpoints
                .contains_key("0A1B2C3D4E5F60718293A4B5C6D7E8F9")
        );
    }

    a.deregister(&c).await.unwrap();
    assert!(a.registration(&c).unwrap().is_none());
    assert!(m.state.lock().unwrap().endpoints.is_empty());
    assert!(a.gateway_identity(&c).unwrap().is_none());
}

#[tokio::test]
async fn two_servers_side_by_side() {
    let one = ems::start(&EmsScenario::default()).await.unwrap();
    let two = ems::start(&EmsScenario {
        serial: "FCTEMS0000000002".into(),
        ..EmsScenario::default()
    })
    .await
    .unwrap();
    let d = tempfile::tempdir().unwrap();
    let a = agent(d.path());
    let (c1, c2) = (conn(&one, "ems.test"), conn(&two, "localhost"));

    a.ensure(&c1, None).await.unwrap();
    a.ensure(&c2, None).await.unwrap();
    // Switching between them neither unregisters nor re-registers.
    for _ in 0..2 {
        assert!(matches!(
            a.keepalive(&c1, false).await.unwrap(),
            Keepalive::Kept { .. }
        ));
        assert!(matches!(
            a.keepalive(&c2, false).await.unwrap(),
            Keepalive::Kept { .. }
        ));
    }
    a.ensure(&c1, None).await.unwrap();
    let (s1, _) = a.gateway_identity(&c1).unwrap().unwrap();
    let (s2, _) = a.gateway_identity(&c2).unwrap().unwrap();
    assert_eq!(s1.as_str(), "FCTEMS0000000001");
    assert_eq!(s2.as_str(), "FCTEMS0000000002");
    for m in [&one, &two] {
        let st = m.state.lock().unwrap();
        assert_eq!(st.seen.iter().filter(|s| s.kind == "REGISTER").count(), 1);
        // Each server only ever sees its own serial.
        let own = if std::ptr::eq(m, &one) {
            "FCTEMS0000000001"
        } else {
            "FCTEMS0000000002"
        };
        assert!(
            st.seen
                .iter()
                .all(|s| s.serial.as_deref().is_none_or(|x| x == own))
        );
    }
}

#[tokio::test]
async fn dropped_registration_is_forgotten() {
    let m = ems::start(&EmsScenario::default()).await.unwrap();
    let d = tempfile::tempdir().unwrap();
    let a = agent(d.path());
    let c = conn(&m, "ems.test");
    a.register(&c, None).await.unwrap();
    m.state.lock().unwrap().endpoints.clear();
    assert_eq!(a.keepalive(&c, false).await.unwrap(), Keepalive::Dropped);
    assert!(a.gateway_identity(&c).unwrap().is_none());
}

#[tokio::test]
async fn wrong_certificate_sends_nothing() {
    let m = ems::start(&EmsScenario::default()).await.unwrap();
    let d = tempfile::tempdir().unwrap();
    let a = agent(d.path());
    let c = Connection::new(
        "ems.test:8013".parse().unwrap(),
        &Trust::Pinned(vec![[7u8; 32]]),
    )
    .unwrap()
    .connect_to(m.handle.addr);
    assert!(matches!(a.probe(&c).await, Err(Error::Trust(_))));
    assert!(m.state.lock().unwrap().seen.is_empty());
}
