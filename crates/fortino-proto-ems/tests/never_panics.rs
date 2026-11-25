#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Every parser that reads network data must return, not panic, on any input.

use fortino_proto_ems::reply::{self, KeepaliveReply, ProbeReply, RegisterReply, TagReply};
use fortino_proto_ems::{blob, sysinfo::SysInfo, tags::Bits};
use proptest::prelude::*;

fn typed(r: &reply::Reply) {
    let _ = ProbeReply::from_reply(r);
    let _ = RegisterReply::from_reply(r);
    let _ = KeepaliveReply::from_reply(r);
    let _ = TagReply::from_reply(r);
}

proptest! {
    #[test]
    fn reply_bytes(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(r) = reply::parse(&data) {
            typed(&r);
        }
    }

    #[test]
    fn reply_shaped(
        kind in "(FCPROBERPLY|FCREGRPLY|FCKARPLY|FCTAGRPLY|[A-Z]{1,12})",
        pairs in proptest::collection::vec(
            ("(FGT|REG|CONT|EMSSN|TAGS|TENANT|QUAR|KA_INTERVAL|ERR_MSG|ZHVR|LIC_FEATS|[A-Z_]{1,8})",
             "[ -{}~:0-9-]{0,40}"),
            0..24,
        ),
    ) {
        let mut s = format!("{kind}: ");
        for (k, v) in &pairs {
            s.push_str(k);
            s.push('|');
            s.push_str(v);
            s.push('|');
        }
        let r = reply::parse(s.as_bytes()).unwrap();
        typed(&r);
    }

    #[test]
    fn blob_text(s in "\\PC{0,256}") {
        let _ = blob::decode(&s, 1 << 16);
    }

    #[test]
    fn blob_bytes(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        use base64::Engine;
        let s = base64::engine::general_purpose::STANDARD.encode(data);
        let _ = blob::decode(&s, 1 << 16);
    }

    #[test]
    fn sysinfo_decode(s in "\\PC{0,256}") {
        let _ = SysInfo::decode(&s);
    }

    #[test]
    fn bits(s in "[01x]{0,64}") {
        let _ = Bits::parse(&s);
    }
}

proptest! {
    #[test]
    fn request_bytes(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = fortino_proto_ems::message::parse_request(&data);
    }

    /// Framed as a client frames it (`\n\r\n` after the header, `\r\n` around the end
    /// marker), so header lines, the type, the end search and the body fields are all parsed;
    /// also cut short anywhere, as reads arrive.
    #[test]
    fn request_shaped(
        head in proptest::collection::vec(("[A-Z_]{1,10}", "[ -~]{0,16}"), 0..8),
        kind in "(KA|REG|PROBE|DEREG|[A-Z]{1,6})",
        fields in proptest::collection::vec(("[A-Z_]{1,8}", "[ -{}~]{0,16}"), 0..8),
        tag: bool,
        cut in 0usize..400,
    ) {
        let lines: String = head.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
        let body: String = fields.iter().map(|(k, v)| format!("{k}|{v}|")).collect();
        let s = if tag {
            format!("X-FCCK-TAG: {lines}X-FCCK-TAG-END\r\n\r\n")
        } else {
            format!("MSG_HEADER: {lines}\n\r\nX-FCCK-{kind}: {body}\r\nX-FCCK-{kind}-END\r\n\r\n")
        };
        let b = s.as_bytes();
        let _ = fortino_proto_ems::message::parse_request(b);
        let _ = fortino_proto_ems::message::parse_request(&b[..cut.min(b.len())]);
    }
}

proptest! {
    #[test]
    fn hv_text(s in "\\PC{0,400}") {
        let _ = fortino_proto_ems::hv::parse(&s);
    }

    #[test]
    fn hv_shaped(
        parts in proptest::collection::vec(
            "(<rule>|</rule>|<criteria>|</criteria>|<criterion>|</criterion>|<tag>|</tag>|<rule_flag>[0-9]{1,5}</rule_flag>|<tag_flag>[0-9x]{1,3}</tag_flag>|<content>[a-z ]{0,8}</content>|<feature>os_version</feature>)",
            0..40,
        ),
    ) {
        let _ = fortino_proto_ems::hv::parse(&parts.concat());
    }
}
