//! FortiClient XML profile export (client side).
//!
//! Writes the subset of a FortiClient configuration the importer in [`crate::import`] reads:
//! `forticlient_configuration/vpn/sslvpn/connections/connection` with `name`, `description`,
//! `server` (`host:port[/realm]`) and `sso_enabled`. FortiClient can import the result with
//! "Restore" and Fortino re-imports it unchanged.
//!
//! Nothing secret is written: no username, password or EMS registration data. Fortino-only
//! settings (IP policy, DNS choice, trust configuration, the per-profile EMS server) have no
//! per-connection equivalent in a FortiClient file and are left out.

use quick_xml::escape::escape;

use crate::model::ProfileSpec;

/// Renders `profiles` as a plain FortiClient XML configuration.
pub fn to_forticlient_xml<'a>(profiles: impl IntoIterator<Item = &'a ProfileSpec>) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n\
         <forticlient_configuration>\n\
         \x20 <vpn>\n\
         \x20   <sslvpn>\n\
         \x20     <options>\n\
         \x20       <enabled>1</enabled>\n\
         \x20     </options>\n\
         \x20     <connections>\n",
    );
    for p in profiles {
        let e = &p.endpoint;
        let mut server = format!("{}:{}", e.host, e.port);
        if let Some(r) = &e.realm {
            server.push('/');
            server.push_str(r);
        }
        out.push_str("        <connection>\n");
        out.push_str(&format!(
            "          <name>{}</name>\n",
            escape(p.name.as_str())
        ));
        if let Some(d) = &p.description {
            out.push_str(&format!(
                "          <description>{}</description>\n",
                escape(d.as_str())
            ));
        }
        out.push_str(&format!(
            "          <server>{}</server>\n",
            escape(server.as_str())
        ));
        out.push_str("          <sso_enabled>0</sso_enabled>\n");
        out.push_str("        </connection>\n");
    }
    out.push_str(
        "      </connections>\n\
         \x20   </sslvpn>\n\
         \x20 </vpn>\n\
         </forticlient_configuration>\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import;
    use crate::model::{EmsServer, Host};

    #[test]
    fn round_trips_through_the_importer() {
        let mut a = ProfileSpec::new("R&D <lab>", "vpn.example.test".parse().unwrap());
        a.endpoint.port = 10443;
        a.endpoint.realm = Some("staff".into());
        a.description = Some("Lab \"east\" & co".into());
        a.username_hint = Some("someone".into());
        a.endpoint.ems = Some("ems.example.test".parse::<EmsServer>().unwrap());
        let b = ProfileSpec::new("Plain", Host::Ipv4("192.0.2.1".parse().unwrap()));
        let xml = to_forticlient_xml([&a, &b]);
        assert!(!xml.contains("someone"));
        assert!(!xml.contains("ems.example.test"));
        let p = import::parse(xml.as_bytes()).unwrap();
        let got: Vec<_> = p.eligible().map(|e| e.spec.clone()).collect();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, a.name);
        assert_eq!(got[0].description, a.description);
        assert_eq!(got[0].endpoint.host, a.endpoint.host);
        assert_eq!(got[0].endpoint.port, 10443);
        assert_eq!(got[0].endpoint.realm.as_deref(), Some("staff"));
        assert_eq!(got[1].endpoint, b.endpoint);
        assert!(p.entries.iter().all(|e| e.warnings.is_empty()));
    }

    #[test]
    fn empty_export_is_valid() {
        let xml = to_forticlient_xml([]);
        let p = import::parse(xml.as_bytes()).unwrap();
        assert!(p.entries.is_empty());
    }
}
