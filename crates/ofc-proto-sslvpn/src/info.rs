//! `GET /remote/info`. Both target gateways return single-quoted attributes on an
//! `api` element.

use quick_xml::Reader;
use quick_xml::events::Event;

/// `f` bit: enable the FortiClient UID.
pub const FLAG_FCT_UID: u32 = 0x80;
/// `f` bit: send `FSV_EMS_SN` and the tenant header.
pub const FLAG_EMS_SN: u32 = 0x100;

/// Parsed `/remote/info`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerInfo {
    /// Credential encryption method. Only 0 (plain) is supported.
    pub encmethod: Option<u32>,
    /// Salt for encrypted credentials.
    pub salt: Option<String>,
    /// Seconds the gateway waits for a second factor.
    pub remote_auth_timeout: Option<u32>,
    /// Port for the external-browser SAML callback.
    pub sso_port: Option<u16>,
    /// Feature flags (`f`). Hex on the wire (`f='3cdf'`); FortiClient logs it in decimal.
    pub flag: Option<u32>,
}

impl ServerInfo {
    /// The gateway wants the EMS serial on requests.
    pub fn wants_ems_sn(&self) -> bool {
        self.flag.is_some_and(|f| f & FLAG_EMS_SN != 0)
    }

    /// The gateway enables the FortiClient UID.
    pub fn wants_fct_uid(&self) -> bool {
        self.flag.is_some_and(|f| f & FLAG_FCT_UID != 0)
    }
}

/// Info parsing errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InfoError {
    /// No `api` element.
    #[error("no api element in /remote/info")]
    NoApi,
    /// Not well-formed XML.
    #[error("malformed /remote/info: {0}")]
    Xml(String),
}

/// Parses the body of `/remote/info`.
pub fn parse(body: &str) -> Result<ServerInfo, InfoError> {
    let mut r = Reader::from_str(body);
    loop {
        match r.read_event() {
            Ok(Event::Start(e) | Event::Empty(e)) if e.name().as_ref() == b"api" => {
                let mut info = ServerInfo::default();
                for a in e.attributes().flatten() {
                    let v = a
                        .unescape_value()
                        .map_err(|e| InfoError::Xml(e.to_string()))?
                        .into_owned();
                    match a.key.as_ref() {
                        b"encmethod" => info.encmethod = v.trim().parse().ok(),
                        b"salt" => info.salt = Some(v),
                        b"remoteauthtimeout" => info.remote_auth_timeout = v.trim().parse().ok(),
                        b"sso_port" => info.sso_port = v.trim().parse().ok(),
                        b"f" => {
                            let t = v.trim();
                            let t = t.strip_prefix("0x").unwrap_or(t);
                            info.flag = u32::from_str_radix(t, 16).ok();
                        }
                        _ => {}
                    }
                }
                return Ok(info);
            }
            Ok(Event::Eof) => return Err(InfoError::NoApi),
            Err(e) => return Err(InfoError::Xml(e.to_string())),
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_quoted_attributes() {
        let i = parse("<?xml version='1.0' encoding='utf-8'?><info><api encmethod='0' salt='a1b2' remoteauthtimeout='600' sso_port='8020' f='3ddf'/></info>").unwrap();
        assert_eq!(i.encmethod, Some(0));
        assert_eq!(i.remote_auth_timeout, Some(600));
        assert_eq!(i.sso_port, Some(8020));
        assert!(i.wants_ems_sn());
        assert!(i.wants_fct_uid());
        let j = parse("<info><api encmethod=\"0\" f=\"3cdf\"/></info>").unwrap();
        assert!(!j.wants_ems_sn());
        assert!(j.wants_fct_uid());
    }

    #[test]
    fn missing_api() {
        assert_eq!(parse("<info/>"), Err(InfoError::NoApi));
        assert!(parse("<info><api").is_err());
    }
}
