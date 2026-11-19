//! `0`/`1` bitstrings: `RULES` (host-verification results, indexed by `rule_flag`) and `TAGS`
//! (EMS-assigned tags, indexed by `tag_flag`).

/// Longest bitstring accepted.
pub const MAX_BITS: usize = 4096;

/// A bitstring.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Bits(Vec<bool>);

/// Not a `0`/`1` string, or too long.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed bitstring")]
pub struct BitsError;

impl Bits {
    /// `len` zero bits.
    pub fn zeros(len: usize) -> Self {
        Self(vec![false; len.min(MAX_BITS)])
    }

    /// Parses `"0010…"`.
    pub fn parse(text: &str) -> Result<Self, BitsError> {
        if text.len() > MAX_BITS {
            return Err(BitsError);
        }
        text.bytes()
            .map(|b| match b {
                b'0' => Ok(false),
                b'1' => Ok(true),
                _ => Err(BitsError),
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }

    /// Bit `i`; bits past the end are clear.
    pub fn get(&self, i: usize) -> bool {
        self.0.get(i).copied().unwrap_or(false)
    }

    /// Sets bit `i`, growing the string up to [`MAX_BITS`]. Returns false past the limit.
    pub fn set(&mut self, i: usize, v: bool) -> bool {
        if i >= MAX_BITS {
            return false;
        }
        if i >= self.0.len() {
            self.0.resize(i + 1, false);
        }
        self.0[i] = v;
        true
    }

    /// Indices of set bits.
    pub fn ones(&self) -> impl Iterator<Item = usize> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter(|(_, b)| **b)
            .map(|(i, _)| i)
    }

    /// Length in bits.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// No bits.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Display for Bits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            f.write_str(if *b { "1" } else { "0" })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let b = Bits::parse("0000000010").unwrap();
        assert!(b.get(8));
        assert!(!b.get(99));
        assert_eq!(b.ones().collect::<Vec<_>>(), vec![8]);
        assert_eq!(b.to_string(), "0000000010");
        assert!(Bits::parse("012").is_err());
    }

    #[test]
    fn set_grows() {
        let mut b = Bits::zeros(2);
        assert!(b.set(4, true));
        assert_eq!(b.to_string(), "00001");
        assert!(!b.set(MAX_BITS, true));
    }
}
