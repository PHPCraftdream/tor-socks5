/// `dns_server.overrides[].patterns`: a list of hostname globs. A single
/// string (the legacy `pattern: *.ru` form) is accepted and read as a
/// one-element list. Order is kept: overrides are first-match.
pub(super) fn override_patterns<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Patterns;

    impl<'de> serde::de::Visitor<'de> for Patterns {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a hostname mask string or a list of hostname mask strings")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            Ok(vec![value.to_owned()])
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut patterns = Vec::new();
            while let Some(pattern) = seq.next_element::<String>()? {
                patterns.push(pattern);
            }
            Ok(patterns)
        }
    }

    deserializer.deserialize_any(Patterns)
}

#[cfg(test)]
#[path = "override_patterns_tests.rs"]
mod tests;
