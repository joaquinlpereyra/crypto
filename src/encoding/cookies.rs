use std::collections::BTreeMap;
use std::fmt;

type Result<T> = std::result::Result<T, CookieError>;

#[derive(Debug, Clone)]
pub enum CookieError {
    MalformedCookie { cookie: String },
}

impl fmt::Display for CookieError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CookieError::MalformedCookie { cookie } => write!(f, "malformed cookie: {}", cookie),
        }
    }
}

pub fn decode(data: &str) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();

    let attrs = data.split('&').map(|a| a.split('='));
    for mut attr in attrs {
        let key = match attr.next() {
            Some("") => continue,
            Some(s) => s.to_owned(),
            // It is surprisingly impossible as far as I can tell
            // to get a zero-length iterator from a split.
            None => unreachable!(),
        };
        let value = attr.next().map(|s| s.into()).unwrap_or(String::from(""));

        if let Some(_) = attr.next() {
            return Result::Err(CookieError::MalformedCookie {
                cookie: data.into(),
            });
        }

        result.insert(key, value);
    }

    Result::Ok(result)
}

pub fn encode(map: BTreeMap<&str, String>) -> String {
    let mut result = String::new();
    if map.is_empty() {
        return result;
    }

    let mut iter = map.into_iter();

    let (key, value) = iter.next().unwrap();
    result += &key;
    result += "=";
    result += &value;
    for (key, value) in iter {
        result += "&";
        result += &key;
        result += "=";
        result += &value;
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_str() {
        let map = decode(String::from("v1=k1&v2=k2")).unwrap();
        let mut expected = HashMap::new();
        expected.insert(String::from("v1"), String::from("k1"));
        expected.insert(String::from("v2"), String::from("k2"));
        assert_eq!(map, expected);
    }

    #[test]
    fn test_parse_empty_str() {
        let map = decode(String::from("")).unwrap();
        let expected = HashMap::new();
        assert_eq!(map, expected);
    }
}
