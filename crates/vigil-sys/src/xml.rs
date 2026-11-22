//! A small XML reader for the well-formed XML Windows hands out: task definitions and rendered
//! event log records. Elements keep their local name (prefixes dropped), attributes, text and
//! children; no DTDs, no external entities.

/// An element: its local name (prefix dropped), attributes, text and children.
#[derive(Debug, Default)]
pub(crate) struct Node {
    pub(crate) name: String,
    pub(crate) attrs: Vec<(String, String)>,
    pub(crate) text: String,
    pub(crate) children: Vec<Node>,
}

impl Node {
    pub(crate) fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    /// The trimmed text of the element at `path` below this one ("" when missing).
    pub(crate) fn text_at(&self, path: &[&str]) -> &str {
        let mut node = self;
        for name in path {
            match node.child(name) {
                Some(next) => node = next,
                None => return "",
            }
        }
        node.text.trim()
    }

    pub(crate) fn attr(&self, name: &str) -> &str {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map_or("", |(_, v)| v.as_str())
    }
}

const MAX_XML_DEPTH: usize = 64;

/// The root element of a document. The XML comes from Windows itself (task definitions, rendered
/// events), which only produces well-formed XML; anything unexpected ends the parse with what was
/// read so far.
pub(crate) fn parse_xml(xml: &str) -> Option<Node> {
    let mut stack: Vec<Node> = vec![Node::default()];
    let mut rest = xml;
    while let Some(lt) = rest.find('<') {
        let text = &rest[..lt];
        if !text.trim().is_empty() {
            stack.last_mut()?.text.push_str(&unescape(text));
        }
        rest = &rest[lt..];
        if let Some(after) = rest.strip_prefix("<!--") {
            rest = after.find("-->").map_or("", |end| &after[end + 3..]);
            continue;
        }
        if let Some(after) = rest.strip_prefix("<![CDATA[") {
            let end = after.find("]]>").unwrap_or(after.len());
            stack.last_mut()?.text.push_str(&after[..end]);
            rest = after.get(end + 3..).unwrap_or("");
            continue;
        }
        if rest.starts_with("<?") || rest.starts_with("<!") {
            rest = rest.find('>').map_or("", |end| &rest[end + 1..]);
            continue;
        }
        let Some(end) = tag_end(rest) else { break };
        let tag = &rest[1..end];
        rest = &rest[end + 1..];
        if tag.starts_with('/') {
            if stack.len() > 1 {
                let node = stack.pop()?;
                stack.last_mut()?.children.push(node);
            }
            continue;
        }
        let closed = tag.ends_with('/');
        let node = open_tag(tag.trim_end_matches('/'));
        if closed {
            stack.last_mut()?.children.push(node);
        } else if stack.len() <= MAX_XML_DEPTH {
            stack.push(node);
        } else {
            break;
        }
    }
    while stack.len() > 1 {
        let node = stack.pop()?;
        stack.last_mut()?.children.push(node);
    }
    stack.pop()?.children.into_iter().next()
}

/// The index of the `>` that ends the tag at the start of `text` (quotes respected).
fn tag_end(text: &str) -> Option<usize> {
    let mut quote = None;
    for (i, c) in text.char_indices().skip(1) {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '>') => return Some(i),
            _ => {}
        }
    }
    None
}

fn open_tag(tag: &str) -> Node {
    let tag = tag.trim();
    let (name, mut rest) = tag.split_once(char::is_whitespace).unwrap_or((tag, ""));
    let mut attrs = Vec::new();
    while let Some(eq) = rest.find('=') {
        let key = rest[..eq].trim();
        let after = rest[eq + 1..].trim_start();
        let Some(quote) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            break;
        };
        let body = &after[1..];
        let Some(close) = body.find(quote) else { break };
        attrs.push((local_name(key).to_string(), unescape(&body[..close])));
        rest = &body[close + 1..];
    }
    Node {
        name: local_name(name).to_string(),
        attrs,
        ..Node::default()
    }
}

fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

pub(crate) fn unescape(text: &str) -> String {
    if !text.contains('&') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let decoded = rest.find(';').filter(|&semi| semi <= 12).and_then(|semi| {
            let entity = &rest[1..semi];
            let c = match entity {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => {
                    let code = match entity.strip_prefix("#x").or_else(|| entity.strip_prefix("#X")) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok(),
                        None => entity.strip_prefix('#').and_then(|d| d.parse().ok()),
                    };
                    code.and_then(char::from_u32)
                }
            };
            c.map(|c| (c, semi))
        });
        match decoded {
            Some((c, semi)) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_attributes_and_entities() {
        assert_eq!(unescape("a &lt;b&gt; &#65;&#x42; &bogus; & c"), "a <b> AB &bogus; & c");
        let node = parse_xml("<a x='1' y=\"2 > 3\"><b>one</b><b>two</b><c/></a>").unwrap();
        assert_eq!((node.attr("x"), node.attr("y")), ("1", "2 > 3"));
        assert_eq!(node.children.len(), 3);
        // Truncated input keeps what was read and never panics.
        let cut = parse_xml("<a><b>one</b><c>unfinished").unwrap();
        assert_eq!(cut.text_at(&["b"]), "one");
        assert!(parse_xml("").is_none());
        assert!(parse_xml("<").is_none());
    }
}
