use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct StringMatch {
    pub offset: u64,
    pub content: String,
    pub encoding: String,
    pub length: usize,
}

pub fn extract_strings(data: &[u8], min_length: usize) -> Vec<StringMatch> {
    let mut results = Vec::new();

    results.extend(extract_ascii_strings(data, min_length));
    results.extend(extract_utf16_strings(data, min_length));

    results.sort_by_key(|m| m.offset);
    results
}

fn extract_ascii_strings(data: &[u8], min_length: usize) -> Vec<StringMatch> {
    let mut results = Vec::new();
    let mut current = Vec::new();
    let mut offset = 0u64;

    for (i, &byte) in data.iter().enumerate() {
        if (0x20..0x7F).contains(&byte) {
            if current.is_empty() {
                offset = i as u64;
            }
            current.push(byte as char);
        } else {
            if current.len() >= min_length {
                results.push(StringMatch {
                    offset,
                    content: current.iter().collect(),
                    encoding: "ASCII".to_string(),
                    length: current.len(),
                });
            }
            current.clear();
        }
    }

    if current.len() >= min_length {
        results.push(StringMatch {
            offset,
            content: current.iter().collect(),
            encoding: "ASCII".to_string(),
            length: current.len(),
        });
    }

    results
}

fn extract_utf16_strings(data: &[u8], min_length: usize) -> Vec<StringMatch> {
    let mut results = Vec::new();
    let mut current = Vec::new();
    let mut offset = 0u64;

    if data.len() < 2 {
        return results;
    }

    for i in (0..data.len() - 1).step_by(2) {
        let ch = u16::from_le_bytes([data[i], data[i + 1]]);

        if (0x20..0x7F).contains(&ch) {
            if current.is_empty() {
                offset = i as u64;
            }
            current.push(ch);
        } else {
            if current.len() >= min_length {
                let s: String = current
                    .iter()
                    .filter_map(|&c| char::from_u32(c as u32))
                    .collect();
                if !s.is_empty() {
                    results.push(StringMatch {
                        offset,
                        content: s,
                        encoding: "UTF-16LE".to_string(),
                        length: current.len(),
                    });
                }
            }
            current.clear();
        }
    }

    if current.len() >= min_length {
        let s: String = current
            .iter()
            .filter_map(|&c| char::from_u32(c as u32))
            .collect();
        if !s.is_empty() {
            results.push(StringMatch {
                offset,
                content: s,
                encoding: "UTF-16LE".to_string(),
                length: current.len(),
            });
        }
    }

    results
}

pub fn search_strings(data: &[u8], pattern: &str, min_length: usize) -> Vec<StringMatch> {
    let all_strings = extract_strings(data, min_length);

    all_strings
        .into_iter()
        .filter(|s| s.content.to_lowercase().contains(&pattern.to_lowercase()))
        .collect()
}

pub fn extract_keywords(data: &[u8], min_length: usize, max_results: usize) -> HashSet<String> {
    let strings = extract_strings(data, min_length);

    let mut keywords: HashSet<String> = HashSet::new();

    for s in strings {
        let lower = s.content.to_lowercase();

        for word in lower.split_whitespace() {
            let cleaned: String = word.chars().filter(|c| c.is_alphanumeric()).collect();

            if cleaned.len() >= min_length {
                keywords.insert(cleaned);
            }
        }

        if keywords.len() >= max_results {
            break;
        }
    }

    keywords
}
