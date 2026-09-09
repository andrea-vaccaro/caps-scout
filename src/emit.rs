use serde_json::{Map, Value};

/// Prints a Checkmk `<<<labels:sep(0)>>>` agent section for the given
/// key/value pairs. Checkmk's core (`cmk/plugins/checkmk/agent_based/labels.py`)
/// turns every entry into a host label automatically — no Checkmk-side plugin
/// code is required.
///
/// Per the "silence means healthy" decision (docs/checkmk-label-catalog.md),
/// nothing is printed at all when there are no labels to report.
pub fn emit_labels(labels: &[(&str, &str)]) {
    if let Some(json) = build_labels_json(labels) {
        println!("<<<labels:sep(0)>>>");
        println!("{json}");
    }
}

fn build_labels_json(labels: &[(&str, &str)]) -> Option<Value> {
    if labels.is_empty() {
        return None;
    }

    let mut map = Map::new();
    for (key, value) in labels {
        map.insert((*key).to_string(), Value::String((*value).to_string()));
    }
    Some(Value::Object(map))
}

#[cfg(test)]
mod tests {
    use super::build_labels_json;
    use serde_json::json;

    #[test]
    fn empty_labels_produce_no_json() {
        assert_eq!(build_labels_json(&[]), None);
    }

    #[test]
    fn labels_become_a_json_object() {
        let json = build_labels_json(&[("caps/db/oracle", "yes"), ("caps/os_type/linux", "yes")]);

        assert_eq!(
            json,
            Some(json!({
                "caps/db/oracle": "yes",
                "caps/os_type/linux": "yes",
            }))
        );
    }
}
