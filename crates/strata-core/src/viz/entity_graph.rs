//! Entity relationship graph export (VIZ-1).
//!
//! Emits GraphML / DOT / JSON so examiners can import into Gephi,
//! Maltego, or Graphviz (all air-gapped locally).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Entity {
    Username(String),
    EmailAddress(String),
    IpAddress(String),
    PhoneNumber(String),
    Domain(String),
    FileHash(String),
    DeviceId(String),
    AccountId(String),
    Url(String),
}

impl Entity {
    pub fn value(&self) -> &str {
        match self {
            Entity::Username(s)
            | Entity::EmailAddress(s)
            | Entity::IpAddress(s)
            | Entity::PhoneNumber(s)
            | Entity::Domain(s)
            | Entity::FileHash(s)
            | Entity::DeviceId(s)
            | Entity::AccountId(s)
            | Entity::Url(s) => s,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Entity::Username(_) => "Username",
            Entity::EmailAddress(_) => "EmailAddress",
            Entity::IpAddress(_) => "IpAddress",
            Entity::PhoneNumber(_) => "PhoneNumber",
            Entity::Domain(_) => "Domain",
            Entity::FileHash(_) => "FileHash",
            Entity::DeviceId(_) => "DeviceId",
            Entity::AccountId(_) => "AccountId",
            Entity::Url(_) => "Url",
        }
    }

    fn id(&self) -> String {
        format!("{}|{}", self.kind(), self.value())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityGraph {
    pub nodes: Vec<Entity>,
    pub edges: Vec<(String, String, f64)>,
}

#[derive(Debug, Default)]
pub struct EntityGraphBuilder {
    node_index: BTreeMap<String, Entity>,
    edge_weight: BTreeMap<(String, String), f64>,
}

impl EntityGraphBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_entity(&mut self, e: Entity) {
        self.node_index.insert(e.id(), e);
    }

    pub fn add_edge(&mut self, a: Entity, b: Entity, weight: f64) {
        self.node_index.insert(a.id(), a.clone());
        self.node_index.insert(b.id(), b.clone());
        let (lo, hi) = if a.id() < b.id() {
            (a.id(), b.id())
        } else {
            (b.id(), a.id())
        };
        *self.edge_weight.entry((lo, hi)).or_insert(0.0) += weight;
    }

    pub fn build(self) -> EntityGraph {
        let nodes: Vec<Entity> = self.node_index.into_values().collect();
        let edges: Vec<(String, String, f64)> = self
            .edge_weight
            .into_iter()
            .map(|((a, b), w)| (a, b, w))
            .collect();
        EntityGraph { nodes, edges }
    }
}

pub fn to_dot(graph: &EntityGraph) -> String {
    let mut out = String::from("graph entities {\n");
    for node in &graph.nodes {
        let shape = match node {
            Entity::IpAddress(_) | Entity::Domain(_) | Entity::Url(_) => "diamond",
            Entity::FileHash(_) => "box",
            Entity::DeviceId(_) => "hexagon",
            _ => "ellipse",
        };
        out.push_str(&format!(
            "  \"{}\" [shape={}, label=\"{}\\n{}\"];\n",
            escape_id(node.value()),
            shape,
            node.kind(),
            escape_id(node.value())
        ));
    }
    for (a, b, w) in &graph.edges {
        let a_val = strip_kind(a);
        let b_val = strip_kind(b);
        let penwidth = (1.0 + w.log2().max(0.0)).min(8.0);
        out.push_str(&format!(
            "  \"{}\" -- \"{}\" [label=\"w={:.1}\", penwidth={:.2}];\n",
            escape_id(a_val),
            escape_id(b_val),
            w,
            penwidth
        ));
    }
    out.push_str("}\n");
    out
}

pub fn to_graphml(graph: &EntityGraph) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n\
         <graph id=\"strata-entities\" edgedefault=\"undirected\">\n",
    );
    for node in &graph.nodes {
        out.push_str(&format!(
            "  <node id=\"{}\" data-type=\"{}\"/>\n",
            xml_escape(node.value()),
            node.kind()
        ));
    }
    for (a, b, w) in &graph.edges {
        out.push_str(&format!(
            "  <edge source=\"{}\" target=\"{}\" weight=\"{:.2}\"/>\n",
            xml_escape(strip_kind(a)),
            xml_escape(strip_kind(b)),
            w
        ));
    }
    out.push_str("</graph>\n</graphml>\n");
    out
}

pub fn to_json(graph: &EntityGraph) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(graph)
}

fn escape_id(s: &str) -> String {
    s.replace('"', "\\\"")
}

fn strip_kind(id: &str) -> &str {
    id.split_once('|').map(|(_, v)| v).unwrap_or(id)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_deduplicates_entities() {
        let mut b = EntityGraphBuilder::new();
        b.add_entity(Entity::Username("alice".into()));
        b.add_entity(Entity::Username("alice".into()));
        b.add_entity(Entity::Username("bob".into()));
        let graph = b.build();
        assert_eq!(graph.nodes.len(), 2);
    }

    #[test]
    fn edge_weight_accumulates_across_calls() {
        let mut b = EntityGraphBuilder::new();
        b.add_edge(
            Entity::Username("a".into()),
            Entity::IpAddress("10.0.0.1".into()),
            1.0,
        );
        b.add_edge(
            Entity::Username("a".into()),
            Entity::IpAddress("10.0.0.1".into()),
            2.0,
        );
        let graph = b.build();
        assert_eq!(graph.edges.len(), 1);
        assert!((graph.edges[0].2 - 3.0).abs() < 1e-6);
    }

    #[test]
    fn to_graphml_emits_nodes_and_edges() {
        let mut b = EntityGraphBuilder::new();
        b.add_edge(
            Entity::Username("alice".into()),
            Entity::IpAddress("10.0.0.1".into()),
            1.0,
        );
        let xml = to_graphml(&b.build());
        assert!(xml.contains("<node id=\"alice\""));
        assert!(xml.contains("<node id=\"10.0.0.1\""));
        assert!(xml.contains("<edge"));
    }

    #[test]
    fn to_dot_picks_shape_per_entity_type() {
        let mut b = EntityGraphBuilder::new();
        b.add_entity(Entity::IpAddress("192.0.2.5".into()));
        b.add_entity(Entity::Username("alice".into()));
        let dot = to_dot(&b.build());
        assert!(dot.contains("shape=diamond"));
        assert!(dot.contains("shape=ellipse"));
    }

    #[test]
    fn to_json_round_trips_structure() {
        let mut b = EntityGraphBuilder::new();
        b.add_edge(
            Entity::Username("alice".into()),
            Entity::EmailAddress("alice@example.com".into()),
            0.5,
        );
        let graph = b.build();
        let json = to_json(&graph).expect("json");
        let parsed: EntityGraph = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed.nodes.len(), 2);
        assert_eq!(parsed.edges.len(), 1);
    }
}
