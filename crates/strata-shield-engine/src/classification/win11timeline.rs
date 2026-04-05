use std::collections::BTreeMap;

use super::wintimeline;

pub fn get_timeline_activities() -> Vec<TimelineActivity> {
    match wintimeline::get_timeline_entries() {
        Ok(entries) => entries
            .into_iter()
            .map(|e| TimelineActivity {
                app_id: e.id.clone(),
                app_name: e.app_name,
                title: e.title,
                description: e.description,
                start_time: e.timestamp,
                end_time: None,
                activity_type: "timeline_entry".to_string(),
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct TimelineActivity {
    pub app_id: String,
    pub app_name: String,
    pub title: String,
    pub description: String,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub activity_type: String,
}

pub fn get_timeline_groups() -> Vec<TimelineGroup> {
    let mut by_day: BTreeMap<String, Vec<TimelineActivity>> = BTreeMap::new();
    for activity in get_timeline_activities() {
        let day = unix_day(activity.start_time);
        by_day.entry(day).or_default().push(activity);
    }
    by_day
        .into_iter()
        .map(|(date, activities)| TimelineGroup { date, activities })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct TimelineGroup {
    pub date: String,
    pub activities: Vec<TimelineActivity>,
}

pub fn get_timeline_search() -> Vec<TimelineSearchResult> {
    vec![TimelineSearchResult {
        query: "all".to_string(),
        results: get_timeline_activities(),
    }]
}

#[derive(Debug, Clone, Default)]
pub struct TimelineSearchResult {
    pub query: String,
    pub results: Vec<TimelineActivity>,
}

fn unix_day(ts: u64) -> String {
    if ts == 0 {
        return "unknown".to_string();
    }
    // Grouping helper without extra dependencies in this module.
    let days = ts / 86_400;
    format!("day-{days}")
}
