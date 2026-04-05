use std::env;
use std::path::PathBuf;

use serde_json::Value;

pub fn get_weather_widget() -> Vec<WeatherData> {
    let Some(items) = load(path("FORENSIC_WIDGET_WEATHER", "weather_widget.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| WeatherData {
            location: s(&v, &["location"]),
            temperature: f(&v, &["temperature", "temp_c"]),
            condition: s(&v, &["condition"]),
            updated: n(&v, &["updated", "timestamp"]),
        })
        .filter(|x| !x.location.is_empty() || x.updated > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct WeatherData {
    pub location: String,
    pub temperature: f32,
    pub condition: String,
    pub updated: u64,
}

pub fn get_stocks_widget() -> Vec<StockData> {
    let Some(items) = load(path("FORENSIC_WIDGET_STOCKS", "stocks_widget.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| StockData {
            symbol: s(&v, &["symbol"]),
            price: f(&v, &["price"]),
            change: f(&v, &["change"]),
            updated: n(&v, &["updated", "timestamp"]),
        })
        .filter(|x| !x.symbol.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct StockData {
    pub symbol: String,
    pub price: f32,
    pub change: f32,
    pub updated: u64,
}

pub fn get_sports_widget() -> Vec<SportsData> {
    let Some(items) = load(path("FORENSIC_WIDGET_SPORTS", "sports_widget.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| SportsData {
            league: s(&v, &["league"]),
            home_team: s(&v, &["home_team"]),
            away_team: s(&v, &["away_team"]),
            score: s(&v, &["score"]),
            status: s(&v, &["status"]),
        })
        .filter(|x| !x.league.is_empty() || !x.home_team.is_empty() || !x.away_team.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct SportsData {
    pub league: String,
    pub home_team: String,
    pub away_team: String,
    pub score: String,
    pub status: String,
}

pub fn get_news_widget() -> Vec<NewsData> {
    let Some(items) = load(path("FORENSIC_WIDGET_NEWS", "news_widget.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| NewsData {
            headline: s(&v, &["headline", "title"]),
            source: s(&v, &["source"]),
            timestamp: n(&v, &["timestamp", "published"]),
            image_url: s(&v, &["image_url", "image"]),
        })
        .filter(|x| !x.headline.is_empty())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct NewsData {
    pub headline: String,
    pub source: String,
    pub timestamp: u64,
    pub image_url: String,
}

pub fn get_traffic_widget() -> Vec<TrafficData> {
    let Some(items) = load(path("FORENSIC_WIDGET_TRAFFIC", "traffic_widget.json")) else {
        return Vec::new();
    };
    items
        .into_iter()
        .map(|v| TrafficData {
            route: s(&v, &["route"]),
            delay_minutes: n(&v, &["delay_minutes", "delay"]) as u32,
            updated: n(&v, &["updated", "timestamp"]),
        })
        .filter(|x| !x.route.is_empty() || x.delay_minutes > 0)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct TrafficData {
    pub route: String,
    pub delay_minutes: u32,
    pub updated: u64,
}

fn path(env_key: &str, file: &str) -> PathBuf {
    env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts").join("widgets").join(file))
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let json: Value = serde_json::from_slice(&data).ok()?;
    if let Some(items) = json.as_array() {
        Some(items.clone())
    } else if json.is_object() {
        Some(vec![json])
    } else {
        None
    }
}

fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}

fn n(v: &Value, keys: &[&str]) -> u64 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return n;
            }
        }
    }
    0
}

fn f(v: &Value, keys: &[&str]) -> f32 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_f64) {
            return x as f32;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<f32>() {
                return n;
            }
        }
    }
    0.0
}
