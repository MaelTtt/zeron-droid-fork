//! A subscription's plan usage as meters: the replies of Claude's
//! `/api/oauth/usage`, Codex's `/wham/usage` and Factory's
//! `/api/billing/limits` read into windows
//! ("Session", "Week", "Month") and the live plan label. Shared by every
//! reader: the engine probing a CLI login, and Cloud's logins, whose usage
//! only the vault can fetch (the desktop and the phone read its reply). Pure.

use chrono::{DateTime, Utc};

use crate::{AgentUsageWindow, HarnessId};

/// `harness`'s usage reply as windows and the live plan label; `None` when
/// it carries no window.
pub fn from_reply(
    harness: HarnessId,
    body: &serde_json::Value,
) -> Option<(Vec<AgentUsageWindow>, Option<String>)> {
    match harness {
        HarnessId::ClaudeCode => claude(body).map(|windows| (windows, None)),
        HarnessId::Codex => codex(body),
        HarnessId::Droid => factory(body).map(|windows| (windows, None)),
        _ => None,
    }
}

/// Factory's `/api/billing/limits`: the Standard allowance's 5-hour, weekly
/// and monthly windows, each a 0-100 `usedPercent` with an RFC 3339
/// `windowEnd` (`null` while the window hasn't started). The Droid Core
/// allowance under `limits.core` is the fallback once Standard runs out and
/// is not a meter of its own.
pub fn factory(body: &serde_json::Value) -> Option<Vec<AgentUsageWindow>> {
    let standard = body.get("limits")?.get("standard")?;
    let mut windows = Vec::new();
    for (key, label) in [
        ("fiveHour", "Session"),
        ("weekly", "Week"),
        ("monthly", "Month"),
    ] {
        if let Some(w) = standard.get(key)
            && let Some(used) = w.get("usedPercent").and_then(|v| v.as_f64())
        {
            windows.push(AgentUsageWindow {
                label: label.to_string(),
                used_fraction: (used / 100.0).clamp(0.0, 1.0) as f32,
                resets_at: parse_when(w.get("windowEnd")),
            });
        }
    }
    (!windows.is_empty()).then_some(windows)
}

/// Claude's `/api/oauth/usage`: the 5-hour session and weekly buckets, each
/// a 0-100 `utilization` with an RFC3339 `resets_at`.
pub fn claude(body: &serde_json::Value) -> Option<Vec<AgentUsageWindow>> {
    let mut windows = Vec::new();
    for (key, label) in [("five_hour", "Session"), ("seven_day", "Week")] {
        if let Some(w) = body.get(key)
            && let Some(utilization) = w.get("utilization").and_then(|v| v.as_f64())
        {
            windows.push(AgentUsageWindow {
                label: label.to_string(),
                used_fraction: (utilization / 100.0) as f32,
                resets_at: parse_when(w.get("resets_at")),
            });
        }
    }
    (!windows.is_empty()).then_some(windows)
}

/// Codex `/wham/usage`: primary/secondary windows + the live plan ("free"/
/// "plus"/"pro"…), which beats the login-time JWT claim.
pub fn codex(body: &serde_json::Value) -> Option<(Vec<AgentUsageWindow>, Option<String>)> {
    let rl = body.get("rate_limit")?;
    let mut windows = Vec::new();
    for key in ["primary_window", "secondary_window"] {
        if let Some(w) = rl.get(key)
            && let Some(used) = w.get("used_percent").and_then(|v| v.as_f64())
        {
            let span = w
                .get("limit_window_seconds")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            windows.push(AgentUsageWindow {
                label: codex_window_label(span).to_string(),
                used_fraction: (used / 100.0) as f32,
                resets_at: parse_when(w.get("reset_at")),
            });
        }
    }
    if windows.is_empty() {
        return None;
    }
    let plan = body
        .get("plan_type")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    Some((windows, codex_plan(plan)))
}

/// "ChatGPT Plus" from Codex's `plan_type`.
pub fn codex_plan(plan: Option<&str>) -> Option<String> {
    let plan = plan?;
    let mut chars = plan.chars();
    let first = chars.next()?;
    Some(format!(
        "ChatGPT {}{}",
        first.to_uppercase(),
        chars.as_str()
    ))
}

/// Meter label for a Codex rate-limit window from its `limit_window_seconds`:
/// the free tier's window is a 30-day month (2_592_000s), Plus runs a 5-hour
/// primary (~18_000s) with a weekly secondary (604_800s). A bare "> 1 day =
/// week" rule mislabeled the monthly window "Week"; thresholds in seconds
/// leave the middle gaps to the nearest label rather than guessing a plan.
pub fn codex_window_label(span_seconds: i64) -> &'static str {
    const DAY: i64 = 86_400;
    if span_seconds >= 28 * DAY {
        "Month"
    } else if span_seconds >= 5 * DAY {
        "Week"
    } else {
        "Session"
    }
}

/// A reset time as Unix seconds or RFC 3339.
pub fn parse_when(value: Option<&serde_json::Value>) -> Option<DateTime<Utc>> {
    match value? {
        serde_json::Value::Number(n) => DateTime::<Utc>::from_timestamp(n.as_i64()?, 0),
        serde_json::Value::String(s) => DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|t| t.with_timezone(&Utc)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `/api/billing/limits` as Factory answers it: Standard maxed out for
    /// the month, Droid Core barely touched.
    fn limits() -> serde_json::Value {
        json!({
            "hasActiveSubscription": true,
            "limits": {
                "standard": {
                    "fiveHour": { "usedPercent": 0, "windowEnd": null, "secondsRemaining": null },
                    "weekly": { "usedPercent": 12.5, "windowEnd": "2026-11-05T17:51:01.392Z" },
                    "monthly": { "usedPercent": 100, "windowEnd": "2026-11-07T19:09:52.366Z" }
                },
                "core": {
                    "fiveHour": { "usedPercent": 6, "windowEnd": "2026-11-04T16:41:02.554Z" },
                    "weekly": { "usedPercent": 22, "windowEnd": "2026-11-05T17:51:01.392Z" },
                    "monthly": { "usedPercent": 7, "windowEnd": "2026-12-01T18:09:18.324Z" }
                }
            },
            "extraUsageBalanceCents": 0
        })
    }

    #[test]
    fn factory_reads_the_standard_windows_and_ignores_core() {
        let windows = factory(&limits()).unwrap();
        let read: Vec<_> = windows
            .iter()
            .map(|w| (w.label.as_str(), w.used_fraction, w.resets_at.is_some()))
            .collect();
        assert_eq!(
            read,
            [
                ("Session", 0.0, false),
                ("Week", 0.125, true),
                ("Month", 1.0, true)
            ]
        );
        assert_eq!(
            windows[2].resets_at.unwrap().to_rfc3339(),
            "2026-11-07T19:09:52.366+00:00"
        );
    }

    #[test]
    fn factory_clamps_overshoot_and_skips_unreadable_windows() {
        let body = json!({ "limits": { "standard": {
            "fiveHour": { "usedPercent": 140 },
            "weekly": { "usedPercent": null },
            "monthly": "soon"
        } } });
        let windows = factory(&body).unwrap();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].used_fraction, 1.0);
    }

    #[test]
    fn factory_without_standard_limits_has_no_windows() {
        assert!(factory(&json!({ "hasActiveSubscription": false })).is_none());
        assert!(factory(&json!({ "limits": { "core": {} } })).is_none());
        assert!(factory(&json!({ "limits": { "standard": {} } })).is_none());
    }

    #[test]
    fn from_reply_routes_droid_to_factory_without_a_plan_label() {
        let (windows, plan) = from_reply(HarnessId::Droid, &limits()).unwrap();
        assert_eq!(windows.len(), 3);
        assert_eq!(plan, None);
        assert!(from_reply(HarnessId::Grok, &limits()).is_none());
    }
}
