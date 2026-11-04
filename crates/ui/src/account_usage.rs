//! The composer footer's ring cluster. The plan-usage ring shows how much of
//! the active account's rate limit the session's harness has used, beside
//! the context ring. Clicking it opens the harness's accounts — each with its
//! usage meters — and clicking one switches to it, the same `ActivateAgentAccount` Settings →
//! Accounts runs. Both views share [`AccountsSnapshotCache`], so a switch in
//! either shows up in the other.
use std::time::{Duration, Instant};

use gpui::{
    Context, Entity, IntoElement, Render, SharedString, Subscription, Task, Window, div,
    prelude::*, px,
};
use zeron_proto::{AgentAccount, AgentAccountsSnapshot, HarnessId};
use zeron_rpc::methods;

use crate::popover;
use crate::settings::accounts::{
    self, AccountsSnapshotCache, UsageLevel, render_usage_meter, reports_usage, signs_in,
    usage_color, usage_level,
};
use crate::settings::widgets;
use crate::state::AppState;
use crate::theme::Theme;

/// Forced probes hit the provider; the engine throttles them too, but the
/// ring re-probes on every hover, so don't even ask more often than this.
const FORCE_MIN_INTERVAL: Duration = Duration::from_secs(30);
/// Background re-probe while a composer is alive: usage moves as turns run.
const POLL_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The binding limit: the most-used window of the account. Pure.
pub fn used_fraction(account: &AgentAccount) -> Option<f32> {
    account
        .usage_windows
        .iter()
        .map(|window| window.used_fraction.clamp(0.0, 1.0))
        .reduce(f32::max)
}

/// Whether a Cursor model draws from Cursor's own pool (Composer and the Grok
/// models, the plan's `autoBucketModels`) rather than the third-party API pool
/// (Claude, GPT, Gemini, ...). Pure.
fn cursor_model_is_first_party(model: &str) -> bool {
    ["default", "auto", "composer", "vega", "grok", "cursor-grok"]
        .iter()
        .any(|prefix| {
            model
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(['-', '.']))
        })
}

/// What the footer ring reads: for Cursor, the window of the pool the selected
/// model draws from (first-party "Cursor" or third-party "Other"); otherwise,
/// or while that window is missing, the most-used window. Pure.
pub fn ring_fraction(
    account: &AgentAccount,
    harness: HarnessId,
    model: Option<&str>,
) -> Option<f32> {
    if harness == HarnessId::Cursor
        && let Some(model) = model
    {
        let label = if cursor_model_is_first_party(model) {
            zeron_proto::CURSOR_USAGE_CURSOR
        } else {
            zeron_proto::CURSOR_USAGE_OTHER
        };
        if let Some(window) = account.usage_windows.iter().find(|w| w.label == label) {
            return Some(window.used_fraction.clamp(0.0, 1.0));
        }
    }
    used_fraction(account)
}

/// The account whose usage a turn of `harness` on `model` spends, when it
/// reports usage: the harness's live login — except Droid, whose custom
/// models may spend another plan (or none) than Factory's. Pure.
pub fn active_account<'a>(
    snapshot: &'a AgentAccountsSnapshot,
    harness: HarnessId,
    model: Option<&str>,
) -> Option<&'a AgentAccount> {
    if harness == HarnessId::Droid {
        return accounts::droid_plan_row(snapshot, model);
    }
    snapshot
        .accounts
        .iter()
        .find(|account| account.harness == harness && account.active)
}

/// Loads (and switches) the accounts of the composer's target device.
pub struct AccountUsage {
    state: Entity<AppState>,
    /// `None` = this device, as in [`AccountsSnapshotCache`].
    target: Option<String>,
    harness: Option<HarnessId>,
    /// The composer's selected model: Cursor's ring follows its pool.
    model: Option<String>,
    /// Once any list has been asked for the current target.
    loaded: bool,
    last_forced: Option<Instant>,
    error: Option<SharedString>,
    load_task: Option<Task<()>>,
    action_task: Option<Task<()>>,
    popup: popover::Popup<FooterCard>,
    _poll: Task<()>,
    _cache: Subscription,
    _state: Subscription,
}

impl AccountUsage {
    pub fn new(state: Entity<AppState>, cx: &mut Context<Self>) -> Self {
        let poll = cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(POLL_INTERVAL).await;
                if this
                    .update(cx, |usage, cx| {
                        if usage.harness.is_some() {
                            usage.load(true, cx);
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            _state: cx.observe(&state, |_, _, cx| cx.notify()),
            state,
            target: None,
            harness: None,
            model: None,
            loaded: false,
            last_forced: None,
            error: None,
            load_task: None,
            action_task: None,
            popup: popover::Popup::default(),
            _poll: poll,
            // Settings → Accounts writes the same cache.
            _cache: cx.observe_global::<AccountsSnapshotCache>(|_, cx| cx.notify()),
        }
    }

    /// Point at the session's harness and device; loads on first sight of a
    /// device. Cheap enough to call every render.
    pub fn track(
        &mut self,
        harness: Option<HarnessId>,
        model: Option<String>,
        target: Option<String>,
        cx: &mut Context<Self>,
    ) {
        let harness = harness.filter(|h| signs_in(*h) && reports_usage(*h));
        self.harness = harness;
        self.model = model;
        if self.target != target {
            self.target = target;
            self.loaded = false;
            self.last_forced = None;
            self.error = None;
        }
        if harness.is_some() && !self.loaded {
            self.loaded = true;
            self.load(true, cx);
        }
    }

    fn snapshot<'a>(&self, cx: &'a gpui::App) -> Option<&'a AgentAccountsSnapshot> {
        cx.try_global::<AccountsSnapshotCache>()?
            .0
            .get(&self.target)
    }

    fn params(&self, mut value: serde_json::Value) -> serde_json::Value {
        if let (Some(target), Some(object)) = (&self.target, value.as_object_mut()) {
            object.insert("targetDeviceId".into(), serde_json::json!(target));
        }
        value
    }

    /// Plain list first when nothing is cached (the engine's persisted usage
    /// paints at once), then the forced probe replaces it.
    fn load(&mut self, force_usage: bool, cx: &mut Context<Self>) {
        if force_usage {
            if self
                .last_forced
                .is_some_and(|at| at.elapsed() < FORCE_MIN_INTERVAL)
            {
                return;
            }
            self.last_forced = Some(Instant::now());
        }
        let Some(engine) = self.state.read(cx).engine().cloned() else {
            return;
        };
        let key = self.target.clone();
        let paint_first = force_usage && self.snapshot(cx).is_none();
        let plain = self.params(serde_json::json!({ "forceUsage": false }));
        let params = self.params(serde_json::json!({ "forceUsage": force_usage }));
        self.load_task = Some(cx.spawn(async move |this, cx| {
            let fetch = |params: serde_json::Value| {
                let engine = engine.clone();
                async move {
                    engine
                        .client()
                        .call(methods::LIST_AGENT_ACCOUNTS, params)
                        .await
                        .ok()
                        .and_then(|value| {
                            serde_json::from_value::<AgentAccountsSnapshot>(value).ok()
                        })
                }
            };
            let store = |snapshot: AgentAccountsSnapshot, cx: &mut gpui::AsyncApp| {
                let key = key.clone();
                this.update(cx, |_, cx| {
                    cx.default_global::<AccountsSnapshotCache>()
                        .0
                        .insert(key, snapshot);
                })
                .ok();
            };
            if paint_first && let Some(snapshot) = fetch(plain).await {
                store(snapshot, cx);
            }
            if let Some(snapshot) = fetch(params).await {
                store(snapshot, cx);
            }
        }));
    }

    /// Switch optimistically, like Settings → Accounts: the rows flip at once
    /// and the engine's reply replaces them; a refusal restores the list.
    fn switch(&mut self, account: &AgentAccount, cx: &mut Context<Self>) {
        let Some(engine) = self.state.read(cx).engine().cloned() else {
            return;
        };
        let key = self.target.clone();
        let cache = &mut cx.default_global::<AccountsSnapshotCache>().0;
        let previous = cache.get(&key).cloned();
        if let Some(snapshot) = cache.get_mut(&key) {
            // Per-provider agents keep one live login per provider: only the
            // switched-to row's group changes.
            accounts::mark_switched(snapshot, account);
        }
        self.error = None;
        let params = self.params(serde_json::json!({
            "id": account.id,
            "accountId": account.id,
            "harness": account.harness,
        }));
        self.action_task = Some(cx.spawn(async move |this, cx| {
            let result = engine
                .client()
                .call(methods::ACTIVATE_AGENT_ACCOUNT, params)
                .await;
            this.update(cx, |usage, cx| {
                match result.map(serde_json::from_value::<AgentAccountsSnapshot>) {
                    Ok(Ok(snapshot)) => {
                        cx.default_global::<AccountsSnapshotCache>()
                            .0
                            .insert(key, snapshot);
                    }
                    Ok(Err(_)) => usage.load(false, cx),
                    Err(err) => {
                        if let Some(previous) = previous {
                            cx.default_global::<AccountsSnapshotCache>()
                                .0
                                .insert(key, previous);
                        }
                        usage.error = Some(err.to_string().into());
                    }
                }
                cx.notify();
            })
            .ok();
        }));
        cx.notify();
    }

    /// The ring's reading: the live account's window for the selected model
    /// (the most-used one when the harness doesn't split by model), when the
    /// harness has a live account with usage to show.
    fn fraction(&self, cx: &gpui::App) -> Option<f32> {
        let harness = self.harness?;
        ring_fraction(
            active_account(self.snapshot(cx)?, harness, self.model.as_deref())?,
            harness,
            self.model.as_deref(),
        )
    }

    /// A trigger click: open this ring's popover, or close it when the
    /// press found it open (the card's mouse-down-out already began that
    /// close — see `Popup::note_trigger_press`).
    fn toggle(&mut self, card: FooterCard, cx: &mut Context<Self>) {
        if self.popup.take_press_was_open() || self.popup.as_open() == Some(&card) {
            self.dismiss(cx);
            return;
        }
        if card == FooterCard::Accounts {
            // Opening the card is the moment someone cares: re-probe.
            self.load(true, cx);
        }
        self.popup.open(card);
        cx.notify();
    }

    fn dismiss(&mut self, cx: &mut Context<Self>) {
        if self.popup.begin_close() {
            popover::reap_popup(cx, |usage: &mut Self| &mut usage.popup);
        }
        cx.notify();
    }

    /// A footer ring that opens `card` above itself, right-aligned like the
    /// model picker.
    fn trigger(
        &self,
        chip: gpui::Stateful<gpui::Div>,
        card: FooterCard,
        content: impl FnOnce(&Self, &mut Context<Self>) -> gpui::Div,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let chip = chip
            .relative()
            .on_mouse_down(
                gpui::MouseButton::Left,
                cx.listener(move |usage, _, _, _| {
                    usage
                        .popup
                        .note_trigger_press_matching(|open| *open == card);
                }),
            )
            .on_click(cx.listener(move |usage, _, _, cx| usage.toggle(card, cx)));
        if self.popup.get() != Some(&card) {
            return chip.into_any_element();
        }
        let content = content(self, cx)
            .on_mouse_down_out(cx.listener(|usage, _, _, cx| usage.dismiss(cx)))
            .into_any_element();
        chip.child(popover::anchored_menu_above_end(
            card.id(),
            content,
            self.popup.closing_since(),
        ))
        .into_any_element()
    }

    fn accounts_card(&self, cx: &mut Context<Self>) -> gpui::Div {
        let theme = &Theme::of(cx).for_popup();
        let harness = self.harness;
        let now = chrono::Utc::now();
        // Droid lists the plans its models can spend (Factory's, and the
        // Claude / ChatGPT accounts its custom models are served from), each
        // a live login of its own agent; the one in use is the plan the
        // selected model spends.
        let droid = harness == Some(HarnessId::Droid);
        let rows: Vec<AgentAccount> = match (harness, self.snapshot(cx)) {
            (Some(HarnessId::Droid), Some(snapshot)) => accounts::droid_plan_rows(snapshot)
                .into_iter()
                .cloned()
                .collect(),
            (Some(harness), Some(snapshot)) => accounts::provider_accounts(snapshot, harness)
                .into_iter()
                .cloned()
                .collect(),
            _ => Vec::new(),
        };
        let unsigned: Vec<HarnessId> = match (droid, self.snapshot(cx)) {
            (true, Some(snapshot)) => accounts::droid_unsigned_plans(snapshot),
            _ => Vec::new(),
        };
        let title = if droid {
            "Droid plans".to_string()
        } else {
            format!(
                "{} accounts",
                harness.map_or("Agent", accounts::provider_name)
            )
        };
        let droid_in_use: Option<String> = match (droid, self.snapshot(cx)) {
            (true, Some(snapshot)) => {
                accounts::droid_plan_row(snapshot, self.model.as_deref()).map(|a| a.id.clone())
            }
            _ => None,
        };
        popover::popover_card(theme)
            .w(px(400.0))
            .flex()
            .flex_col()
            .child(popover::menu_heading(theme, &title))
            .children(rows.iter().enumerate().map(|(ix, account)| {
                let email: SharedString = account
                    .email
                    .clone()
                    .or_else(|| account.display_name.clone())
                    .unwrap_or_else(|| "Unknown account".into())
                    .into();
                let in_use = if droid {
                    droid_in_use.as_deref() == Some(account.id.as_str())
                } else {
                    account.active
                };
                let can_switch = !account.active && account.switchable;
                // Whose plan a Droid row is: its own agent's.
                let source = droid.then(|| match account.harness {
                    HarnessId::Droid => "Factory",
                    other => accounts::provider_name(other),
                });
                let mut meta: Vec<gpui::AnyElement> = source
                    .map(str::to_string)
                    .into_iter()
                    .chain(account.plan_label.clone())
                    .map(|part| div().child(SharedString::from(part)).into_any_element())
                    .collect();
                if in_use {
                    meta.push(
                        div()
                            .text_color(theme.accent)
                            .child(SharedString::from("In use"))
                            .into_any_element(),
                    );
                }
                // A live login's reason shows beside its meters; Droid's
                // rows say why they have none even while in use.
                if let Some(reason) = account
                    .usage_error
                    .clone()
                    .filter(|_| account.usage_windows.is_empty() && (!in_use || droid))
                {
                    meta.push(div().child(SharedString::from(reason)).into_any_element());
                }
                let switch_to = account.clone();
                popover::menu_row(theme, in_use, format!("account-usage-row-{ix}"))
                    .id(("account-usage-row", ix))
                    .when(!can_switch, |row| row.cursor_default())
                    .when(can_switch, |row| {
                        row.on_click(cx.listener(move |usage, _, _, cx| {
                            usage.switch(&switch_to, cx);
                        }))
                    })
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .truncate()
                                    .text_size(px(12.5))
                                    .font_weight(gpui::FontWeight::MEDIUM)
                                    .child(email),
                            )
                            .when(!meta.is_empty(), |el| {
                                el.child(crate::settings::widgets::meta_line(theme, meta))
                            }),
                    )
                    .child(
                        div()
                            .id(("account-usage-meters", ix))
                            .flex_none()
                            .flex()
                            .flex_col()
                            .gap(px(2.0))
                            .when(!account.usage_windows.is_empty(), |meters| {
                                meters.tooltip(widgets::text_tooltip(accounts::usage_resets(
                                    &account.usage_windows,
                                    now,
                                )))
                            })
                            .children(
                                account
                                    .usage_windows
                                    .iter()
                                    .map(|window| render_usage_meter(window, theme)),
                            ),
                    )
            }))
            .children(unsigned.into_iter().map(|harness| {
                div()
                    .px(px(8.0))
                    .py(px(4.0))
                    .text_size(px(12.0))
                    .text_color(theme.text_muted)
                    .child(SharedString::from(format!(
                        "{} isn't signed in here, so its usage can't be shown",
                        accounts::provider_name(harness)
                    )))
            }))
            .children(self.error.clone().map(|error| {
                div()
                    .px(px(8.0))
                    .py(px(4.0))
                    .text_size(px(12.0))
                    .text_color(theme.danger)
                    .child(error)
            }))
    }
}

/// Which footer ring's popover is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FooterCard {
    Accounts,
    Context,
}

impl FooterCard {
    fn id(self) -> &'static str {
        match self {
            FooterCard::Accounts => "account-usage-menu",
            FooterCard::Context => "context-usage-menu",
        }
    }
}

/// The footer's ring cluster: account usage (accent arc, so the two read
/// apart), then context occupancy. Each opens its popover on click.
impl Render for AccountUsage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::of(cx).clone();
        let context = self.state.read(cx).context_usage;
        let account = self.fraction(cx).map(|fraction| {
            let level = usage_level(fraction);
            let chip = crate::context_usage::ring_chip(
                "account-usage",
                fraction,
                usage_color(level, &theme),
                match level {
                    UsageLevel::Normal => theme.text_muted,
                    _ => usage_color(level, &theme),
                },
                format!("{}%", (fraction * 100.0).round() as u32),
                self.popup.get() == Some(&FooterCard::Accounts),
                &theme,
            );
            self.trigger(
                chip,
                FooterCard::Accounts,
                |usage, cx| usage.accounts_card(cx),
                cx,
            )
        });
        let context = crate::context_usage::has_window(context).then(|| {
            let chip = crate::context_usage::chip(
                context,
                self.popup.get() == Some(&FooterCard::Context),
                &theme,
            );
            self.trigger(
                chip,
                FooterCard::Context,
                move |_, cx| crate::context_usage::card(context, &Theme::of(cx).for_popup()),
                cx,
            )
        });
        div()
            .flex()
            .items_center()
            .gap(px(4.0))
            .children(account)
            .children(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeron_proto::AgentUsageWindow;

    fn account(harness: HarnessId, active: bool, used: &[f32]) -> AgentAccount {
        serde_json::from_value(serde_json::json!({
            "id": format!("{harness:?}-{active}"),
            "harness": harness,
            "email": null,
            "planLabel": null,
            "active": active,
            "switchable": true,
            "usageWindows": used
                .iter()
                .map(|fraction| AgentUsageWindow {
                    label: "5h".into(),
                    used_fraction: *fraction,
                    resets_at: None,
                })
                .collect::<Vec<_>>(),
        }))
        .unwrap()
    }

    #[test]
    fn ring_shows_the_most_used_window() {
        assert_eq!(used_fraction(&account(HarnessId::Codex, true, &[])), None);
        assert_eq!(
            used_fraction(&account(HarnessId::Codex, true, &[0.12, 0.64])),
            Some(0.64)
        );
        assert_eq!(
            used_fraction(&account(HarnessId::Codex, true, &[1.4])),
            Some(1.0)
        );
    }

    #[test]
    fn cursor_ring_follows_the_selected_models_pool() {
        let mut cursor = account(HarnessId::Cursor, true, &[0.5, 0.01, 0.48]);
        for (window, label) in cursor.usage_windows.iter_mut().zip([
            zeron_proto::CURSOR_USAGE_CURSOR,
            zeron_proto::CURSOR_USAGE_GROK,
            zeron_proto::CURSOR_USAGE_OTHER,
        ]) {
            window.label = label.into();
        }
        let ring = |model| ring_fraction(&cursor, HarnessId::Cursor, model);
        assert_eq!(ring(Some("composer-2.5")), Some(0.5));
        assert_eq!(ring(Some("grok-4.7")), Some(0.5));
        assert_eq!(ring(Some("default")), Some(0.5));
        assert_eq!(ring(Some("claude-opus-5-5")), Some(0.48));
        assert_eq!(ring(Some("gpt-5.5")), Some(0.48));
        // "grokker" is not a Grok model; no model yet falls back to the most used.
        assert_eq!(ring(Some("grokker-1")), Some(0.48));
        assert_eq!(ring(None), Some(0.5));
        // Other harnesses ignore the model, and a missing pool falls back too.
        let codex = account(HarnessId::Codex, true, &[0.12, 0.64]);
        assert_eq!(
            ring_fraction(&codex, HarnessId::Codex, Some("gpt-5.5")),
            Some(0.64)
        );
        let lone = account(HarnessId::Cursor, true, &[0.3]);
        assert_eq!(
            ring_fraction(&lone, HarnessId::Cursor, Some("gpt-5.5")),
            Some(0.3)
        );
    }

    #[test]
    fn active_account_is_scoped_to_the_harness() {
        let snapshot = AgentAccountsSnapshot {
            accounts: vec![
                account(HarnessId::ClaudeCode, true, &[0.3]),
                account(HarnessId::Codex, false, &[0.1]),
                account(HarnessId::Codex, true, &[0.2]),
            ],
            ..Default::default()
        };
        assert_eq!(
            active_account(&snapshot, HarnessId::Codex, None).map(|a| a.id.as_str()),
            Some("Codex-true")
        );
        assert!(active_account(&snapshot, HarnessId::Cursor, None).is_none());
    }

    #[test]
    fn droids_ring_follows_the_plan_the_model_spends() {
        let snapshot = AgentAccountsSnapshot {
            accounts: vec![
                account(HarnessId::Droid, true, &[1.0]),
                account(HarnessId::ClaudeCode, true, &[0.3]),
            ],
            model_plans: [("custom:Claude-0".to_string(), HarnessId::ClaudeCode)].into(),
            ..Default::default()
        };
        let ring = |model: Option<&str>| {
            active_account(&snapshot, HarnessId::Droid, model)
                .and_then(|account| ring_fraction(account, HarnessId::Droid, model))
        };
        assert_eq!(ring(Some("claude-opus-5-5")), Some(1.0));
        assert_eq!(ring(Some("custom:Claude-0")), Some(0.3));
        // A local model spends no plan: no ring at all.
        assert_eq!(ring(Some("custom:Local-0")), None);
    }
}
