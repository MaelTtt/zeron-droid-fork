//! Which agents Zeron signs in to and how: the rules every app's provider
//! settings follow (desktop Settings → Providers, the phone's Providers), so
//! the platforms offer the same sign-ins, labels and switching. Pure.

use crate::{AgentAccount, AgentAccountsSnapshot, HarnessId};

/// The providers zeron can sign into, in display order: (harness, name, CLI
/// command — named in the empty-state copy, zeron settings.agents.tsx
/// `PROVIDERS`). Every agent with a login of its own is here; what each one
/// supports is documented engine-side (`agent_accounts` module docs).
pub const PROVIDERS: [(HarnessId, &str, &str); 11] = [
    (HarnessId::ClaudeCode, "Claude Code", "claude"),
    (HarnessId::Codex, "Codex", "codex"),
    (HarnessId::Cursor, "Cursor", "cursor-agent"),
    (HarnessId::Antigravity, "Antigravity", "Antigravity"),
    (HarnessId::Grok, "Grok", "grok login"),
    (HarnessId::Devin, "Devin", "devin auth login"),
    (HarnessId::Opencode, "OpenCode", "opencode auth login"),
    (HarnessId::Pi, "Pi", "pi"),
    (HarnessId::Hermes, "Hermes", "hermes auth add"),
    (HarnessId::Muse, "Muse Code", "muse login"),
    (HarnessId::Droid, "Factory Droid", "droid"),
];

/// Whether `harness` has an Accounts section (and sign-in flow). Pure.
pub fn signs_in(harness: HarnessId) -> bool {
    PROVIDERS
        .iter()
        .any(|(provider, _, _)| *provider == harness)
}

pub fn provider_name(harness: HarnessId) -> &'static str {
    if harness == HarnessId::Fx {
        return "fx";
    }
    PROVIDERS
        .iter()
        .find(|(provider, _, _)| *provider == harness)
        .map_or("this provider", |(_, name, _)| name)
}

/// Whether the provider reports plan usage. One that doesn't shows no meters
/// and no "usage unavailable" note — there is nothing missing. Pure.
pub fn reports_usage(harness: HarnessId) -> bool {
    !matches!(harness, HarnessId::Antigravity | HarnessId::Fx)
}

/// Providers whose agent holds exactly ONE login (Antigravity, Droid): once
/// it is connected there is nothing to add — signing in again only
/// re-confirms it.
pub fn keeps_one_login(harness: HarnessId) -> bool {
    matches!(harness, HarnessId::Antigravity | HarnessId::Droid)
}

/// Whether zeron switches this agent's logins. Hermes rotates through its
/// own credential pool (listed, never reordered); Antigravity keeps one;
/// Droid's login is its own, read for its usage and never rewritten.
pub fn switches_accounts(harness: HarnessId) -> bool {
    !matches!(
        harness,
        HarnessId::Hermes | HarnessId::Antigravity | HarnessId::Fx | HarnessId::Droid
    )
}

/// A standing note under a provider's Accounts label, for an agent whose
/// accounts work differently. Hermes owns its credential pool: zeron lists
/// it and adds to it through Hermes' own CLI, but never switches or removes
/// its entries. Droid signs in through its own `/login`; zeron only reads the
/// account for its plan usage. Pure.
pub fn provider_note(harness: HarnessId) -> Option<&'static str> {
    match harness {
        HarnessId::Hermes => Some(
            "Hermes manages its own credential pool and rotates through it. Accounts added \
             here go through `hermes auth add`; remove one with `hermes auth remove`.",
        ),
        HarnessId::Droid => Some(
            "Droid keeps its own sign-in: run `droid` and use /login to connect an account. \
             zeron reads that account's usage and never changes the login. Custom models \
             served from your Claude or ChatGPT subscription show that plan's usage, from \
             the Claude Code or Codex account signed in here.",
        ),
        _ => None,
    }
}

/// The account whose usage a turn of Droid on `model` spends: Factory's own
/// for its models (and before any model is picked); the Claude Code or Codex
/// account behind a custom model served from a Claude or ChatGPT
/// subscription (`model_plans`); and none for any other custom model, since
/// local or API-billed models use no plan. `None` too when that account isn't
/// listed (not signed in). Pure.
pub fn droid_plan_row<'a>(
    snapshot: &'a AgentAccountsSnapshot,
    model: Option<&str>,
) -> Option<&'a AgentAccount> {
    let harness = match model {
        Some(model) => match snapshot.model_plans.get(model) {
            Some(harness) => *harness,
            // Droid names a custom model `custom:…`; one not mapped to a
            // plan spends none.
            None if model.starts_with("custom:") => return None,
            None => HarnessId::Droid,
        },
        None => HarnessId::Droid,
    };
    live_account(snapshot, harness)
}

/// The rows Droid's usage popover lists: Factory's account, then the live
/// account of each agent whose plan one of Droid's custom models spends. Pure.
pub fn droid_plan_rows(snapshot: &AgentAccountsSnapshot) -> Vec<&AgentAccount> {
    [HarnessId::Droid]
        .into_iter()
        .chain(spent_plans(snapshot))
        .filter_map(|harness| live_account(snapshot, harness))
        .collect()
}

/// The agents whose plan one of Droid's custom models spends but that have
/// no live account here: the usage can't be shown until they sign in. Pure.
pub fn droid_unsigned_plans(snapshot: &AgentAccountsSnapshot) -> Vec<HarnessId> {
    spent_plans(snapshot)
        .filter(|harness| live_account(snapshot, *harness).is_none())
        .collect()
}

/// The agents Droid's custom models draw a plan from, in display order.
fn spent_plans(snapshot: &AgentAccountsSnapshot) -> impl Iterator<Item = HarnessId> {
    [HarnessId::ClaudeCode, HarnessId::Codex]
        .into_iter()
        .filter(|harness| snapshot.model_plans.values().any(|plan| plan == harness))
}

fn live_account(snapshot: &AgentAccountsSnapshot, harness: HarnessId) -> Option<&AgentAccount> {
    snapshot
        .accounts
        .iter()
        .find(|account| account.harness == harness && account.active)
}

/// One way to add an account: agents that keep a login PER model provider
/// (OpenCode, Pi, Hermes) sign in to a named provider; the rest have one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginOption {
    /// The engine's `provider` param (`None` = the agent's only login).
    pub provider: Option<&'static str>,
    /// Who the user signs in to.
    pub label: &'static str,
}

/// The sign-ins zeron offers for `harness`, in button order. Pure.
pub fn login_options(harness: HarnessId) -> Vec<LoginOption> {
    let option = |provider, label| LoginOption {
        provider: Some(provider),
        label,
    };
    match harness {
        // Droid signs in on its own; there is nothing zeron can start.
        HarnessId::Droid => Vec::new(),
        HarnessId::Opencode => vec![
            option("openai", "ChatGPT"),
            option("github-copilot", "GitHub Copilot"),
        ],
        HarnessId::Pi => vec![option("openai-codex", "ChatGPT")],
        HarnessId::Hermes => vec![
            option("openai-codex", "ChatGPT"),
            option("nous", "Nous Portal"),
        ],
        _ => vec![LoginOption {
            provider: None,
            label: provider_name(harness),
        }],
    }
}

/// The list's last row: connect the first account, or add another. Pure.
pub fn add_account_label(harness: HarnessId, empty: bool) -> String {
    if empty {
        format!("Connect a {} account", provider_name(harness))
    } else {
        "Add account".to_string()
    }
}

/// [`add_account_label`] for one [`LoginOption`]: a per-provider sign-in
/// names its provider ("Connect ChatGPT", "Add GitHub Copilot account"). Pure.
pub fn add_option_label(harness: HarnessId, option: LoginOption, empty: bool) -> String {
    match option.provider {
        None => add_account_label(harness, empty),
        Some(_) if empty => format!("Connect {}", option.label),
        Some(_) => format!("Add {} account", option.label),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(harness: HarnessId) -> AgentAccount {
        AgentAccount {
            id: format!("{harness:?}"),
            harness,
            email: None,
            plan_label: None,
            active: true,
            usage_windows: Vec::new(),
            usage_fetched_at: None,
            usage_error: None,
            codex_reset_credits: None,
            display_name: None,
            organization: None,
            auth_kind: None,
            switchable: false,
            saved_at: None,
            provider: None,
        }
    }

    fn snapshot(harnesses: &[HarnessId]) -> AgentAccountsSnapshot {
        AgentAccountsSnapshot {
            accounts: harnesses.iter().map(|h| row(*h)).collect(),
            warnings: Vec::new(),
            model_plans: [
                ("custom:Claude-Opus-0".to_string(), HarnessId::ClaudeCode),
                ("custom:gpt-5-0".to_string(), HarnessId::Codex),
            ]
            .into(),
        }
    }

    #[test]
    fn a_droid_turn_spends_the_plan_its_model_draws_on() {
        let all = snapshot(&[HarnessId::Droid, HarnessId::ClaudeCode, HarnessId::Codex]);
        let harness = |model| droid_plan_row(&all, model).map(|r| r.harness);
        assert_eq!(harness(Some("claude-opus-5-5")), Some(HarnessId::Droid));
        assert_eq!(harness(Some("auto")), Some(HarnessId::Droid));
        assert_eq!(harness(None), Some(HarnessId::Droid));
        assert_eq!(
            harness(Some("custom:Claude-Opus-0")),
            Some(HarnessId::ClaudeCode)
        );
        assert_eq!(harness(Some("custom:gpt-5-0")), Some(HarnessId::Codex));
        // A local or API-billed custom model spends no plan.
        assert_eq!(harness(Some("custom:Local-llama-0")), None);

        // Not signed in to the agent behind a model: nothing to read.
        let no_codex = snapshot(&[HarnessId::Droid, HarnessId::ClaudeCode]);
        assert!(droid_plan_row(&no_codex, Some("custom:gpt-5-0")).is_none());
        let no_factory = snapshot(&[HarnessId::ClaudeCode]);
        assert!(droid_plan_row(&no_factory, Some("auto")).is_none());
        // Only the live account of an agent counts.
        let mut idle = snapshot(&[HarnessId::Droid, HarnessId::ClaudeCode]);
        idle.accounts[1].active = false;
        assert!(droid_plan_row(&idle, Some("custom:Claude-Opus-0")).is_none());
    }

    #[test]
    fn the_popover_lists_factory_then_the_plans_custom_models_spend() {
        let harnesses = |snapshot: &AgentAccountsSnapshot| {
            droid_plan_rows(snapshot)
                .iter()
                .map(|row| row.harness)
                .collect::<Vec<_>>()
        };
        let all = snapshot(&[HarnessId::Codex, HarnessId::ClaudeCode, HarnessId::Droid]);
        assert_eq!(
            harnesses(&all),
            [HarnessId::Droid, HarnessId::ClaudeCode, HarnessId::Codex]
        );
        // A signed-in Codex nobody's model uses is not Droid's business.
        let mut claude_only = all.clone();
        claude_only.model_plans.remove("custom:gpt-5-0");
        assert_eq!(
            harnesses(&claude_only),
            [HarnessId::Droid, HarnessId::ClaudeCode]
        );
        assert_eq!(
            harnesses(&snapshot(&[HarnessId::Droid])),
            [HarnessId::Droid]
        );
    }

    #[test]
    fn a_plan_with_no_signed_in_agent_is_reported_not_dropped() {
        let none = snapshot(&[HarnessId::Droid]);
        assert_eq!(
            droid_unsigned_plans(&none),
            [HarnessId::ClaudeCode, HarnessId::Codex]
        );
        let claude = snapshot(&[HarnessId::Droid, HarnessId::ClaudeCode]);
        assert_eq!(droid_unsigned_plans(&claude), [HarnessId::Codex]);
        let all = snapshot(&[HarnessId::Droid, HarnessId::ClaudeCode, HarnessId::Codex]);
        assert!(droid_unsigned_plans(&all).is_empty());
    }
}
