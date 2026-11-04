//! Caches remote users in AccountsService after they log in through cosmic-greeter, like GDM
//! does, so that they keep being listed on the login screen after logging out.

use cosmic_greeter_daemon::accounts;
use futures_util::StreamExt;
use std::{
    collections::{HashSet, VecDeque},
    fs,
    time::Duration,
};
use zbus::Connection;
use zbus::zvariant::OwnedObjectPath;
use zbus_systemd::login1::{ManagerProxy, SessionProxy};

const DEFAULT_PAM_SERVICE: &str = "cosmic-greeter";
const GREETD_DEFAULT_PAM_SERVICE: &str = "greetd";
const GREETD_CONFIG_PATH: &str = "/etc/greetd/cosmic-greeter.toml";
const MAX_CACHE_ATTEMPTS: u32 = 8;
const MAX_CACHE_TASKS: usize = 4;
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

#[derive(serde::Deserialize)]
struct GreetdConfig {
    general: Option<GeneralConfig>,
}

#[derive(serde::Deserialize)]
struct GeneralConfig {
    service: Option<String>,
}

fn configured_pam_service(data: &str) -> Option<String> {
    basic_toml::from_str::<GreetdConfig>(data)
        .ok()?
        .general?
        .service
}

fn pam_service_from(config: Option<&str>) -> String {
    match config {
        Some(data) => configured_pam_service(data)
            .filter(|service| !service.is_empty())
            .unwrap_or_else(|| GREETD_DEFAULT_PAM_SERVICE.to_string()),
        None => DEFAULT_PAM_SERVICE.to_string(),
    }
}

pub fn pam_service() -> String {
    let config = match fs::read_to_string(GREETD_CONFIG_PATH) {
        Ok(config) => Some(config),
        Err(err) => {
            tracing::warn!("failed to read greetd config {GREETD_CONFIG_PATH:?}: {err:?}");
            None
        }
    };
    pam_service_from(config.as_deref())
}

//IMPORTANT: This task may run while run_as_user has switched the effective user of the process.
// It must only talk over the existing D-Bus connection, whose credentials were recorded by the
// bus when it connected as root, and must not use NSS (getpwnam is not thread safe).
pub async fn run(connection: Connection, pam_service: String) {
    // The daemon keeps running when watching fails, so systemd would not restart it: retry here
    let mut backoff = MIN_BACKOFF;
    loop {
        match watch_sessions(&connection, &pam_service).await {
            Ok(()) => {
                tracing::warn!("logind session signals ended, watching again");
                backoff = MIN_BACKOFF;
            }
            Err(err) => {
                tracing::error!(
                    "failed to watch logind sessions, retrying in {backoff:?}: {err:?}"
                );
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn watch_sessions(connection: &Connection, pam_service: &str) -> zbus::Result<()> {
    let manager = ManagerProxy::new(connection).await?;
    let mut handled_sessions = HashSet::new();
    let mut pending_sessions = VecDeque::new();
    let mut cache_tasks = tokio::task::JoinSet::new();

    // Subscribe before listing, so sessions created in between are not missed
    let mut session_new = manager.receive_session_new().await?;
    let mut session_removed = manager.receive_session_removed().await?;

    // Catch up on users that logged in while the daemon was not running
    for (_, _, _, _, path) in manager.list_sessions().await? {
        if handled_sessions.insert(path.clone()) {
            pending_sessions.push_back(path);
        }
    }
    while cache_tasks.len() < MAX_CACHE_TASKS
        && let Some(path) = pending_sessions.pop_front()
    {
        cache_tasks.spawn(cache_session_user(
            connection.clone(),
            path,
            pam_service.to_string(),
        ));
    }

    loop {
        tokio::select! {
            signal = session_new.next() => {
                let Some(signal) = signal else {
                    return Ok(());
                };
                match signal.args() {
                    Ok(args) => {
                        let path = args.object_path().clone();
                        if handled_sessions.insert(path.clone()) {
                            pending_sessions.push_back(path);
                        }
                    }
                    Err(err) => tracing::warn!("invalid SessionNew signal: {err:?}"),
                }
                while cache_tasks.len() < MAX_CACHE_TASKS
                    && let Some(path) = pending_sessions.pop_front()
                {
                    cache_tasks.spawn(cache_session_user(
                        connection.clone(),
                        path,
                        pam_service.to_string(),
                    ));
                }
            }
            signal = session_removed.next() => {
                let Some(signal) = signal else {
                    return Ok(());
                };
                match signal.args() {
                    Ok(args) => {
                        handled_sessions.remove(args.object_path());
                        pending_sessions.retain(|path| path != args.object_path());
                    }
                    Err(err) => tracing::warn!("invalid SessionRemoved signal: {err:?}"),
                }
            }
            Some(result) = cache_tasks.join_next(), if !cache_tasks.is_empty() => {
                if let Err(err) = result {
                    tracing::warn!("remote user cache task failed: {err:?}");
                }
                while cache_tasks.len() < MAX_CACHE_TASKS
                    && let Some(path) = pending_sessions.pop_front()
                {
                    cache_tasks.spawn(cache_session_user(
                        connection.clone(),
                        path,
                        pam_service.to_string(),
                    ));
                }
            }
        }
    }
}

async fn cache_session_user(connection: Connection, path: OwnedObjectPath, pam_service: String) {
    let mut user_opt = None;
    let mut backoff = MIN_BACKOFF;
    for attempt in 0..MAX_CACHE_ATTEMPTS {
        if user_opt.is_none() {
            match greeter_session_user(&connection, path.clone(), &pam_service).await {
                Ok(Some(user)) => user_opt = Some(user),
                Ok(None) => return,
                Err(err) => {
                    tracing::warn!("failed to read logind session {path:?}: {err:?}");
                }
            }
        }

        if let Some((name, uid)) = user_opt.as_ref() {
            match accounts::cache_remote_user(&connection, name, *uid).await {
                Ok(true) => {
                    tracing::info!("cached remote user {name:?} in AccountsService");
                    return;
                }
                Ok(false) => return,
                Err(err) => {
                    tracing::warn!("failed to cache user {name:?} in AccountsService: {err:?}");
                }
            }
        }

        if attempt + 1 < MAX_CACHE_ATTEMPTS {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    tracing::warn!("stopped retrying AccountsService caching for logind session {path:?}");
}

/// Returns the user of a session if it is a local user session started by cosmic-greeter.
async fn greeter_session_user(
    connection: &Connection,
    path: OwnedObjectPath,
    pam_service: &str,
) -> zbus::Result<Option<(String, u32)>> {
    let session = SessionProxy::new(connection, path).await?;

    // Skips the greeter itself (class "greeter") and SSH or other remote logins
    if session.service().await? != pam_service
        || session.remote().await?
        || session.class().await? != "user"
    {
        return Ok(None);
    }

    let uid = session.user().await?.0;
    Ok(Some((session.name().await?, uid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_configured_pam_service() {
        let data = r#"
            [terminal]
            vt = "1"
            [general]
            service = "custom-greeter"
            [default_session]
            service = "session-service"
        "#;
        assert_eq!(pam_service_from(Some(data)), "custom-greeter");
        assert_eq!(
            configured_pam_service("[general]\nservice = 'custom-greeter'").as_deref(),
            Some("custom-greeter")
        );
    }

    #[test]
    fn reads_pam_service_with_toml_comments() {
        let data = "[general] # login\nservice = \"custom-greeter\" # PAM service";
        assert_eq!(pam_service_from(Some(data)), "custom-greeter");
    }

    #[test]
    fn missing_empty_or_invalid_pam_service_uses_greetd_default() {
        assert_eq!(
            pam_service_from(Some("[general]")),
            GREETD_DEFAULT_PAM_SERVICE
        );
        assert_eq!(
            pam_service_from(Some("[general]\nservice = \"\"")),
            GREETD_DEFAULT_PAM_SERVICE
        );
        assert_eq!(
            pam_service_from(Some("[general]\nservice =")),
            GREETD_DEFAULT_PAM_SERVICE
        );
        assert_eq!(
            pam_service_from(Some("[default_session]\nservice = \"session-service\"")),
            GREETD_DEFAULT_PAM_SERVICE
        );
    }

    #[test]
    fn unreadable_config_uses_cosmic_default() {
        assert_eq!(pam_service_from(None), DEFAULT_PAM_SERVICE);
    }
}
