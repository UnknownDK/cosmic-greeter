//! Caches remote users in AccountsService after they log in through cosmic-greeter, like GDM
//! does, so that they keep being listed on the login screen after logging out.

use cosmic_greeter_daemon::accounts;
use futures_util::StreamExt;
use std::time::Duration;
use zbus::Connection;
use zbus::zvariant::OwnedObjectPath;
use zbus_systemd::login1::{ManagerProxy, SessionProxy};

/// PAM service greetd uses for user sessions, set in cosmic-greeter.toml
const PAM_SERVICE: &str = "cosmic-greeter";

const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

//IMPORTANT: This task may run while run_as_user has switched the effective user of the process.
// It must only talk over the existing D-Bus connection, whose credentials were recorded by the
// bus when it connected as root, and must not use NSS (getpwnam is not thread safe).
pub async fn run(connection: Connection) {
    // The daemon keeps running when watching fails, so systemd would not restart it: retry here
    let mut backoff = MIN_BACKOFF;
    loop {
        match watch_sessions(&connection).await {
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

async fn watch_sessions(connection: &Connection) -> zbus::Result<()> {
    let manager = ManagerProxy::new(connection).await?;

    // Subscribe before listing, so sessions created in between are not missed
    let mut session_new = manager.receive_session_new().await?;

    // Catch up on users that logged in while the daemon was not running
    for (_, _, _, _, path) in manager.list_sessions().await? {
        cache_session_user(connection, path).await;
    }

    while let Some(signal) = session_new.next().await {
        match signal.args() {
            Ok(args) => cache_session_user(connection, args.object_path().clone()).await,
            Err(err) => tracing::warn!("invalid SessionNew signal: {err:?}"),
        }
    }

    Ok(())
}

async fn cache_session_user(connection: &Connection, path: OwnedObjectPath) {
    let name = match greeter_session_user(connection, path.clone()).await {
        Ok(Some(name)) => name,
        Ok(None) => return,
        Err(err) => {
            tracing::warn!("failed to read logind session {path:?}: {err:?}");
            return;
        }
    };

    match accounts::cache_remote_user(connection, &name).await {
        Ok(true) => tracing::info!("cached remote user {name:?} in AccountsService"),
        Ok(false) => {}
        Err(err) => tracing::warn!("failed to cache user {name:?} in AccountsService: {err:?}"),
    }
}

/// Returns the user of a session if it is a local user session started by cosmic-greeter.
/// logind only registers a session after PAM authentication and account checks succeeded.
async fn greeter_session_user(
    connection: &Connection,
    path: OwnedObjectPath,
) -> zbus::Result<Option<String>> {
    let session = SessionProxy::new(connection, path).await?;

    // Skips the greeter itself (class "greeter") and SSH or other remote logins
    if session.service().await? != PAM_SERVICE
        || session.remote().await?
        || !session.class().await?.starts_with("user")
    {
        return Ok(None);
    }

    Ok(Some(session.name().await?))
}
