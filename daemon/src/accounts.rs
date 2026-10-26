//! Minimal client for the org.freedesktop.Accounts (AccountsService) D-Bus service.

use zbus::{Connection, proxy, proxy::CacheProperties, zvariant::OwnedObjectPath};

#[proxy(
    interface = "org.freedesktop.Accounts",
    default_service = "org.freedesktop.Accounts",
    default_path = "/org/freedesktop/Accounts"
)]
pub trait Accounts {
    fn list_cached_users(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    fn find_user_by_name(&self, name: &str) -> zbus::Result<OwnedObjectPath>;

    fn cache_user(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    interface = "org.freedesktop.Accounts.User",
    default_service = "org.freedesktop.Accounts"
)]
pub trait AccountsUser {
    #[zbus(property)]
    fn user_name(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn real_name(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn icon_file(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;

    #[zbus(property)]
    fn system_account(&self) -> zbus::Result<bool>;

    #[zbus(property)]
    fn local_account(&self) -> zbus::Result<bool>;
}

#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub real_name: String,
    pub icon_file: String,
}

/// Lists the users AccountsService considers suitable for a login screen: human users from
/// /etc/passwd, systemd-homed users, and remote users that were cached after logging in.
pub async fn list_users(connection: &Connection) -> zbus::Result<Vec<User>> {
    let accounts = AccountsProxy::new(connection).await?;

    let mut users = Vec::new();
    for path in accounts.list_cached_users().await? {
        // A user may be removed while the list is read, so one failure must not drop the others
        match read_user(connection, path.clone()).await {
            Ok(Some(user)) => users.push(user),
            Ok(None) => {}
            Err(err) => tracing::warn!("failed to read AccountsService user {path:?}: {err:?}"),
        }
    }

    Ok(users)
}

/// Reads a user, returning `None` for users that should not be shown
async fn read_user(connection: &Connection, path: OwnedObjectPath) -> zbus::Result<Option<User>> {
    let user = AccountsUserProxy::builder(connection)
        .path(path)?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    // Same exclusions as the GNOME Shell login dialog
    if user.system_account().await? || user.locked().await? {
        return Ok(None);
    }

    Ok(Some(User {
        name: user.user_name().await?,
        real_name: user.real_name().await?,
        icon_file: user.icon_file().await?,
    }))
}

/// Caches a remote (e.g. LDAP, SSSD or AD) user so AccountsService keeps listing them after they
/// log out. Local users are already listed from /etc/passwd and are left alone. Returns whether
/// the user was cached. This is what GDM does after a successful login, and requires root.
pub async fn cache_remote_user(connection: &Connection, name: &str) -> zbus::Result<bool> {
    let accounts = AccountsProxy::new(connection).await?;
    let path = accounts.find_user_by_name(name).await?;
    let user = AccountsUserProxy::builder(connection)
        .path(path)?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;

    if user.local_account().await? || user.system_account().await? {
        return Ok(false);
    }

    accounts.cache_user(name).await?;
    Ok(true)
}
