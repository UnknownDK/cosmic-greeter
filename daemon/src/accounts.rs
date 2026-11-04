//! Minimal client for the org.freedesktop.Accounts (AccountsService) D-Bus service.

use std::collections::BTreeSet;
use zbus::{Connection, proxy, zvariant::OwnedObjectPath};

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
    fn uid(&self) -> zbus::Result<u64>;

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
pub(crate) struct User {
    pub name: String,
    pub real_name: String,
    pub icon_file: String,
}

pub(crate) struct UserList {
    pub users: Vec<User>,
    pub excluded_names: BTreeSet<String>,
    pub complete: bool,
}

enum ReadUser {
    Included(User),
    Excluded(String),
}

/// Lists the users AccountsService considers suitable for a login screen: human users from
/// /etc/passwd, systemd-homed users, and remote users that were cached after logging in.
pub(crate) async fn list_users(connection: &Connection) -> zbus::Result<UserList> {
    let accounts = AccountsProxy::new(connection).await?;

    let mut users = Vec::new();
    let mut excluded_names = BTreeSet::new();
    let mut complete = true;
    for path in accounts.list_cached_users().await? {
        // A user may be removed while the list is read, so one failure must not drop the others
        match read_user(connection, path.clone()).await {
            Ok(ReadUser::Included(user)) => users.push(user),
            Ok(ReadUser::Excluded(name)) => {
                excluded_names.insert(name);
            }
            Err(err) => {
                tracing::warn!("failed to read AccountsService user {path:?}: {err:?}");
                complete = false;
            }
        }
    }

    Ok(UserList {
        users,
        excluded_names,
        complete,
    })
}

async fn read_user(connection: &Connection, path: OwnedObjectPath) -> zbus::Result<ReadUser> {
    let user = AccountsUserProxy::new(connection, path).await?;
    let name = user.user_name().await?;

    // Same exclusions as the GNOME Shell login dialog
    if user.system_account().await? || user.locked().await? {
        return Ok(ReadUser::Excluded(name));
    }

    let real_name = user
        .real_name()
        .await
        .inspect_err(|err| tracing::warn!("failed to read real name for {name:?}: {err:?}"))
        .unwrap_or_default();
    let icon_file = user
        .icon_file()
        .await
        .inspect_err(|err| tracing::warn!("failed to read icon file for {name:?}: {err:?}"))
        .unwrap_or_default();

    Ok(ReadUser::Included(User {
        name,
        real_name,
        icon_file,
    }))
}

pub(crate) async fn user_by_name(
    connection: &Connection,
    name: &str,
) -> zbus::Result<Option<User>> {
    let accounts = AccountsProxy::new(connection).await?;
    let path = accounts.find_user_by_name(name).await?;
    Ok(match read_user(connection, path).await? {
        ReadUser::Included(user) => Some(user),
        ReadUser::Excluded(_) => None,
    })
}

/// Caches a remote (e.g. LDAP, SSSD or AD) user so AccountsService keeps listing them after they
/// log out. Local users are already listed from /etc/passwd and are left alone. Returns whether
/// the user was cached. This is what GDM does after a successful login, and requires root.
pub async fn cache_remote_user(
    connection: &Connection,
    name: &str,
    uid: u32,
) -> zbus::Result<bool> {
    let accounts = AccountsProxy::new(connection).await?;
    let path = accounts.find_user_by_name(name).await?;
    let user = AccountsUserProxy::new(connection, path).await?;

    if user.local_account().await? || user.uid().await? != u64::from(uid) {
        return Ok(false);
    }

    accounts.cache_user(name).await?;
    Ok(true)
}
