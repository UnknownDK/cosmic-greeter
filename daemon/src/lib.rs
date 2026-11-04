use cosmic_comp_config::output::randr;
use cosmic_config::CosmicConfigEntry;
use kdl::KdlDocument;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use zbus::Connection;

pub use cosmic_applets_config::time::TimeAppletConfig;
pub use cosmic_bg_config::state::State as BgState;
pub use cosmic_bg_config::{Color, Source as BgSource};
pub use cosmic_comp_config::{CosmicCompConfig, XkbConfig, ZoomConfig};
pub use cosmic_theme::{Theme, ThemeBuilder};

pub mod accounts;

const MAX_ICON_SIZE: usize = 16 * 1024 * 1024;

/// Accounts that are never shown, matching the AccountsService defaults
const EXCLUDED_USERNAMES: &[&str] = &[
    "bin",
    "root",
    "daemon",
    "adm",
    "lp",
    "sync",
    "shutdown",
    "halt",
    "mail",
    "news",
    "uucp",
    "nobody",
    "postgres",
    "pvm",
    "rpm",
    "nfsnobody",
    "pcap",
    "mysql",
    "ftp",
    "games",
    "man",
    "at",
    "gdm",
    "lightdm",
    "gnome-initial-setup",
    "git",
    "greetd",
    "cosmic-greeter",
];

/// Reads /etc/passwd directly instead of enumerating NSS, so that directory services with
/// enumeration enabled do not list every domain account.
fn local_passwd_users() -> io::Result<Vec<pwd::Passwd>> {
    let data = fs::read_to_string("/etc/passwd")?;

    Ok(data
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            let [name, passwd, uid, gid, gecos, dir, shell] = fields[..] else {
                return None;
            };
            Some(pwd::Passwd {
                name: name.to_string(),
                passwd: Some(passwd.to_string()),
                uid: uid.parse().ok()?,
                gid: gid.parse().ok()?,
                gecos: Some(gecos.to_string()),
                dir: dir.to_string(),
                shell: shell.to_string(),
            })
        })
        .collect())
}

pub type LoadedUser = (pwd::Passwd, UserData, Option<PathBuf>);

pub struct LoadedUsers {
    pub users: Vec<LoadedUser>,
    pub complete: bool,
}

enum AccountLookup {
    Included(accounts::User),
    Excluded,
    Unavailable,
}

async fn lookup_account(
    connection: Option<&Connection>,
    accounts_by_name: &mut BTreeMap<String, accounts::User>,
    name: &str,
) -> AccountLookup {
    if let Some(user) = accounts_by_name.remove(name) {
        return AccountLookup::Included(user);
    }
    let Some(connection) = connection else {
        return AccountLookup::Unavailable;
    };
    match accounts::user_by_name(connection, name).await {
        Ok(Some(user)) => AccountLookup::Included(user),
        Ok(None) => AccountLookup::Excluded,
        Err(err) => {
            tracing::warn!("failed to read user {name:?} from AccountsService: {err:?}");
            AccountLookup::Unavailable
        }
    }
}

/// Loads local users and merges cached AccountsService users and their metadata. systemd-homed
/// users are added as well, as older AccountsService versions do not list them.
pub async fn load_users() -> LoadedUsers {
    let user_filter = UserFilter::new().await;
    let mut complete = user_filter.homed_complete;
    let local_users = match local_passwd_users() {
        Ok(users) => users,
        Err(err) => {
            tracing::error!("failed to read /etc/passwd: {err:?}");
            complete = false;
            Vec::new()
        }
    };

    let mut accounts_connection = None;
    let mut accounts_by_name = BTreeMap::new();
    let mut excluded_names = BTreeSet::new();
    match Connection::system().await {
        Ok(connection) => match accounts::list_users(&connection).await {
            Ok(accounts_users) => {
                complete &= accounts_users.complete;
                excluded_names = accounts_users.excluded_names;
                for user in accounts_users.users {
                    accounts_by_name.entry(user.name.clone()).or_insert(user);
                }
                accounts_connection = Some(connection);
            }
            Err(err) => {
                tracing::warn!("failed to list users from AccountsService: {err:?}");
                complete = false;
            }
        },
        Err(err) => {
            tracing::warn!("failed to connect to AccountsService: {err:?}");
            complete = false;
        }
    }

    // The pwd::Passwd methods are unsafe (but not labelled as such) due to using global state (libc getpwnam and getpwuid).
    // To prevent issues, this should only be called once in the entire process space at a time
    let mut users = Vec::new();
    for user in local_users {
        if !user_filter.filter(&user) || excluded_names.contains(&user.name) {
            continue;
        }

        let (user_data, icon_file) = match lookup_account(
            accounts_connection.as_ref(),
            &mut accounts_by_name,
            &user.name,
        )
        .await
        {
            AccountLookup::Included(accounts_user) => UserData::from_accounts(&user, accounts_user),
            AccountLookup::Excluded => continue,
            AccountLookup::Unavailable => (UserData::from(&user), None),
        };
        push_user(&mut users, user, user_data, icon_file);
    }

    for accounts_user in accounts_by_name.values().cloned() {
        let user = match pwd::Passwd::from_name(&accounts_user.name) {
            Ok(Some(user)) => user,
            Ok(None) => {
                tracing::warn!(
                    "user {:?} from AccountsService not found",
                    accounts_user.name
                );
                complete = false;
                continue;
            }
            Err(err) => {
                tracing::warn!("failed to look up user {:?}: {err:?}", accounts_user.name);
                complete = false;
                continue;
            }
        };
        let (user_data, icon_file) = UserData::from_accounts(&user, accounts_user);
        push_user(&mut users, user, user_data, icon_file);
    }

    for &uid in &user_filter.homed_uids {
        if users.iter().any(|(user, ..)| user.uid == uid) {
            continue;
        }
        let Some(user) = pwd::Passwd::from_uid(uid) else {
            tracing::warn!("systemd-homed user with UID {uid} not found");
            complete = false;
            continue;
        };
        if !user_filter.filter(&user) || excluded_names.contains(&user.name) {
            continue;
        }

        let (user_data, icon_file) = match lookup_account(
            accounts_connection.as_ref(),
            &mut accounts_by_name,
            &user.name,
        )
        .await
        {
            AccountLookup::Included(accounts_user) => UserData::from_accounts(&user, accounts_user),
            AccountLookup::Excluded => continue,
            AccountLookup::Unavailable => (UserData::from(&user), None),
        };
        push_user(&mut users, user, user_data, icon_file);
    }

    LoadedUsers { users, complete }
}

fn push_user(
    users: &mut Vec<LoadedUser>,
    user: pwd::Passwd,
    user_data: UserData,
    icon_file: Option<PathBuf>,
) {
    if users
        .iter()
        .any(|(existing, ..)| existing.uid == user.uid || existing.name == user.name)
    {
        return;
    }
    users.push((user, user_data, icon_file));
}

pub struct UserFilter {
    uid_min: u32,
    valid_shells: Option<BTreeSet<String>>,
    homed_uids: BTreeSet<u32>,
    homed_complete: bool,
}

impl UserFilter {
    #[cfg(feature = "systemd")]
    async fn get_homed_uids() -> Result<BTreeSet<u32>, zbus::Error> {
        use zbus_systemd::home1;

        let connection = Connection::system().await?;
        let homed = home1::ManagerProxy::new(&connection).await?;

        let homed_uids = homed
            .list_homes()
            .await?
            .iter()
            .map(|(_, uid, ..)| *uid)
            .collect();

        Ok(homed_uids)
    }

    pub async fn new() -> Self {
        let login_defs_data = fs::read_to_string("/etc/login.defs").unwrap_or_default();
        let login_defs = whitespace_conf::parse(&login_defs_data);

        #[cfg(feature = "systemd")]
        let (homed_uids, homed_complete) = match Self::get_homed_uids().await {
            Ok(homed_uids) => (homed_uids, true),
            Err(err) => {
                tracing::warn!("failed to list dynamic UIDs from systemd-homed: {err:?}");
                (BTreeSet::new(), false)
            }
        };
        #[cfg(not(feature = "systemd"))]
        let (homed_uids, homed_complete) = (BTreeSet::new(), true);

        // Without /etc/shells, only the false and nologin checks apply
        let valid_shells = fs::read_to_string("/etc/shells").ok().map(|data| {
            data.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_string)
                .collect()
        });

        Self {
            uid_min: login_defs
                .get("UID_MIN")
                .and_then(|x| x.parse::<u32>().ok())
                .unwrap_or(1000),
            valid_shells,
            homed_uids,
            homed_complete,
        }
    }

    /// Decides whether an account belongs to a human, using the same rules as AccountsService.
    /// There is deliberately no upper UID bound: UID_MAX only limits the UIDs useradd allocates,
    /// while directory services (SSSD, winbind) map users to UIDs far above it.
    pub fn filter(&self, user: &pwd::Passwd) -> bool {
        if EXCLUDED_USERNAMES.contains(&user.name.as_str()) {
            return false;
        }

        let shell = if user.shell.is_empty() {
            "/bin/sh"
        } else {
            &user.shell
        };
        match Path::new(shell).file_name().and_then(|x| x.to_str()) {
            // Skip shell ending in false
            Some("false") => return false,
            // Skip shell ending in nologin
            Some("nologin") => return false,
            _ => {}
        }

        // Skip shells that are not listed in /etc/shells
        if self
            .valid_shells
            .as_ref()
            .is_some_and(|shells| !shells.contains(shell))
        {
            return false;
        }

        // systemd-homed users may have any UID outside the system range, including below UID_MIN
        user.uid >= self.uid_min || self.homed_uids.contains(&user.uid)
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct UserData {
    pub uid: u32,
    pub name: String,
    pub full_name: String,
    pub icon_opt: Option<Vec<u8>>,
    pub theme_opt: Option<Theme>,
    pub theme_builder_opt: Option<ThemeBuilder>,
    pub bg_state: BgState,
    pub bg_path_data: BTreeMap<PathBuf, Vec<u8>>,
    pub xkb_config_opt: Option<XkbConfig>,
    pub time_applet_config: TimeAppletConfig,
    pub accessibility_zoom: ZoomConfig,
    pub kdl_output_lists: Vec<String>,
}

impl UserData {
    pub fn load_wallpapers_as_user(&mut self) {
        //TODO: reload changed background files?
        self.bg_path_data.retain(|path, _| {
            self.bg_state
                .wallpapers
                .iter()
                .any(|(_, source)| match source {
                    BgSource::Path(source_path) => source_path == path,
                    _ => false,
                })
        });
        for (_, source) in self.bg_state.wallpapers.iter() {
            //TODO: do not reread duplicate paths, cache data by path?
            if let BgSource::Path(path) = source
                && !self.bg_path_data.contains_key(path)
            {
                match fs::read(path) {
                    Ok(bytes) => {
                        self.bg_path_data.insert(path.clone(), bytes);
                    }
                    Err(err) => {
                        tracing::error!("failed to read wallpaper {:?}: {:?}", path, err);
                    }
                }
            }
        }
    }

    fn load_icon_as_user(&mut self, accounts_icon: Option<&Path>) {
        let icon_paths = accounts_icon.into_iter().map(Path::to_path_buf).chain([
            // Avatar set through AccountsService, used when AccountsService is unavailable
            Path::new("/var/lib/AccountsService/icons").join(&self.name),
            // systemd-homed cache
            Path::new("/var/cache/systemd/home")
                .join(&self.name)
                .join("avatar"),
        ]);

        for icon_path in icon_paths {
            //IMPORTANT: This runs with the identity of the user, so a user controlled icon path
            // (like ~/.face) cannot be used to read files the user has no access to
            match fs::OpenOptions::new()
                .read(true)
                // Do not follow symlinks, and do not block on a FIFO
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&icon_path)
            {
                Ok(icon_file) => {
                    let Ok(metadata) = icon_file.metadata() else {
                        tracing::warn!("failed to read icon metadata {:?}", icon_path);
                        continue;
                    };
                    if !metadata.is_file() {
                        tracing::warn!("icon {:?} is not a regular file", icon_path);
                        continue;
                    }
                    if metadata.len() > MAX_ICON_SIZE as u64 {
                        tracing::warn!("icon {:?} is too large", icon_path);
                        continue;
                    }

                    let mut icon_data = Vec::new();
                    match icon_file
                        .take((MAX_ICON_SIZE + 1) as u64)
                        .read_to_end(&mut icon_data)
                    {
                        Ok(_) if icon_data.len() <= MAX_ICON_SIZE => {
                            self.icon_opt = Some(icon_data);
                            return;
                        }
                        Ok(_) => {
                            tracing::warn!("icon {:?} grew beyond the size limit", icon_path);
                        }
                        Err(err) => {
                            tracing::error!("failed to read icon data {:?}: {:?}", icon_path, err);
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!("failed to open icon {:?}: {:?}", icon_path, err);
                }
            }
        }

        tracing::error!("failed to load icon for user {:?}", self.name)
    }

    pub fn load_config_as_user(&mut self) {
        self.load_config_as_user_with_icon(None);
    }

    pub fn load_config_as_user_with_icon(&mut self, accounts_icon: Option<&Path>) {
        self.icon_opt = None;
        self.theme_opt = None;
        self.theme_builder_opt = None;
        self.bg_state = Default::default();
        self.xkb_config_opt = None;
        self.time_applet_config = Default::default();

        self.load_icon_as_user(accounts_icon);

        let mut is_dark = true;
        match cosmic_theme::ThemeMode::config() {
            Ok(helper) => match cosmic_theme::ThemeMode::get_entry(&helper) {
                Ok(theme_mode) => {
                    is_dark = theme_mode.is_dark;
                }
                Err((errs, theme_mode)) => {
                    tracing::error!("failed to load cosmic-theme config: {:?}", errs);
                    is_dark = theme_mode.is_dark;
                }
            },
            Err(err) => {
                tracing::error!("failed to create cosmic-theme mode helper: {:?}", err);
            }
        }

        match if is_dark {
            cosmic_theme::Theme::dark_config()
        } else {
            cosmic_theme::Theme::light_config()
        } {
            Ok(helper) => match cosmic_theme::Theme::get_entry(&helper) {
                Ok(theme) => {
                    self.theme_opt = Some(theme);
                }
                Err((errs, theme)) => {
                    tracing::error!("failed to load cosmic-theme config: {:?}", errs);
                    self.theme_opt = Some(theme);
                }
            },
            Err(err) => {
                tracing::error!("failed to create cosmic-theme config helper: {:?}", err);
            }
        }

        match if is_dark {
            cosmic_theme::ThemeBuilder::dark_config()
        } else {
            cosmic_theme::ThemeBuilder::light_config()
        } {
            Ok(helper) => match cosmic_theme::ThemeBuilder::get_entry(&helper) {
                Ok(theme) => {
                    self.theme_builder_opt = Some(theme);
                }
                Err((errs, theme)) => {
                    tracing::error!("failed to load cosmic-theme builder config: {:?}", errs);
                    self.theme_builder_opt = Some(theme);
                }
            },
            Err(err) => {
                tracing::error!(
                    "failed to create cosmic-theme builder config helper: {:?}",
                    err
                );
            }
        }

        //TODO: fallback to background config if background state is not set?
        match cosmic_bg_config::state::State::state() {
            Ok(helper) => match cosmic_bg_config::state::State::get_entry(&helper) {
                Ok(state) => {
                    self.bg_state = state;
                }
                Err((errs, state)) => {
                    tracing::error!("failed to load cosmic-bg state: {:?}", errs);
                    self.bg_state = state;
                }
            },
            Err(err) => {
                tracing::error!("failed to create cosmic-bg state helper: {:?}", err);
            }
        }
        if self.bg_state.wallpapers.is_empty() {
            self.bg_state.wallpapers.push((
                String::new(),
                BgSource::Path(
                    Path::new("/var/cache/systemd/home")
                        .join(&self.name)
                        .join("login-background"),
                ),
            ));
        }
        self.load_wallpapers_as_user();

        match cosmic_config::Config::new("com.system76.CosmicComp", CosmicCompConfig::VERSION) {
            Ok(config_handler) => {
                match CosmicCompConfig::get_entry(&config_handler) {
                    Ok(config) => {
                        self.xkb_config_opt = Some(config.xkb_config);
                        self.accessibility_zoom = config.accessibility_zoom;
                    }
                    Err((errs, config)) => {
                        tracing::error!("errors loading cosmic-comp config: {:?}", errs);
                        self.xkb_config_opt = Some(config.xkb_config);
                        self.accessibility_zoom = config.accessibility_zoom;
                    }
                };
            }
            Err(err) => {
                tracing::error!("failed to create cosmic-comp config handler: {}", err);
            }
        };

        let xdg = xdg::BaseDirectories::new();
        self.kdl_output_lists = xdg
            .get_state_home()
            .map(|mut s| {
                s.push("cosmic-comp/outputs.ron");
                let lists = randr::load_outputs(Some(&s));
                lists
                    .into_iter()
                    .map(|l| KdlDocument::from(l).to_string())
                    .collect()
            })
            .unwrap_or_default();

        match cosmic_config::Config::new("com.system76.CosmicAppletTime", TimeAppletConfig::VERSION)
        {
            Ok(config_handler) => match TimeAppletConfig::get_entry(&config_handler) {
                Ok(config) => {
                    self.time_applet_config = config;
                }
                Err((errs, config)) => {
                    tracing::error!("failed to load time applet config: {:?}", errs);
                    self.time_applet_config = config;
                }
            },
            Err(err) => {
                tracing::error!(
                    "failed to create CosmicAppletTime config handler: {:?}",
                    err
                );
            }
        };
    }
}

impl From<pwd::Passwd> for UserData {
    fn from(user: pwd::Passwd) -> Self {
        Self::from(&user)
    }
}

impl From<&pwd::Passwd> for UserData {
    fn from(user: &pwd::Passwd) -> Self {
        let mut full_name = user
            .gecos
            .as_ref()
            .and_then(|gecos| gecos.split(',').next())
            .map(|x| x.to_string())
            .unwrap_or_default();
        if full_name.is_empty() {
            full_name = user.name.clone();
        }
        Self {
            uid: user.uid,
            name: user.name.clone(),
            full_name,
            ..Default::default()
        }
    }
}

impl UserData {
    fn from_accounts(user: &pwd::Passwd, accounts_user: accounts::User) -> (Self, Option<PathBuf>) {
        let mut user_data = Self::from(user);
        if !accounts_user.real_name.is_empty() {
            user_data.full_name = accounts_user.real_name;
        }
        let icon_file = if accounts_user.icon_file.is_empty() {
            None
        } else {
            Some(PathBuf::from(accounts_user.icon_file))
        };
        (user_data, icon_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_filter(valid_shells: Option<&[&str]>) -> UserFilter {
        UserFilter {
            uid_min: 1000,
            valid_shells: valid_shells
                .map(|shells| shells.iter().copied().map(str::to_string).collect()),
            homed_uids: BTreeSet::new(),
            homed_complete: true,
        }
    }

    fn user(uid: u32, name: &str, shell: &str) -> pwd::Passwd {
        pwd::Passwd {
            name: name.to_string(),
            passwd: None,
            uid,
            gid: uid,
            gecos: None,
            dir: format!("/home/{name}"),
            shell: shell.to_string(),
        }
    }

    #[test]
    fn domain_uids_above_uid_max_are_shown() {
        let filter = user_filter(Some(&["/bin/bash"]));
        assert!(filter.filter(&user(1_234_500_001, "jdoe@corp.example", "/bin/bash")));
        assert!(filter.filter(&user(65_001, "jdoe", "/bin/bash")));
    }

    #[test]
    fn uids_below_uid_min_are_hidden() {
        let filter = user_filter(Some(&["/bin/bash"]));
        assert!(!filter.filter(&user(999, "service", "/bin/bash")));
        assert!(filter.filter(&user(1000, "user", "/bin/bash")));
    }

    #[test]
    fn homed_users_below_uid_min_are_shown() {
        let filter = UserFilter {
            uid_min: 5000,
            homed_uids: BTreeSet::from([2000]),
            ..user_filter(Some(&["/bin/bash"]))
        };
        assert!(filter.filter(&user(2000, "homed", "/bin/bash")));
        assert!(!filter.filter(&user(2001, "local", "/bin/bash")));
        // The username and shell checks still apply
        assert!(!filter.filter(&user(2000, "homed", "/usr/sbin/nologin")));
    }

    #[test]
    fn excluded_usernames_are_hidden() {
        // The overflow UID is no longer hidden by an upper UID bound
        let filter = user_filter(None);
        assert!(!filter.filter(&user(65_534, "nobody", "/bin/sh")));
        assert!(!filter.filter(&user(65_534, "nfsnobody", "/bin/sh")));
        assert!(!filter.filter(&user(1001, "cosmic-greeter", "/bin/sh")));
    }

    #[test]
    fn empty_shell_uses_default_sh() {
        let filter = user_filter(Some(&["/bin/sh"]));
        assert!(filter.filter(&user(1000, "user", "")));

        let filter = user_filter(Some(&["/bin/bash"]));
        assert!(!filter.filter(&user(1000, "user", "")));
    }

    #[test]
    fn invalid_shells_are_hidden() {
        let filter = user_filter(None);
        assert!(!filter.filter(&user(1000, "user", "/usr/sbin/nologin")));
        assert!(!filter.filter(&user(1000, "user", "/bin/false")));
        assert!(filter.filter(&user(1000, "user", "/opt/custom/shell")));

        let filter = user_filter(Some(&["/bin/bash"]));
        assert!(!filter.filter(&user(1000, "user", "/opt/custom/shell")));
    }

    #[test]
    fn merged_users_have_no_local_cap_and_are_deduplicated() {
        let mut users = Vec::new();
        for uid in 1000..1060 {
            let user = user(uid, &format!("user{uid}"), "/bin/sh");
            push_user(&mut users, user.clone(), UserData::from(&user), None);
        }
        assert_eq!(users.len(), 60);

        let alias = user(1000, "alias", "/bin/sh");
        push_user(&mut users, alias.clone(), UserData::from(&alias), None);
        let duplicate_name = user(2000, "user1000", "/bin/sh");
        push_user(
            &mut users,
            duplicate_name.clone(),
            UserData::from(&duplicate_name),
            None,
        );
        assert_eq!(users.len(), 60);
    }
}
