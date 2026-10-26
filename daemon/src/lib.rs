use cosmic_comp_config::output::randr;
use cosmic_config::CosmicConfigEntry;
use kdl::KdlDocument;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use zbus::Connection;

pub use cosmic_applets_config::time::TimeAppletConfig;
pub use cosmic_bg_config::state::State as BgState;
pub use cosmic_bg_config::{Color, Source as BgSource};
pub use cosmic_comp_config::{CosmicCompConfig, XkbConfig, ZoomConfig};
pub use cosmic_theme::{Theme, ThemeBuilder};

pub mod accounts;

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

/// Decides whether an account belongs to a human, using the same rules as AccountsService.
/// There is deliberately no upper UID bound: UID_MAX only limits the UIDs useradd allocates,
/// while directory services (SSSD, winbind) map users to UIDs far above it.
fn is_human(
    uid: u32,
    name: &str,
    shell: &str,
    uid_min: u32,
    valid_shells: Option<&BTreeSet<String>>,
) -> bool {
    if EXCLUDED_USERNAMES.contains(&name) {
        return false;
    }

    match Path::new(shell).file_name().and_then(|x| x.to_str()) {
        // Skip empty shell
        None => return false,
        // Skip shell ending in false
        Some("false") => return false,
        // Skip shell ending in nologin
        Some("nologin") => return false,
        _ => {}
    }

    // Skip shells that are not listed in /etc/shells
    if valid_shells.is_some_and(|shells| !shells.contains(shell)) {
        return false;
    }

    uid >= uid_min
}

/// Reads /etc/passwd directly instead of enumerating NSS, so that directory services with
/// enumeration enabled do not list every domain account.
fn local_passwd_users() -> Vec<pwd::Passwd> {
    let data = match fs::read_to_string("/etc/passwd") {
        Ok(data) => data,
        Err(err) => {
            tracing::error!("failed to read /etc/passwd: {err:?}");
            return Vec::new();
        }
    };

    data.lines()
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
        .collect()
}

/// Loads the users to show on the login screen, from AccountsService when available and from
/// /etc/passwd otherwise. systemd-homed users are added in both cases, as older AccountsService
/// versions do not list them.
pub async fn load_users() -> Vec<(pwd::Passwd, UserData)> {
    let user_filter = UserFilter::new().await;

    let accounts_users = match Connection::system().await {
        Ok(connection) => accounts::list_users(&connection).await,
        Err(err) => Err(err),
    };

    // The pwd::Passwd methods are unsafe (but not labelled as such) due to using global state (libc pwent functions).
    // To prevent issues, this should only be called once in the entire process space at a time
    let mut users: Vec<(pwd::Passwd, UserData)> = match accounts_users {
        Ok(accounts_users) => accounts_users
            .into_iter()
            .filter_map(
                |accounts_user| match pwd::Passwd::from_name(&accounts_user.name) {
                    Ok(Some(user)) => {
                        Some((user.clone(), UserData::from_accounts(user, accounts_user)))
                    }
                    Ok(None) => {
                        tracing::warn!(
                            "user {:?} from AccountsService not found",
                            accounts_user.name
                        );
                        None
                    }
                    Err(err) => {
                        tracing::warn!("failed to look up user {:?}: {err:?}", accounts_user.name);
                        None
                    }
                },
            )
            .collect(),
        Err(err) => {
            tracing::warn!("failed to list users from AccountsService, using /etc/passwd: {err:?}");
            local_passwd_users()
                .into_iter()
                .filter(|user| user_filter.filter(user))
                .map(|user| (user.clone(), UserData::from(user)))
                .collect()
        }
    };

    for uid in user_filter.homed_uids.iter() {
        if users.iter().any(|(user, _)| user.uid == *uid) {
            continue;
        }
        if let Some(user) = pwd::Passwd::from_uid(*uid)
            && user_filter.filter(&user)
        {
            users.push((user.clone(), UserData::from(user)));
        }
    }

    users
}

pub struct UserFilter {
    uid_min: u32,
    valid_shells: Option<BTreeSet<String>>,
    homed_uids: BTreeSet<u32>,
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
        let homed_uids = Self::get_homed_uids()
            .await
            .inspect_err(|e| {
                tracing::warn!("failed to list dynamic UIDs from systemd-homed: {e:?}")
            })
            .unwrap_or_default();
        #[cfg(not(feature = "systemd"))]
        let homed_uids = BTreeSet::new();

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
        }
    }

    pub fn filter(&self, user: &pwd::Passwd) -> bool {
        // systemd-homed allocates UIDs from its own range, which may be below UID_MIN
        let uid_min = if self.homed_uids.contains(&user.uid) {
            0
        } else {
            self.uid_min
        };
        is_human(
            user.uid,
            &user.name,
            &user.shell,
            uid_min,
            self.valid_shells.as_ref(),
        )
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct UserData {
    pub uid: u32,
    pub name: String,
    pub full_name: String,
    /// Avatar path from AccountsService, only used by the daemon to load `icon_opt`
    #[serde(skip)]
    pub icon_file_opt: Option<PathBuf>,
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

    fn load_icon_as_user(&mut self) {
        let icon_paths = self.icon_file_opt.iter().cloned().chain([
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
                Ok(mut icon_file) => {
                    if !icon_file
                        .metadata()
                        .is_ok_and(|metadata| metadata.is_file())
                    {
                        tracing::warn!("icon {:?} is not a regular file", icon_path);
                        continue;
                    }
                    let mut icon_data = Vec::new();
                    match icon_file.read_to_end(&mut icon_data) {
                        Ok(count) => {
                            icon_data.truncate(count);
                            self.icon_opt = Some(icon_data);
                            return;
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
        self.icon_opt = None;
        self.theme_opt = None;
        self.theme_builder_opt = None;
        self.bg_state = Default::default();
        self.xkb_config_opt = None;
        self.time_applet_config = Default::default();

        self.load_icon_as_user();

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
    fn from_accounts(user: pwd::Passwd, accounts_user: accounts::User) -> Self {
        let mut user_data = Self::from(user);
        if !accounts_user.real_name.is_empty() {
            user_data.full_name = accounts_user.real_name;
        }
        if !accounts_user.icon_file.is_empty() {
            user_data.icon_file_opt = Some(PathBuf::from(accounts_user.icon_file));
        }
        user_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shells() -> BTreeSet<String> {
        ["/bin/sh", "/bin/bash", "/usr/bin/bash", "/usr/bin/fish"]
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn domain_uids_above_uid_max_are_human() {
        assert!(is_human(
            1_234_500_001,
            "jdoe@corp.example",
            "/bin/bash",
            1000,
            Some(&shells())
        ));
        assert!(is_human(65_001, "jdoe", "/bin/bash", 1000, Some(&shells())));
    }

    #[test]
    fn uids_below_uid_min_are_not_human() {
        assert!(!is_human(
            999,
            "service",
            "/bin/bash",
            1000,
            Some(&shells())
        ));
        assert!(is_human(1000, "user", "/bin/bash", 1000, Some(&shells())));
    }

    #[test]
    fn excluded_usernames_are_not_human() {
        // The overflow UID is no longer hidden by an upper UID bound
        assert!(!is_human(
            65_534,
            "nobody",
            "/bin/sh",
            1000,
            Some(&shells())
        ));
        assert!(!is_human(65_534, "nfsnobody", "/bin/sh", 1000, None));
        assert!(!is_human(1001, "cosmic-greeter", "/bin/sh", 1000, None));
    }

    #[test]
    fn invalid_shells_are_not_human() {
        assert!(!is_human(1000, "user", "/usr/sbin/nologin", 1000, None));
        assert!(!is_human(1000, "user", "/bin/false", 1000, None));
        assert!(!is_human(1000, "user", "", 1000, None));
        assert!(!is_human(
            1000,
            "user",
            "/opt/custom/shell",
            1000,
            Some(&shells())
        ));
        assert!(is_human(1000, "user", "/opt/custom/shell", 1000, None));
    }
}
