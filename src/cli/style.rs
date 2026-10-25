use std::io::IsTerminal;

pub struct Style {
    enabled: bool,
}

impl Default for Style {
    fn default() -> Self {
        Self::new()
    }
}

impl Style {
    pub fn new() -> Self {
        let enabled = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        Self { enabled }
    }

    pub fn red(&self, s: &str) -> String {
        if self.enabled {
            format!("\x1b[1;31m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn green(&self, s: &str) -> String {
        if self.enabled {
            format!("\x1b[1;32m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn yellow(&self, s: &str) -> String {
        if self.enabled {
            format!("\x1b[1;33m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn cyan(&self, s: &str) -> String {
        if self.enabled {
            format!("\x1b[1;36m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn bold(&self, s: &str) -> String {
        if self.enabled {
            format!("\x1b[1m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn dim(&self, s: &str) -> String {
        if self.enabled {
            format!("\x1b[2m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}
