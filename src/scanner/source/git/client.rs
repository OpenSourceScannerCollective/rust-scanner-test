use git2::{Commit, Error, ErrorClass, ErrorCode, Repository, Sort};
use tempfile::TempDir;

pub const GITHUB_ROOT_HTTPS: &str = "https://github.com/";
pub const GITHUB_ROOT_SSH: &str = "git@github.com:";
pub const GITHUB_POSTFIX: &str = ".git";
pub const GITHUB_ROOT_FILESYSTEM: &str = "file://";

#[derive(Default)]
enum GitUrlKind {
    #[default]
    HTTPS,
    SSH,
    FILESYSTEM,
}

trait GitUrl {
    fn get_kind(&self) -> &GitUrlKind;
    fn get_url(&self) -> Result<(GitUrlKind, String), GitErr>;
}

#[derive(Default)]
struct GitHubUrl<'a> {
    kind: GitUrlKind,
    pub owner: &'a str,
    pub repo_name: &'a str,
    pub root: &'a str,
    repo: Option<Repository>,
}

impl GitUrl for GitHubUrl<'_> {
    fn get_kind(&self) -> &GitUrlKind {
        &self.kind
    }

    fn get_url(&self) -> Result<(GitUrlKind, String), GitErr> {
        Ok(match &self.kind {
            GitUrlKind::HTTPS => (GitUrlKind::HTTPS, self.get_url_http()),
            GitUrlKind::SSH => (GitUrlKind::SSH, self.get_url_ssh()),
            _ => return Err(GitErr::InvalidKind),
        })
    }
}

impl GitHubUrl<'_> {
    pub fn new<'a>(
        owner: &'a str,
        repo_name: &'a str,
        root: Option<&'a str>,
    ) -> Result<GitHubUrl<'a>, GitErr> {
        match root.unwrap_or_else(|| GITHUB_ROOT_HTTPS) {
            the_root => Ok(GitHubUrl {
                kind: Self::detect_url_kind(the_root)?,
                owner,
                repo_name,
                root: the_root,
                repo: None,
            }),
        }
    }
    fn detect_url_kind(url: &str) -> Result<GitUrlKind, GitErr> {
        Ok(match String::from(url).get(0..8).unwrap_or_default() {
            "git@" => GitUrlKind::SSH,
            "https://" => GitUrlKind::HTTPS,
            "file://" => GitUrlKind::FILESYSTEM,
            _ => return Err(GitErr::UrlUnknown),
        })
    }
    fn get_url_http(&self) -> String {
        [self.root, self.owner, "/", self.repo_name, GITHUB_POSTFIX].concat()
    }
    fn get_url_ssh(&self) -> String {
        [
            GITHUB_ROOT_SSH,
            self.owner,
            "/",
            self.repo_name,
            GITHUB_POSTFIX,
        ]
        .concat()
    }
    fn get_target_path(&self) -> Result<String, GitErr> {
        // TODO: Support user specified targets
        match TempDir::new() {
            Ok(the_dir) => match the_dir.path().to_str() {
                None => Err(GitErr::TempDirFailed),
                Some(path) => Ok(String::from(path)),
            },
            Err(_) => Err(GitErr::TempDirFailed),
        }
    }
    fn clone_or_open(&self) -> Result<Repository, GitErr> {
        match self.get_url() {
            Ok((kind, path)) => {
                match match kind {
                    GitUrlKind::HTTPS | GitUrlKind::SSH => {
                        Repository::clone(path.as_str(), self.get_target_path()?)
                    }
                    GitUrlKind::FILESYSTEM => Repository::open(path),
                } {
                    Ok(repo) => Ok(repo),
                    Err(_) => Err(GitErr::CloneOrOpenFail),
                }
            }
            Err(e) => Err(e),
        }
    }

    fn walk<F>(&self, process: F) -> Result<(), Error>
    where
        F: Fn(&Repository, &Commit) -> bool,
    {
        let repo = match self.clone_or_open() {
            Ok(the_repo) => the_repo,
            Err(_) => { return Err(Error::new(
                ErrorCode::Directory,
                ErrorClass::Filesystem,
                "Unable to clone or open repository."
            )); }
        };

        let mut walker = repo.revwalk()?;
        walker.push_head()?;
        walker.set_sorting(Sort::NONE)?;

        for oid in walker {
            if process(&repo, &repo.find_commit(oid?)?) == false {
                break;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
enum GitErr {
    Unknown,
    UnableToWalk,
    CloneOrOpenFail,
    UrlUnknown,
    TempDirFailed,
    InvalidKind,
    CloneFailed,
}
