use std::{fs};
use git2::{Commit, Error, ErrorClass, ErrorCode, Repository, Sort};
use tempfile::TempDir;

pub const GITHUB_ROOT_HTTPS: &str = "https://github.com/";
pub const GITHUB_ROOT_SSH: &str = "git@github.com:";
pub const GITHUB_POSTFIX: &str = ".git";
pub const GITHUB_ROOT_FILESYSTEM: &str = "file://";

#[derive(Default, Clone)]
pub enum GitUrlKind {
    #[default]
    HTTPS,
    HTTP,
    SSH,
    FILESYSTEM,
}

#[derive(Debug)]
pub enum GitErr {
    Unknown,
    UnableToWalk,
    CloneOrOpenFail,
    UrlUnknown,
    UrlInvalid,
    TempDirFailed,
    InvalidKind,
    CloneFailed,
}

pub trait GitPath {
    fn get_path(&self) -> Result<(GitUrlKind, String), GitErr>;
}

pub struct GitClient<'a> {
    url: &'a dyn GitPath,
    repo: Option<Repository>,
}

impl GitClient<'_> {
    pub fn from(git_url: &dyn GitPath) -> Result<GitClient, GitErr> {
        let mut client = GitClient {
            url: git_url,
            repo: None,
        };
        client.repo = Some(client.clone_or_open()?.0);

        Ok(client)
    }

    fn get_target_path(&self) -> Result<(String, bool), GitErr> {
        // TODO: Support user specified targets
        match TempDir::new() {
            Ok(the_dir) => match the_dir.path().to_str() {
                None => Err(GitErr::TempDirFailed),
                Some(path) => Ok((String::from(path), true)),
            },
            Err(_) => Err(GitErr::TempDirFailed),
        }
    }

    fn clone_or_open(&self) -> Result<(Repository, bool), GitErr> {

        let (kind, path) = self.url.get_path()?;

        match kind {
            GitUrlKind::HTTPS |GitUrlKind::HTTP | GitUrlKind::SSH => {
                let target = self.get_target_path()?;
                let repo = Repository::clone(path.as_str(), target.0);
                if repo.is_err() { return Err(GitErr::CloneFailed) }
                Ok((repo.unwrap(), target.1))
            }
            GitUrlKind::FILESYSTEM => {
                let repo = Repository::open(path.as_str());
                if repo.is_err() { return Err(GitErr::CloneFailed) }
                Ok((repo.unwrap(), false))
            }
        }
    }

    pub fn walk<F>(&self, process: F) -> Result<(), Error>
    where
        F: Fn(&Repository, &Commit) -> bool,
    {
        let repo_result = match self.clone_or_open() {
            Ok((the_repo, is_temp_dir)) => (the_repo, is_temp_dir),
            Err(_) => {
                return Err(Error::new(
                    ErrorCode::Directory,
                    ErrorClass::Filesystem,
                    "Unable to clone or open repository.",
                ));
            }
        };

        let repo = repo_result.0;
        let is_temp_dir = repo_result.1;

        let mut walker = repo.revwalk()?;
        walker.push_head()?;
        walker.set_sorting(Sort::NONE)?;

        for oid in walker {
            if process(&repo, &repo.find_commit(oid?)?) == false {
                break;
            }
        }

        // cleanup temp dir
        if is_temp_dir {
            // TODO: better error handling
            let temp_path = repo.path().to_str().unwrap_or("Unknown");
            let res = fs::remove_dir_all(temp_path);

            if res.is_err() {
                println!("Unable to delete temp dir: {}", temp_path);
            } else {
                println!("Deleted temp dir: {}", temp_path);
            }
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct FileSystemPath<'a> {
    pub path: &'a str,
}

impl GitPath for FileSystemPath<'_> {
    fn get_path(&self) -> Result<(GitUrlKind, String), GitErr> {
        Ok((GitUrlKind::FILESYSTEM, String::from(self.path)))
    }
}
