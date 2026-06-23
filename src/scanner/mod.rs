pub mod port;
pub mod service;
pub mod system;
pub mod docker;
pub mod nginx;
pub mod ssh;

use crate::report::Finding;

pub trait Scanner {
    fn name(&self) -> &'static str;
    fn scan(&self) -> Vec<Finding>;
}
