#![doc = include_str!("../docs/lib.md")]
#![cfg_attr(docsrs, feature(doc_cfg), warn(rustdoc::broken_intra_doc_links))]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

/// Policy types: [`AccessPolicy`], [`AccessRule`], and [`CustomFn`](policy::CustomFn).
pub mod policy;

/// The [`Principal`] trait.
pub mod principal;

/// The [`LayeCheckResult`] type.
pub mod result;

#[cfg(feature = "actix-web")]
#[cfg_attr(docsrs, doc(cfg(feature = "actix-web")))]
pub mod actix;

#[cfg(feature = "tower")]
#[cfg_attr(docsrs, doc(cfg(feature = "tower")))]
pub mod tower_middleware;

pub use policy::{AccessPolicy, AccessRule};
pub use principal::Principal;
pub use result::LayeCheckResult;
