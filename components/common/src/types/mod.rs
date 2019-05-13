// Copyright (c) 2018 Chef Software Inc. and/or applicable contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod listen_ctl_addr;
pub use self::listen_ctl_addr::ListenCtlAddr;
use crate::error::Error;
use clap::ArgMatches;
use std::{collections::HashMap,
          env::{self,
                VarError},
          fmt,
          result,
          str::FromStr};

/// Bundles up information about the user and group that a supervised
/// service should be run as. If the Supervisor itself is running with
/// root-like permissions, then these will be for `SVC_USER` and
/// `SVC_GROUP` for a service. If not, it will be for the user the
/// Supervisor itself is running as.
///
/// On Windows, all but `username` will be `None`. On Linux,
/// `username` and `groupname` may legitimately be `None`, but `uid`
/// and `gid` should always be `Some`.
#[derive(Debug, Default)]
pub struct UserInfo {
    /// Windows required, Linux optional
    pub username: Option<String>,
    /// Linux preferred
    pub uid: Option<u32>,
    /// Linux optional
    pub groupname: Option<String>,
    /// Linux preferred
    pub gid: Option<u32>,
}

/// Captures arbitrary key-value pair metadata to attach to all events
/// generated by the Supervisor.
#[derive(Clone, Debug, Default)]
pub struct EventStreamMetadata(HashMap<String, String>);

impl Into<HashMap<String, String>> for EventStreamMetadata {
    fn into(self) -> HashMap<String, String> { self.0 }
}

impl EventStreamMetadata {
    /// The name of the Clap argument we'll use for arguments of this type.
    pub const ARG_NAME: &'static str = "EVENT_STREAM_METADATA";

    /// Ensure that user input from Clap can be converted into a
    /// key-value pair we can consume.
    ///
    /// Note: this validates each value given by the user, not all the
    /// values given at once.
    #[allow(clippy::needless_pass_by_value)] // Signature required by CLAP
    pub fn validate(value: String) -> result::Result<(), String> {
        Self::split_raw(&value).map(|_| ())
    }

    /// Utility function to create a key-value pair tuple from a
    /// user-provided value in Clap.
    fn split_raw(raw: &str) -> result::Result<(String, String), String> {
        match raw.split('=').collect::<Vec<_>>().as_slice() {
            [key, value] if !key.is_empty() && !value.is_empty() => {
                Ok((key.to_string(), value.to_string()))
            }
            _ => {
                Err(format!("Invalid key-value pair given (must be \
                             '='-delimited pair of non-empty strings): {}",
                            raw))
            }
        }
    }

    /// Same as `split_raw`, but for running on already-validated
    /// input (thus, this function cannot fail).
    fn split_validated(validated_input: &str) -> (String, String) {
        Self::split_raw(validated_input).expect("EVENT_STREAM_METADATA should be validated at \
                                                 this point")
    }
}

impl<'a> From<&'a ArgMatches<'a>> for EventStreamMetadata {
    /// Create an instance of `EventStreamMetadata` from validated
    /// user input.
    fn from(m: &ArgMatches) -> Self {
        let raw_meta = m.values_of(Self::ARG_NAME).unwrap_or_default();
        Self(raw_meta.map(Self::split_validated).collect())
    }
}

/// This represents an environment variable that holds an authentication token which enables
/// integration with Automate. Supervisors use this token to connect to the messaging server
/// on the Automate side in order to send data about the services they're running via event
/// messages. If the environment variable is present, its value is the auth token. If it's not
/// present and the feature flag for the Event Stream is enabled, initialization of the Event
/// Stream will fail.
#[derive(Clone, Debug)]
pub struct AutomateAuthToken(String);

impl AutomateAuthToken {
    /// The name of the Clap argument we'll use for arguments of this type.
    pub const ARG_NAME: &'static str = "EVENT_STREAM_TOKEN";
    // Ideally, we'd like to take advantage of
    // `habitat_core::env::Config` trait, but that currently requires
    // a `Default` implementation, and there isn't really a legitimate
    // default value right now.
    pub const ENVVAR: &'static str = "HAB_AUTOMATE_AUTH_TOKEN";
}

impl AutomateAuthToken {
    // TODO: @gcp make a real error type for the case where's there no auth token value
    // refactor: to_string_lossy doesn't return an error if it can't convert the OsString
    pub fn from_env() -> result::Result<AutomateAuthToken, VarError> {
        // unwrap won't fail; any error would arise from env::var()? (from_str currently doesn't
        // return an error) we probably won't keep unwrap long-term
        println!("getting automate auth token from env...");
        Ok(env::var(AutomateAuthToken::ENVVAR)?.parse().unwrap())
    }

    /// Ensure that user input from Clap can be converted an instance
    /// of a token.
    #[allow(clippy::needless_pass_by_value)] // Signature required by CLAP
    pub fn validate(value: String) -> result::Result<(), String> {
        value.parse::<Self>().map(|_| ()).map_err(|e| e.to_string())
    }
}

impl<'a> From<&'a ArgMatches<'a>> for AutomateAuthToken {
    /// Create an instance of `AutomateAuthToken` from validated
    /// user input.
    fn from(m: &ArgMatches) -> Self {
        m.value_of(Self::ARG_NAME)
         .expect("HAB_AUTOMATE_AUTH_TOKEN should be set")
         .parse()
         .expect("HAB_AUTOMATE_AUTH_TOKEN should be validated at this point")
    }
}

impl FromStr for AutomateAuthToken {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.is_empty() {
            Err(Error::InvalidEventStreamToken(s.to_string()))
        } else {
            Ok(AutomateAuthToken(s.to_string()))
        }
    }
}

impl fmt::Display for AutomateAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.0) }
}

#[cfg(test)]
mod test {
    use super::*;

    mod auth_token {
        use super::*;

        #[test]
        fn cannot_parse_from_empty_string() { assert!("".parse::<AutomateAuthToken>().is_err()) }

    }

}
