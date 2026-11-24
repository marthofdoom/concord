use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::Value;

use crate::api::{Method, PveApi};
use crate::error::PveError;

/// One recorded call to a [`MockPve`].
#[derive(Clone, Debug, PartialEq)]
pub struct Call {
    pub method: Method,
    pub path: String,
    pub params: Vec<(String, String)>,
}

#[derive(Default)]
struct State {
    /// Responses per (method, path). A queue longer than one is consumed front
    /// to back and its last element then repeats, so "running, running,
    /// stopped" ends in a stable "stopped".
    routes: HashMap<(Method, String), VecDeque<Result<Value, PveError>>>,
    calls: Vec<Call>,
}

/// A canned-response [`PveApi`] for tests. Paths are matched exactly as passed
/// to `request` (percent-encoded; see [`crate::api_path`]).
#[derive(Default)]
pub struct MockPve {
    state: Mutex<State>,
}

impl MockPve {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a successful response, appended to any already registered for
    /// the same route (making a sequence).
    pub fn on(self, method: Method, path: &str, data: Value) -> Self {
        self.on_result(method, path, Ok(data))
    }

    /// Registers an error response. If it ends up last in its route's queue
    /// it repeats like any other response, as an identical clone of `err`.
    pub fn on_err(self, method: Method, path: &str, err: PveError) -> Self {
        self.on_result(method, path, Err(err))
    }

    pub fn on_result(self, method: Method, path: &str, result: Result<Value, PveError>) -> Self {
        self.lock()
            .routes
            .entry((method, path.to_string()))
            .or_default()
            .push_back(result);
        self
    }

    /// Every call made so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.lock().calls.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[async_trait]
impl PveApi for MockPve {
    async fn request(
        &self,
        method: Method,
        path: &str,
        params: &[(&str, String)],
    ) -> Result<Value, PveError> {
        let mut st = self.lock();
        st.calls.push(Call {
            method,
            path: path.to_string(),
            params: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        });
        let Some(queue) = st.routes.get_mut(&(method, path.to_string())) else {
            return Err(PveError::Mock(format!(
                "no response registered for {} {}",
                method.as_str(),
                path
            )));
        };
        if queue.len() > 1 {
            return queue
                .pop_front()
                .unwrap_or_else(|| Err(PveError::Mock("empty queue".into())));
        }
        match queue.front() {
            Some(r) => r.clone(),
            None => Err(PveError::Mock(format!(
                "no response registered for {} {}",
                method.as_str(),
                path
            ))),
        }
    }
}
