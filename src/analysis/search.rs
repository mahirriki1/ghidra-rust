//! One cached query; all scan progress remains explicit in the request.
use super::LoadedProgram;
use crate::model::{Request, Response};
use crate::search::{CompiledPattern, MemorySearchSpec, SearchDomain};

pub(super) struct CachedSearch {
    spec: MemorySearchSpec,
    domain: SearchDomain,
    pattern: CompiledPattern,
}

impl LoadedProgram {
    pub(super) fn search_memory(&mut self, request: Request) -> Result<Response, String> {
        let Request::SearchMemory { binding, spec, .. } = &request else {
            return Err("Expected memory search request".into());
        };
        if binding.binary_sha256 != self.info.sha256 {
            return Err("Search does not match the opened image".into());
        }
        if self
            .search
            .as_ref()
            .is_none_or(|cached| cached.spec != *spec)
        {
            let pattern = spec.compile()?;
            let domain = SearchDomain::new(&self.info.sections, self.snapshot.len() as u64)?;
            self.search = Some(CachedSearch {
                spec: spec.clone(),
                domain,
                pattern,
            });
        }
        let cached = self.search.as_ref().expect("search prepared");
        let context = cached.domain.request_context(&request)?;
        let page = cached
            .domain
            .scan(&self.snapshot, &cached.pattern, &context)?;
        Ok(Response::MemorySearch(page))
    }
}
