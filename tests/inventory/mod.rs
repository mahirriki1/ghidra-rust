//! Parent-side worker inventory adoption shared by integration test clients.
#![allow(dead_code)]

use ghidra_rust::discovery::{Discovery, WorkerInventory};
use ghidra_rust::model::{BinaryInfo, DiscoveryBatch, FunctionInfo, Request};

/// Parent-side worker inventory adoption for test clients, as in the desktop:
/// requests name the adopted revision and replies are reconstructed from it.
#[derive(Default)]
pub struct Inventory {
    pub adopted: Option<WorkerInventory>,
}

impl Inventory {
    /// Names the adopted revision in a discovery batch request for its worker.
    pub fn bind(&self, mut request: Request) -> Request {
        if let Request::DiscoverBatch {
            binding,
            inventory_base,
            ..
        } = &mut request
        {
            *inventory_base = self
                .adopted
                .as_ref()
                .filter(|adopted| adopted.epoch() == binding.epoch)
                .map(|adopted| adopted.revision());
        }
        request
    }

    /// Commits a reply to the bound `request`, returning whether rows changed.
    pub fn commit(
        &mut self,
        state: &mut Discovery,
        info: &BinaryInfo,
        request: &Request,
        batch: &mut DiscoveryBatch,
    ) -> Result<bool, String> {
        let Request::DiscoverBatch { inventory_base, .. } = request else {
            return Err("not a discovery batch request".into());
        };
        let (adopted, changed) =
            state.commit_reply(info, self.adopted.as_ref(), *inventory_base, batch)?;
        self.adopted = Some(adopted);
        Ok(changed)
    }

    pub fn functions(&self) -> &[FunctionInfo] {
        self.adopted
            .as_ref()
            .map_or(&[], |adopted| adopted.functions())
    }
}
