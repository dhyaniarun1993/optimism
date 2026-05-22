use super::super::state::EngineState;
use crate::{
    BlockStateDiff, OpProofsProviderRO, OpProofsStore, engine::EngineError,
    proof::DatabaseStateRoot, provider::OpProofsStateProviderRef,
};
use alloy_eips::{NumHash, eip1898::BlockWithParent};
use alloy_primitives::B256;
use crossbeam_channel::Sender;
use reth_evm::{ConfigureEvm, execute::Executor};
use reth_primitives_traits::{AlloyBlockHeader, NodePrimitives, RecoveredBlock};
use reth_provider::{
    BlockHashReader, BlockReader, DatabaseProviderFactory, HashedPostStateProvider, ProviderError,
    StateProviderFactory, StateReader, StateRootProvider,
};
use reth_revm::database::StateProviderDatabase;
use reth_trie::{StateRoot, TrieInput};
use std::time::Instant;
use tracing::{debug, error, info};

pub(crate) struct ExecuteBlockTask<Block: reth_primitives_traits::Block> {
    pub(crate) block: RecoveredBlock<Block>,
    pub(crate) reply: Sender<Result<(), EngineError>>,
}

impl<Block: reth_primitives_traits::Block> ExecuteBlockTask<Block> {
    pub(crate) fn execute<Evm, Provider, Store>(self, state: &mut EngineState<Evm, Provider, Store>)
    where
        Evm: ConfigureEvm<Primitives: NodePrimitives<Block = Block>>,
        Provider: BlockHashReader
            + StateReader
            + DatabaseProviderFactory
            + StateProviderFactory
            + BlockReader<Block = Block>
            + Clone
            + 'static,
        Store: OpProofsStore + Clone + 'static,
    {
        let result = run(&self.block, state);
        let _ = self.reply.send(result);
    }
}

pub(crate) fn run<Block, Evm, Provider, Store>(
    block: &RecoveredBlock<Block>,
    state: &mut EngineState<Evm, Provider, Store>,
) -> Result<(), EngineError>
where
    Block: reth_primitives_traits::Block,
    Evm: ConfigureEvm<Primitives: NodePrimitives<Block = Block>>,
    Provider: BlockHashReader
        + StateReader
        + DatabaseProviderFactory
        + StateProviderFactory
        + BlockReader<Block = Block>
        + Clone
        + 'static,
    Store: OpProofsStore + Clone + 'static,
{
    let start = Instant::now();
    let tip = state.get_tip()?;
    let parent_block_number = block.number().saturating_sub(1);

    if block.number() <= tip.number {
        debug!(
            target: "trie::engine::task",
            block_number = block.number(),
            tip_number = tip.number,
            "Block already covered by tip, skipping execute_and_store",
        );
        return Ok(());
    }

    if block.number() > tip.number.saturating_add(1) {
        debug!(
            target: "trie::engine::task",
            block_number = block.number(),
            tip_number = tip.number,
            "Gap detected, updating sync target",
        );
        state.update_sync_target(block.number());
        return Ok(());
    }

    if block.parent_hash() != tip.hash {
        return Err(EngineError::ParentHashMismatch {
            block_number: block.number(),
            expected_parent_hash: tip.hash,
            actual_parent_hash: block.parent_hash(),
        });
    }

    let block_ref =
        BlockWithParent::new(block.parent_hash(), NumHash::new(block.number(), block.hash()));

    let parent_state = match state.provider.state_by_block_hash(block.parent_hash()) {
        Ok(p) => p,
        Err(ProviderError::StateForHashNotFound(hash)) => {
            // Recoverable: either a transient reorg race or reth still materializing state
            // (staged sync mid-flight). Skip; subsequent notifications will resync us.
            // Logged at debug to avoid flooding during long catch-up phases
            debug!(
                target: "trie::engine::task",
                block_number = block.number(),
                parent_hash = ?hash,
                "Parent state not available in reth; skipping execute_block",
            );
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let inner_provider = OpProofsStateProviderRef::new(
        parent_state,
        state.storage.provider_ro()?,
        parent_block_number,
    );
    let state_provider = state.memory.state_provider(block.parent_hash(), inner_provider);

    let db = StateProviderDatabase::new(&state_provider);
    let block_executor = state.evm_config.batch_executor(db);
    let execution_result = block_executor.execute(block)?;
    let execution_duration = start.elapsed();

    let hashed_state = state_provider.hashed_post_state(&execution_result.state);
    let (state_root, trie_updates) =
        state_provider.state_root_with_updates(hashed_state.clone())?;
    let state_root_duration = start.elapsed() - execution_duration;

    if state_root != block.state_root() {
        // Localize the divergence by comparing our view's trie root at parent against the
        // canonical state_root recorded in reth's block headers. Headers are retained even
        // when reth has pruned the historical state, so this works even when the proofs
        // engine is far behind reth's tip. The runner backs off exponentially, so this
        // diagnostic won't spin even if the failure persists.
        log_state_root_mismatch_diagnostic(
            block.number(),
            parent_block_number,
            state_root,
            block.state_root(),
            &state_provider,
            &state.provider,
            &state.storage,
        );

        return Err(EngineError::StateRootMismatch {
            block_number: block.number(),
            current_state_hash: state_root,
            expected_state_hash: block.state_root(),
        });
    }

    let sorted_trie_updates = trie_updates.into_sorted();
    let sorted_post_state = hashed_state.into_sorted();

    state.memory.insert(block_ref, BlockStateDiff { sorted_trie_updates, sorted_post_state });

    let total_duration = start.elapsed();

    #[cfg(feature = "metrics")]
    {
        state.metrics.execute_block_duration_seconds.record(total_duration);
        state.metrics.execution_duration_seconds.record(execution_duration);
        state.metrics.state_root_duration_seconds.record(state_root_duration);
    }

    info!(
        target: "trie::engine::task",
        block_number = block.number(),
        ?total_duration,
        ?execution_duration,
        ?state_root_duration,
        "Block executed and trie updates buffered successfully",
    );

    Ok(())
}

/// Diagnostic: localize a [`EngineError::StateRootMismatch`] to either the persisted V2 tables
/// or the in-memory overlay by comparing our trie roots against canonical block headers.
///
/// Reth retains block headers for the entire canonical chain even when the corresponding state
/// has been pruned, so [`HeaderProvider::header_by_number`] works regardless of how far the
/// proofs engine is behind reth's tip.
///
/// Three roots are computed and logged:
///
/// - `storage_alone`: `StateRoot::overlay_root_from_nodes(storage_provider, storage_latest, ∅)`.
///   The root of the persisted V2 tables (`V2HashedAccounts`, `V2HashedStorages`,
///   `V2AccountsTrie`, `V2StoragesTrie`) at the storage's persisted tip. Compared with the
///   canonical state_root in reth's header at `storage_latest.number`.
/// - `composed_at_parent`: `state_provider.state_root_from_nodes(default)`. The root of the
///   storage layer plus the memory overlay's buffered diffs at `parent_block_number`. Compared
///   with the canonical state_root in reth's header at `parent_block_number`.
/// - `computed`: the value already produced by the failing call to
///   `state_root_with_updates(hashed_state)`. Compared with `expected = block.state_root()`.
///
/// Interpretation:
/// - `storage_alone` mismatches header → V2 persistence is divergent at `storage_latest`.
/// - `composed_at_parent` mismatches header but `storage_alone` matches → the memory overlay's
///   diffs for `(storage_latest, parent_block_number]` are wrong.
/// - Both intermediate roots match their headers, only `computed` mismatches → the EVM bundle
///   for this block (or how we hash it into `HashedPostState`) is wrong.
fn log_state_root_mismatch_diagnostic<S, P, Store>(
    block_number: u64,
    parent_block_number: u64,
    computed: B256,
    expected: B256,
    state_provider: &S,
    reth_provider: &P,
    storage: &Store,
) where
    S: StateRootProvider,
    P: BlockReader,
    Store: OpProofsStore,
{
    // Canonical header roots — present on a healthy reth even when state is pruned.
    let canonical_parent_root = reth_provider
        .header_by_number(parent_block_number)
        .ok()
        .flatten()
        .map(|h| h.state_root());

    // Storage-alone root: compute from the V2 tables at the persisted tip.
    let (storage_latest_num, canonical_storage_latest_root, storage_alone_root) =
        match storage.provider_ro() {
            Ok(ro) => match ro.get_latest_block() {
                Ok(latest) => {
                    let canonical = reth_provider
                        .header_by_number(latest.number)
                        .ok()
                        .flatten()
                        .map(|h| h.state_root());
                    let ours =
                        StateRoot::overlay_root_from_nodes(ro, latest.number, TrieInput::default())
                            .ok();
                    (Some(latest.number), canonical, ours)
                }
                Err(e) => {
                    error!(
                        target: "trie::engine::task",
                        ?e,
                        "diagnostic: could not read storage's latest block",
                    );
                    (None, None, None)
                }
            },
            Err(e) => {
                error!(
                    target: "trie::engine::task",
                    ?e,
                    "diagnostic: could not open storage provider_ro",
                );
                (None, None, None)
            }
        };

    // Composed root at parent_block_number: storage layer + memory overlay's diffs (no
    // execution post-state). Built by reusing the existing composed `state_provider` and
    // feeding it an empty TrieInput.
    let composed_at_parent_root = state_provider.state_root_from_nodes(TrieInput::default()).ok();

    error!(
        target: "trie::engine::task",
        block_number,
        parent_block_number,
        storage_latest = ?storage_latest_num,
        ?computed,
        ?expected,
        ?storage_alone_root,
        ?canonical_storage_latest_root,
        ?composed_at_parent_root,
        ?canonical_parent_root,
        storage_alone_matches_header =
            matches_or_unknown(storage_alone_root, canonical_storage_latest_root),
        composed_at_parent_matches_header =
            matches_or_unknown(composed_at_parent_root, canonical_parent_root),
        "StateRootMismatch diagnostic",
    );
}

/// Three-way result for "do two optionally-known roots agree?".
///
/// Returns:
/// - `Some(true)` — both are known and equal.
/// - `Some(false)` — both are known and differ.
/// - `None` — at least one side is missing (e.g. header pruned, root computation failed), so we
///   can't make a claim either way.
fn matches_or_unknown(a: Option<B256>, b: Option<B256>) -> Option<bool> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x == y),
        _ => None,
    }
}
