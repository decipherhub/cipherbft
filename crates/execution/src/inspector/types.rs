//! Tracing types compatible with Geth's debug API.
//!
//! These types are used to represent trace results that can be serialized
//! to JSON and returned via RPC methods like `debug_traceTransaction`.

use alloy_primitives::{Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of call operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[derive(Default)]
pub enum CallType {
    /// Regular call (CALL opcode).
    #[default]
    Call,
    /// Delegate call (DELEGATECALL opcode).
    DelegateCall,
    /// Static call (STATICCALL opcode).
    StaticCall,
    /// Call code (CALLCODE opcode).
    CallCode,
    /// Contract creation (CREATE opcode).
    Create,
    /// Contract creation with salt (CREATE2 opcode).
    Create2,
}

/// A single call frame in the execution trace.
///
/// Represents one call in the call stack, including nested internal calls.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallFrame {
    /// Type of call (CALL, DELEGATECALL, etc.).
    #[serde(rename = "type")]
    pub call_type: CallType,

    /// Caller address.
    pub from: Address,

    /// Callee address (None for CREATE).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,

    /// Value transferred in wei.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,

    /// Gas provided for this call.
    pub gas: u64,

    /// Gas used by this call.
    pub gas_used: u64,

    /// Input data.
    pub input: Bytes,

    /// Output data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Bytes>,

    /// Error message if the call failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Revert reason if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,

    /// Nested calls made by this call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<CallFrame>,

    /// Logs emitted by this call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logs: Vec<CallLog>,
}

/// Log emitted during execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallLog {
    /// Contract address that emitted the log.
    pub address: Address,

    /// Log topics.
    pub topics: Vec<B256>,

    /// Log data.
    pub data: Bytes,

    /// Position in block (set later).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<u64>,
}

/// A single step in opcode-level tracing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpcodeStep {
    /// Program counter.
    pub pc: usize,

    /// Opcode value.
    pub op: u8,

    /// Opcode name.
    pub op_name: String,

    /// Gas remaining before this step.
    pub gas: u64,

    /// Gas cost of this opcode.
    pub gas_cost: u64,

    /// Call depth.
    pub depth: usize,

    /// Stack contents (if enabled).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack: Vec<U256>,

    /// Memory contents (if enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<Bytes>,

    /// Storage changes (if enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<HashMap<U256, U256>>,

    /// Return data from last call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_data: Option<Bytes>,

    /// Error if this step caused a failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// State difference for an account.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountStateDiff {
    /// Balance change: (before, after).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<StateDiffValue<U256>>,

    /// Nonce change: (before, after).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<StateDiffValue<u64>>,

    /// Code change: (before, after).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<StateDiffValue<Bytes>>,

    /// Storage changes.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub storage: HashMap<U256, StateDiffValue<U256>>,
}

/// Before/after value for state diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDiffValue<T> {
    /// Value before execution (None if created).
    #[serde(rename = "*")]
    pub from: Option<T>,

    /// Value after execution (None if deleted).
    #[serde(rename = "+")]
    pub to: Option<T>,
}

/// Complete state diff for a transaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateDiff(pub HashMap<Address, AccountStateDiff>);

/// Trace result wrapper containing different trace formats.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceResult {
    /// Call trace (for callTracer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_trace: Option<CallFrame>,

    /// Opcode trace (for structLogs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub struct_logs: Option<Vec<OpcodeStep>>,

    /// State diff (for prestateTracer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_diff: Option<StateDiff>,

    /// Whether execution failed.
    #[serde(default)]
    pub failed: bool,

    /// Gas used.
    pub gas: u64,

    /// Return value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_value: Option<Bytes>,
}

/// Configuration for the call tracer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallTracerConfig {
    /// Only trace the top-level call (no nested calls).
    #[serde(default)]
    pub only_top_call: bool,

    /// Include logs in the trace.
    #[serde(default)]
    pub with_log: bool,
}

/// Configuration for the opcode tracer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpcodeTracerConfig {
    /// Include full stack in each step.
    #[serde(default)]
    pub enable_stack: bool,

    /// Include memory in each step.
    #[serde(default)]
    pub enable_memory: bool,

    /// Include storage in each step.
    #[serde(default)]
    pub enable_storage: bool,

    /// Include return data in each step.
    #[serde(default)]
    pub enable_return_data: bool,

    /// Maximum number of steps to trace (0 = unlimited).
    #[serde(default)]
    pub limit: usize,
}

/// RPC trace options.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceOptions {
    /// Tracer type: "callTracer", "prestateTracer", or null for struct logs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracer: Option<String>,

    /// Tracer-specific configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracer_config: Option<serde_json::Value>,

    /// Timeout in string format (e.g., "10s").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,

    /// State overrides for the trace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_overrides: Option<HashMap<Address, StateOverride>>,

    /// Block overrides for the trace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_overrides: Option<BlockOverrides>,
}

/// State override for tracing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateOverride {
    /// Override balance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,

    /// Override nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,

    /// Override code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<Bytes>,

    /// Override storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<HashMap<U256, U256>>,

    /// Merge with existing storage (vs replace).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_diff: Option<HashMap<U256, U256>>,
}

/// Block overrides for tracing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockOverrides {
    /// Override block number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<u64>,

    /// Override timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<u64>,

    /// Override gas limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,

    /// Override coinbase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coinbase: Option<Address>,

    /// Override base fee.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee: Option<U256>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_frame_serialization() {
        let frame = CallFrame {
            call_type: CallType::Call,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            value: Some(U256::from(1000)),
            gas: 21000,
            gas_used: 21000,
            input: Bytes::from(vec![0x00]),
            output: Some(Bytes::new()),
            error: None,
            revert_reason: None,
            calls: vec![],
            logs: vec![],
        };

        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("\"type\":\"CALL\""));
        assert!(json.contains("\"gas\":21000"));
    }

    #[test]
    fn test_trace_options_deserialization() {
        let json = r#"{"tracer":"callTracer","tracerConfig":{"onlyTopCall":true}}"#;
        let opts: TraceOptions = serde_json::from_str(json).unwrap();
        assert_eq!(opts.tracer.as_deref(), Some("callTracer"));
    }
}
