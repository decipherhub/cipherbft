//! Opcode tracer implementation.
//!
//! Tracks step-by-step EVM execution, capturing:
//! - Program counter and opcode
//! - Gas consumption per step
//! - Stack, memory, and storage state
//! - Call depth

use super::types::{OpcodeStep, OpcodeTracerConfig};
use alloy_primitives::Bytes;
use revm::{
    context_interface::JournalTr,
    interpreter::{
        interpreter_types::{Jumps, MemoryTr, ReturnData, StackTr},
        CallInputs, CallOutcome, CreateInputs, CreateOutcome, Interpreter, InterpreterTypes,
    },
    Inspector,
};
use std::collections::HashMap;

/// Get opcode name from opcode value.
/// Uses a match statement for accuracy rather than a lookup table.
fn opcode_name_lookup(opcode: u8) -> &'static str {
    match opcode {
        0x00 => "STOP",
        0x01 => "ADD",
        0x02 => "MUL",
        0x03 => "SUB",
        0x04 => "DIV",
        0x05 => "SDIV",
        0x06 => "MOD",
        0x07 => "SMOD",
        0x08 => "ADDMOD",
        0x09 => "MULMOD",
        0x0a => "EXP",
        0x0b => "SIGNEXTEND",
        0x10 => "LT",
        0x11 => "GT",
        0x12 => "SLT",
        0x13 => "SGT",
        0x14 => "EQ",
        0x15 => "ISZERO",
        0x16 => "AND",
        0x17 => "OR",
        0x18 => "XOR",
        0x19 => "NOT",
        0x1a => "BYTE",
        0x1b => "SHL",
        0x1c => "SHR",
        0x1d => "SAR",
        0x20 => "KECCAK256",
        0x30 => "ADDRESS",
        0x31 => "BALANCE",
        0x32 => "ORIGIN",
        0x33 => "CALLER",
        0x34 => "CALLVALUE",
        0x35 => "CALLDATALOAD",
        0x36 => "CALLDATASIZE",
        0x37 => "CALLDATACOPY",
        0x38 => "CODESIZE",
        0x39 => "CODECOPY",
        0x3a => "GASPRICE",
        0x3b => "EXTCODESIZE",
        0x3c => "EXTCODECOPY",
        0x3d => "RETURNDATASIZE",
        0x3e => "RETURNDATACOPY",
        0x3f => "EXTCODEHASH",
        0x40 => "BLOCKHASH",
        0x41 => "COINBASE",
        0x42 => "TIMESTAMP",
        0x43 => "NUMBER",
        0x44 => "PREVRANDAO",
        0x45 => "GASLIMIT",
        0x46 => "CHAINID",
        0x47 => "SELFBALANCE",
        0x48 => "BASEFEE",
        0x49 => "BLOBHASH",
        0x4a => "BLOBBASEFEE",
        0x50 => "POP",
        0x51 => "MLOAD",
        0x52 => "MSTORE",
        0x53 => "MSTORE8",
        0x54 => "SLOAD",
        0x55 => "SSTORE",
        0x56 => "JUMP",
        0x57 => "JUMPI",
        0x58 => "PC",
        0x59 => "MSIZE",
        0x5a => "GAS",
        0x5b => "JUMPDEST",
        0x5c => "TLOAD",
        0x5d => "TSTORE",
        0x5e => "MCOPY",
        0x5f => "PUSH0",
        0x60 => "PUSH1",
        0x61 => "PUSH2",
        0x62 => "PUSH3",
        0x63 => "PUSH4",
        0x64 => "PUSH5",
        0x65 => "PUSH6",
        0x66 => "PUSH7",
        0x67 => "PUSH8",
        0x68 => "PUSH9",
        0x69 => "PUSH10",
        0x6a => "PUSH11",
        0x6b => "PUSH12",
        0x6c => "PUSH13",
        0x6d => "PUSH14",
        0x6e => "PUSH15",
        0x6f => "PUSH16",
        0x70 => "PUSH17",
        0x71 => "PUSH18",
        0x72 => "PUSH19",
        0x73 => "PUSH20",
        0x74 => "PUSH21",
        0x75 => "PUSH22",
        0x76 => "PUSH23",
        0x77 => "PUSH24",
        0x78 => "PUSH25",
        0x79 => "PUSH26",
        0x7a => "PUSH27",
        0x7b => "PUSH28",
        0x7c => "PUSH29",
        0x7d => "PUSH30",
        0x7e => "PUSH31",
        0x7f => "PUSH32",
        0x80 => "DUP1",
        0x81 => "DUP2",
        0x82 => "DUP3",
        0x83 => "DUP4",
        0x84 => "DUP5",
        0x85 => "DUP6",
        0x86 => "DUP7",
        0x87 => "DUP8",
        0x88 => "DUP9",
        0x89 => "DUP10",
        0x8a => "DUP11",
        0x8b => "DUP12",
        0x8c => "DUP13",
        0x8d => "DUP14",
        0x8e => "DUP15",
        0x8f => "DUP16",
        0x90 => "SWAP1",
        0x91 => "SWAP2",
        0x92 => "SWAP3",
        0x93 => "SWAP4",
        0x94 => "SWAP5",
        0x95 => "SWAP6",
        0x96 => "SWAP7",
        0x97 => "SWAP8",
        0x98 => "SWAP9",
        0x99 => "SWAP10",
        0x9a => "SWAP11",
        0x9b => "SWAP12",
        0x9c => "SWAP13",
        0x9d => "SWAP14",
        0x9e => "SWAP15",
        0x9f => "SWAP16",
        0xa0 => "LOG0",
        0xa1 => "LOG1",
        0xa2 => "LOG2",
        0xa3 => "LOG3",
        0xa4 => "LOG4",
        0xf0 => "CREATE",
        0xf1 => "CALL",
        0xf2 => "CALLCODE",
        0xf3 => "RETURN",
        0xf4 => "DELEGATECALL",
        0xf5 => "CREATE2",
        0xfa => "STATICCALL",
        0xfd => "REVERT",
        0xfe => "INVALID",
        0xff => "SELFDESTRUCT",
        _ => "UNKNOWN",
    }
}

/// Get opcode name from opcode value.
#[inline]
fn opcode_name(opcode: u8) -> &'static str {
    opcode_name_lookup(opcode)
}

/// Opcode tracer that captures step-by-step execution.
///
/// This tracer implements `revm::Inspector` to capture each opcode
/// execution step, building a list of steps with optional stack/memory.
#[derive(Debug, Clone, Default)]
pub struct OpcodeTracer {
    /// Configuration options.
    config: OpcodeTracerConfig,

    /// Recorded execution steps.
    steps: Vec<OpcodeStep>,

    /// Gas at the start of the current step.
    current_gas: u64,

    /// Current call depth.
    depth: usize,

    /// Whether we've reached the step limit.
    limit_reached: bool,
}

impl OpcodeTracer {
    /// Create a new opcode tracer with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new opcode tracer with custom configuration.
    pub fn with_config(config: OpcodeTracerConfig) -> Self {
        Self {
            config,
            steps: Vec::new(),
            current_gas: 0,
            depth: 0,
            limit_reached: false,
        }
    }

    /// Get the recorded steps after execution completes.
    pub fn into_steps(self) -> Vec<OpcodeStep> {
        self.steps
    }

    /// Get a reference to the recorded steps.
    pub fn steps(&self) -> &[OpcodeStep] {
        &self.steps
    }

    /// Check if the step limit was reached.
    pub fn limit_reached(&self) -> bool {
        self.limit_reached
    }

    /// Check if we should continue recording.
    fn should_record(&self) -> bool {
        if self.limit_reached {
            return false;
        }
        if self.config.limit > 0 && self.steps.len() >= self.config.limit {
            return false;
        }
        true
    }
}

impl<CTX, INTR> Inspector<CTX, INTR> for OpcodeTracer
where
    CTX: JournalTr,
    INTR: InterpreterTypes,
{
    fn step(&mut self, interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        if !self.should_record() {
            if !self.limit_reached && self.config.limit > 0 {
                self.limit_reached = true;
            }
            return;
        }

        let pc = interp.bytecode.pc();
        let opcode = interp.bytecode.opcode();

        // Record gas before execution
        self.current_gas = interp.gas.remaining();

        // Build stack if enabled
        let stack = if self.config.enable_stack {
            interp.stack.data().iter().copied().collect()
        } else {
            Vec::new()
        };

        // Build memory if enabled
        let memory = if self.config.enable_memory {
            let mem_size = interp.memory.size();
            if mem_size > 0 {
                let slice = interp.memory.slice(0..mem_size);
                Some(Bytes::copy_from_slice(&slice))
            } else {
                Some(Bytes::new())
            }
        } else {
            None
        };

        // We'll fill in storage in step_end if enabled
        let storage = if self.config.enable_storage {
            Some(HashMap::new())
        } else {
            None
        };

        let step = OpcodeStep {
            pc,
            op: opcode,
            op_name: opcode_name(opcode).to_string(),
            gas: self.current_gas,
            gas_cost: 0, // Will be filled in step_end
            depth: self.depth,
            stack,
            memory,
            storage,
            return_data: None,
            error: None,
        };

        self.steps.push(step);
    }

    fn step_end(&mut self, interp: &mut Interpreter<INTR>, _context: &mut CTX) {
        if let Some(step) = self.steps.last_mut() {
            // Calculate actual gas cost
            let gas_after = interp.gas.remaining();
            step.gas_cost = self.current_gas.saturating_sub(gas_after);

            // Add return data if enabled
            if self.config.enable_return_data {
                step.return_data = Some(interp.return_data.buffer().clone());
            }
        }
    }

    fn call(&mut self, _context: &mut CTX, _inputs: &mut CallInputs) -> Option<CallOutcome> {
        self.depth += 1;
        None
    }

    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, _outcome: &mut CallOutcome) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn create(&mut self, _context: &mut CTX, _inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        self.depth += 1;
        None
    }

    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CreateInputs,
        _outcome: &mut CreateOutcome,
    ) {
        self.depth = self.depth.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_name() {
        assert_eq!(opcode_name(0x00), "STOP");
        assert_eq!(opcode_name(0x01), "ADD");
        assert_eq!(opcode_name(0x60), "PUSH1");
        assert_eq!(opcode_name(0xf1), "CALL");
        assert_eq!(opcode_name(0xff), "SELFDESTRUCT");
    }

    #[test]
    fn test_opcode_tracer_new() {
        let tracer = OpcodeTracer::new();
        assert!(tracer.steps().is_empty());
        assert_eq!(tracer.depth, 0);
        assert!(!tracer.limit_reached());
    }

    #[test]
    fn test_opcode_tracer_with_config() {
        let config = OpcodeTracerConfig {
            enable_stack: true,
            enable_memory: true,
            enable_storage: false,
            enable_return_data: true,
            limit: 1000,
        };
        let tracer = OpcodeTracer::with_config(config);
        assert!(tracer.config.enable_stack);
        assert!(tracer.config.enable_memory);
        assert!(!tracer.config.enable_storage);
        assert!(tracer.config.enable_return_data);
        assert_eq!(tracer.config.limit, 1000);
    }

    #[test]
    fn test_should_record_with_limit() {
        let mut tracer = OpcodeTracer::with_config(OpcodeTracerConfig {
            limit: 2,
            ..Default::default()
        });

        // Should record first two
        assert!(tracer.should_record());
        tracer.steps.push(OpcodeStep::default());
        assert!(tracer.should_record());
        tracer.steps.push(OpcodeStep::default());

        // Should not record third
        assert!(!tracer.should_record());
    }

    #[test]
    fn test_depth_tracking() {
        let mut tracer = OpcodeTracer::new();

        // Simulate nested calls
        tracer.depth += 1;
        assert_eq!(tracer.depth, 1);

        tracer.depth += 1;
        assert_eq!(tracer.depth, 2);

        tracer.depth = tracer.depth.saturating_sub(1);
        assert_eq!(tracer.depth, 1);

        tracer.depth = tracer.depth.saturating_sub(1);
        assert_eq!(tracer.depth, 0);
    }
}
