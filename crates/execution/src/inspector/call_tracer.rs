//! Call tracer implementation.
//!
//! Tracks the call stack during EVM execution, capturing:
//! - Call type (CALL, DELEGATECALL, CREATE, etc.)
//! - Input/output data
//! - Gas usage
//! - Nested calls
//! - Errors and reverts

use super::types::{CallFrame, CallLog, CallTracerConfig, CallType};
use alloy_primitives::{Address, Bytes, U256};
use revm::{
    context_interface::JournalTr,
    interpreter::{CallInputs, CallOutcome, CreateInputs, CreateOutcome, InterpreterTypes},
    Inspector,
};

/// Call tracer that builds a tree of call frames.
///
/// This tracer implements `revm::Inspector` to capture all calls during
/// transaction execution, building a nested structure of call frames.
#[derive(Debug, Clone, Default)]
pub struct CallTracer {
    /// Configuration options.
    config: CallTracerConfig,

    /// Stack of call frames (current call chain).
    call_stack: Vec<CallFrame>,

    /// The root call frame (populated after execution).
    root_frame: Option<CallFrame>,

    /// Current call depth.
    depth: usize,
}

impl CallTracer {
    /// Create a new call tracer with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new call tracer with custom configuration.
    pub fn with_config(config: CallTracerConfig) -> Self {
        Self {
            config,
            call_stack: Vec::new(),
            root_frame: None,
            depth: 0,
        }
    }

    /// Get the trace result after execution completes.
    pub fn into_trace(self) -> Option<CallFrame> {
        self.root_frame
    }

    /// Get a reference to the trace result.
    pub fn trace(&self) -> Option<&CallFrame> {
        self.root_frame.as_ref()
    }

    /// Push a new call frame onto the stack.
    fn push_frame(&mut self, frame: CallFrame) {
        if self.config.only_top_call && self.depth > 0 {
            return;
        }
        self.call_stack.push(frame);
        self.depth += 1;
    }

    /// Pop a call frame from the stack and attach it to the parent.
    fn pop_frame(&mut self, gas_used: u64, output: Option<Bytes>, error: Option<String>) {
        if self.config.only_top_call && self.depth > 1 {
            self.depth = self.depth.saturating_sub(1);
            return;
        }

        if let Some(mut frame) = self.call_stack.pop() {
            frame.gas_used = gas_used;
            frame.output = output;
            frame.error = error;

            self.depth = self.depth.saturating_sub(1);

            if let Some(parent) = self.call_stack.last_mut() {
                parent.calls.push(frame);
            } else {
                // This was the root call
                self.root_frame = Some(frame);
            }
        }
    }
}

impl<CTX, INTR> Inspector<CTX, INTR> for CallTracer
where
    CTX: JournalTr,
    INTR: InterpreterTypes,
{
    fn call(&mut self, _context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let call_type = match inputs.scheme {
            revm::interpreter::CallScheme::Call => CallType::Call,
            revm::interpreter::CallScheme::DelegateCall => CallType::DelegateCall,
            revm::interpreter::CallScheme::StaticCall => CallType::StaticCall,
            revm::interpreter::CallScheme::CallCode => CallType::CallCode,
        };

        let frame = CallFrame {
            call_type,
            from: inputs.caller,
            to: Some(inputs.target_address),
            value: inputs.value.transfer(),
            gas: inputs.gas_limit,
            gas_used: 0,
            input: Bytes::new(), // Input is complex in revm 33.x, skip for now
            output: None,
            error: None,
            revert_reason: None,
            calls: Vec::new(),
            logs: Vec::new(),
        };

        self.push_frame(frame);
        None
    }

    fn call_end(&mut self, _context: &mut CTX, _inputs: &CallInputs, outcome: &mut CallOutcome) {
        let gas_used = outcome.gas().spent();
        let output = Some(outcome.result.output.clone());
        let error = if outcome.result.result.is_error() {
            Some(format!("{:?}", outcome.result.result))
        } else {
            None
        };

        self.pop_frame(gas_used, output, error);
    }

    fn create(&mut self, _context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        let call_type = match inputs.scheme {
            revm::interpreter::CreateScheme::Create => CallType::Create,
            revm::interpreter::CreateScheme::Create2 { .. } => CallType::Create2,
            // Handle custom create schemes as Create
            _ => CallType::Create,
        };

        let frame = CallFrame {
            call_type,
            from: inputs.caller,
            to: None, // Will be set in create_end
            value: Some(inputs.value),
            gas: inputs.gas_limit,
            gas_used: 0,
            input: inputs.init_code.clone(),
            output: None,
            error: None,
            revert_reason: None,
            calls: Vec::new(),
            logs: Vec::new(),
        };

        self.push_frame(frame);
        None
    }

    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        let gas_used = outcome.gas().spent();

        // Set the created contract address
        if let Some(frame) = self.call_stack.last_mut() {
            frame.to = outcome.address;
        }

        let output = Some(outcome.result.output.clone());
        let error = if outcome.result.result.is_error() {
            Some(format!("{:?}", outcome.result.result))
        } else {
            None
        };

        self.pop_frame(gas_used, output, error);
    }

    fn log(&mut self, _context: &mut CTX, log: alloy_primitives::Log) {
        if !self.config.with_log {
            return;
        }

        if let Some(frame) = self.call_stack.last_mut() {
            frame.logs.push(CallLog {
                address: log.address,
                topics: log.topics().to_vec(),
                data: log.data.data.clone(),
                position: None,
            });
        }
    }

    fn selfdestruct(&mut self, _contract: Address, _target: Address, _value: U256) {
        // Could track self-destructs if needed
    }
}

/// Convenience function to execute with call tracing.
pub fn trace_call<F, R>(config: CallTracerConfig, f: F) -> (R, Option<CallFrame>)
where
    F: FnOnce(&mut CallTracer) -> R,
{
    let mut tracer = CallTracer::with_config(config);
    let result = f(&mut tracer);
    (result, tracer.into_trace())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_tracer_new() {
        let tracer = CallTracer::new();
        assert!(tracer.trace().is_none());
        assert_eq!(tracer.depth, 0);
    }

    #[test]
    fn test_call_tracer_with_config() {
        let config = CallTracerConfig {
            only_top_call: true,
            with_log: true,
        };
        let tracer = CallTracer::with_config(config);
        assert!(tracer.config.only_top_call);
        assert!(tracer.config.with_log);
    }

    #[test]
    fn test_push_pop_frame() {
        let mut tracer = CallTracer::new();

        let frame = CallFrame {
            call_type: CallType::Call,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            gas: 21000,
            ..Default::default()
        };

        tracer.push_frame(frame);
        assert_eq!(tracer.depth, 1);

        tracer.pop_frame(21000, Some(Bytes::new()), None);
        assert_eq!(tracer.depth, 0);
        assert!(tracer.root_frame.is_some());
    }

    #[test]
    fn test_nested_calls() {
        let mut tracer = CallTracer::new();

        // Push root call
        tracer.push_frame(CallFrame {
            call_type: CallType::Call,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            gas: 100000,
            ..Default::default()
        });

        // Push nested call
        tracer.push_frame(CallFrame {
            call_type: CallType::DelegateCall,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            gas: 50000,
            ..Default::default()
        });

        // Pop nested call
        tracer.pop_frame(25000, Some(Bytes::new()), None);
        assert_eq!(tracer.depth, 1);

        // Pop root call
        tracer.pop_frame(75000, Some(Bytes::new()), None);
        assert_eq!(tracer.depth, 0);

        let root = tracer.into_trace().unwrap();
        assert_eq!(root.calls.len(), 1);
        assert_eq!(root.calls[0].call_type, CallType::DelegateCall);
    }

    #[test]
    fn test_only_top_call() {
        let mut tracer = CallTracer::with_config(CallTracerConfig {
            only_top_call: true,
            with_log: false,
        });

        // Push root call
        tracer.push_frame(CallFrame {
            call_type: CallType::Call,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            gas: 100000,
            ..Default::default()
        });

        // Try to push nested call (should be ignored)
        tracer.push_frame(CallFrame {
            call_type: CallType::DelegateCall,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            gas: 50000,
            ..Default::default()
        });

        // Depth should still be 1 (nested call ignored)
        assert_eq!(tracer.call_stack.len(), 1);
    }
}
