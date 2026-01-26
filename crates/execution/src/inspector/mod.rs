//! EVM Inspector implementations for transaction tracing.
//!
//! This module provides `revm::Inspector` implementations for:
//! - Call tracing (`CallTracer`) - tracks call stack and internal calls
//! - Opcode tracing (`OpcodeTracer`) - tracks step-by-step execution
//!
//! These inspectors are used by the debug_* RPC methods.

mod call_tracer;
mod opcode_tracer;
mod types;

pub use call_tracer::CallTracer;
pub use opcode_tracer::OpcodeTracer;
pub use types::*;
