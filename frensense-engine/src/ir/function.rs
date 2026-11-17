// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Phase 1: Intermediate Representation (IR)
//!
//! This module defines the 3-Address Code and Control Flow Graph structures.
//! It serves as the foundation for modern SSA-based dataflow analysis across
//! dynamic, object-oriented, and systems languages.
//!
//! NEW: Incorporates Memory SSA concepts. The heap is no longer a global state.
//! Instead, memory mutations generate a new `MemoryState` (represented as a VarId),
//! which perfectly tracks flow-sensitive object modifications over time.

use rustc_hash::FxHashMap;

/// A unique identifier for a variable or Memory State in the IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct VarId(pub usize);

/// Source name of the hidden memory-state parameter every [`FunctionIR`]
/// allocates as its `VarId(0)`. Shared by the IR builder (which names the
/// variable) and path reconstruction (which strips the artifact).
pub const INITIAL_HEAP_STATE: &str = "InitialHeapState";

/// A unique identifier for a Basic Block in the CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct BlockId(pub usize);

/// Identifies the type of allocation for points-to analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum AllocationKind {
    /// A plain object (record, dictionary, struct literal).
    Object,
    /// An array or list.
    Array,
    /// An instance of the named class, constructor call, or struct type.
    ClassInstance(String),
}

/// Metadata mapping a VarId back to its original source code context.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct VarMetadata {
    /// Name of the variable as written in the source, when it has one. `None` for compiler temporaries.
    pub source_name: Option<String>,
    /// Declared or inferred type name from the source, when the language provides one.
    pub type_name: Option<String>,
    /// Byte range `(start, end)` of the defining source text, used to map findings back to source.
    pub byte_range: Option<(usize, usize)>,
    /// Flags if this VarId represents a hidden Memory State rather than a real code variable
    pub is_memory_state: bool,
    /// For a var produced by an object-literal composite: the keys whose
    /// values were merged into it (e.g. `["where", "message"]`). Sinks use
    /// this to classify the *shape* of the tainted argument (IDOR-style
    /// object payload vs raw injection string).
    pub object_keys: Vec<String>,
    /// Bound by a declaration visited while lowering this function's body
    /// (`char *p;`, `let x;`, `x = v` in Python, destructuring patterns) -
    /// provably function-scoped. Vars created at first *expression* use are
    /// left `false`: those are file/module/header globals (or undeclared
    /// names), whose values are initialized elsewhere. Uninitialized-free
    /// analysis fires only on `declared` vars.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub declared: bool,
}

/// Operands are the inputs to instructions.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum Operand {
    /// A variable holding an SSA value.
    Var(VarId),
    /// A string literal.
    StringLiteral(String),
    /// An integer literal.
    IntLiteral(i64),
    /// A floating-point literal.
    FloatLiteral(f64),
    /// A boolean literal.
    BoolLiteral(bool),
    /// The null / nil / None value.
    Null,
    /// A value the lowering could not model (an unsupported expression form).
    Unknown,
}

/// A Phi node for SSA representation. Evaluated at the start of a block.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct Phi {
    /// Variable defined by the phi (the merged value).
    pub dest: VarId,
    /// One `(predecessor block, variable)` pair per incoming control-flow edge: the phi takes the variable that arrives along that edge.
    pub incoming: Vec<(BlockId, VarId)>,
}

/// A single linear instruction in 3-Address Code form.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum Instruction {
    /// v_dest = v_src
    Assign {
        /// Variable being defined.
        dest: VarId,
        /// Value assigned to `dest`.
        src: Operand,
    },

    // --- Object & Array Memory Access (Memory SSA Enabled) ---
    // Reads depend on a specific moment in time (mem_in).
    // Writes consume a moment in time, and generate a new one (mem_out).
    /// v_dest = base.field  @ mem_in
    LoadField {
        /// Variable that receives the loaded value.
        dest: VarId,
        /// Memory state the load reads from.
        mem_in: VarId,
        /// Variable holding the object whose field is read.
        base: VarId,
        /// Name of the field being read.
        field: String,
    },

    /// base.field = src  -> generates mem_out
    StoreField {
        /// New memory state produced by the store.
        mem_out: VarId,
        /// Memory state the store applies to.
        mem_in: VarId,
        /// Variable holding the object being written.
        base: VarId,
        /// Name of the field being written.
        field: String,
        /// Value stored into the field.
        src: Operand,
    },

    /// `v_dest = base[index]  @ mem_in`
    LoadElement {
        /// Variable that receives the loaded element.
        dest: VarId,
        /// Memory state the load reads from.
        mem_in: VarId,
        /// Variable holding the array or collection.
        base: VarId,
        /// Index or key operand selecting the element.
        index: Operand,
    },

    /// `base[index] = src` generates `mem_out`.
    StoreElement {
        /// New memory state produced by the store.
        mem_out: VarId,
        /// Memory state the store applies to.
        mem_in: VarId,
        /// Variable holding the array or collection being written.
        base: VarId,
        /// Index or key operand selecting the element.
        index: Operand,
        /// Value stored into the element.
        src: Operand,
    },

    // --- Global Environment ---
    /// v_dest = global_name
    LoadGlobal {
        /// Variable that receives the global's value.
        dest: VarId,
        /// Memory state the load reads from.
        mem_in: VarId,
        /// Name of the global being read.
        name: String,
    },

    /// global_name = src
    StoreGlobal {
        /// New memory state produced by the store.
        mem_out: VarId,
        /// Memory state the store applies to.
        mem_in: VarId,
        /// Name of the global being written.
        name: String,
        /// Value stored into the global.
        src: Operand,
    },

    // --- Functions & Calls ---
    // Function calls can mutate memory, so they consume mem_in and return mem_out.
    /// mem_out, dest = func(args) @ mem_in
    CallStatic {
        /// Variable receiving the call's return value, or `None` when the result is discarded.
        dest: Option<VarId>,
        /// Memory state after the call (calls may mutate memory).
        mem_out: VarId,
        /// Memory state the call executes in.
        mem_in: VarId,
        /// Name of the called function as written at the call site.
        func: String,
        /// Argument operands, in call order.
        args: Vec<Operand>,
        /// Keyword/keyed argument names, parallel to `args`: entry `i` is
        /// the name of `args[i]`, or empty when that argument is
        /// positional. Shorter than `args` (or empty) means the source
        /// language, or the lowered node, carries no names - callers must
        /// treat a missing entry as positional. See the `args` field documentation.
        arg_names: Vec<String>,
    },

    /// mem_out, dest = receiver.method(args) @ mem_in
    CallVirtual {
        /// Variable receiving the call's return value, or `None` when the result is discarded.
        dest: Option<VarId>,
        /// Memory state after the call (calls may mutate memory).
        mem_out: VarId,
        /// Memory state the call executes in.
        mem_in: VarId,
        /// Name of the invoked method.
        method: String,
        /// The receiver the method is invoked on (`self`, `this`, or the object before the dot).
        receiver: Operand,
        /// Argument operands, in call order, not including the receiver.
        args: Vec<Operand>,
        /// Parallel to `args`; see [`Instruction::CallStatic`].
        arg_names: Vec<String>,
    },

    /// mem_out, dest = func_ptr(args) @ mem_in
    CallPointer {
        /// Variable receiving the call's return value, or `None` when the result is discarded.
        dest: Option<VarId>,
        /// Memory state after the call (calls may mutate memory).
        mem_out: VarId,
        /// Memory state the call executes in.
        mem_in: VarId,
        /// Operand holding the callee value (a function pointer, closure or callable variable).
        func_ptr: Operand,
        /// Argument operands, in call order.
        args: Vec<Operand>,
        /// Parallel to `args`; see [`Instruction::CallStatic`].
        arg_names: Vec<String>,
    },

    // --- Memory & Pointers (Systems Languages) ---
    /// mem_out, v_dest = new Object/Array() @ mem_in
    Allocate {
        /// Variable that receives the new object or array.
        dest: VarId,
        /// Memory state after the allocation.
        mem_out: VarId,
        /// Memory state the allocation executes in.
        mem_in: VarId,
        /// What is being allocated; used by points-to analysis to name the abstract object.
        kind: AllocationKind,
    },

    /// v_dest = &src
    AddressOf {
        /// Variable that receives the address.
        dest: VarId,
        /// Variable whose address is taken.
        src: VarId,
    },

    /// v_dest = *ptr @ mem_in
    Dereference {
        /// Variable that receives the dereferenced value.
        dest: VarId,
        /// Memory state the load reads from.
        mem_in: VarId,
        /// Pointer operand being dereferenced.
        ptr: Operand,
    },

    // --- Types & Multiple Returns ---
    /// Converts `src` to `target_type`, defining `dest`.
    Cast {
        /// Variable that receives the converted value.
        dest: VarId,
        /// Value being converted.
        src: Operand,
        /// Name of the target type as written in the source.
        target_type: String,
    },
    /// Extracts one component of a tuple or multiple-return value.
    ExtractValue {
        /// Variable that receives the extracted component.
        dest: VarId,
        /// The tuple (or multi-value result) being unpacked.
        tuple: Operand,
        /// Zero-based position of the component.
        index: usize,
    },

    // --- Operations & Async ---
    /// A binary operation, `dest = lhs op rhs`.
    BinaryOp {
        /// Variable that receives the result.
        dest: VarId,
        /// Operator as recorded by lowering: the token as written (for example `==`, `&&`), except that `+` is recorded as `concat`.
        op: String,
        /// Left operand.
        lhs: Operand,
        /// Right operand.
        rhs: Operand,
    },
    /// A unary operation, `dest = op src`.
    UnaryOp {
        /// Variable that receives the result.
        dest: VarId,
        /// Operator token as written (for example `!`, `-`, `~`), or `neg` when none was found.
        op: String,
        /// Operand.
        src: Operand,
    },
    /// Awaits a promise or future; `dest` receives the resolved value.
    Await {
        /// Variable that receives the resolved value.
        dest: VarId,
        /// Memory state after the await (other code may run while suspended).
        mem_out: VarId,
        /// Memory state the await starts in.
        mem_in: VarId,
        /// The promise or future being awaited.
        promise: Operand,
    },
    /// Yields a value from a generator or coroutine; `dest` receives whatever the caller sends back.
    Yield {
        /// Variable that receives the value sent back into the generator, if it is used.
        dest: Option<VarId>,
        /// Memory state after the yield.
        mem_out: VarId,
        /// Memory state the yield starts in.
        mem_in: VarId,
        /// The yielded value, if any.
        src: Option<Operand>,
    },
}

impl Instruction {
    /// The value variable this instruction defines, if any.
    ///
    /// Covers every instruction kind that produces a value: assignments,
    /// loads, calls (when the result is used), allocations, address-of,
    /// dereference, casts, aggregate extraction, unary/binary operations,
    /// `await` and `yield`. Memory-state outputs are not included; see
    /// [`Instruction::mem_out`]. This is the one definition of "what does this
    /// instruction define"; do not re-match the variants elsewhere, because
    /// a copy that forgets a variant silently drops findings on it.
    #[must_use]
    pub fn dest(&self) -> Option<VarId> {
        match self {
            Self::Assign { dest, .. }
            | Self::LoadField { dest, .. }
            | Self::LoadElement { dest, .. }
            | Self::LoadGlobal { dest, .. }
            | Self::Allocate { dest, .. }
            | Self::AddressOf { dest, .. }
            | Self::Dereference { dest, .. }
            | Self::Cast { dest, .. }
            | Self::ExtractValue { dest, .. }
            | Self::BinaryOp { dest, .. }
            | Self::UnaryOp { dest, .. }
            | Self::Await { dest, .. } => Some(*dest),
            Self::CallStatic { dest, .. }
            | Self::CallVirtual { dest, .. }
            | Self::CallPointer { dest, .. }
            | Self::Yield { dest, .. } => *dest,
            // No `_` arm on purpose: a new instruction kind must decide here
            // whether it defines a value.
            Self::StoreField { .. } | Self::StoreElement { .. } | Self::StoreGlobal { .. } => None,
        }
    }

    /// The memory-state variable this instruction produces, if any.
    #[must_use]
    pub fn mem_out(&self) -> Option<VarId> {
        match self {
            Self::StoreField { mem_out, .. }
            | Self::StoreElement { mem_out, .. }
            | Self::StoreGlobal { mem_out, .. }
            | Self::CallStatic { mem_out, .. }
            | Self::CallVirtual { mem_out, .. }
            | Self::CallPointer { mem_out, .. }
            | Self::Allocate { mem_out, .. }
            | Self::Await { mem_out, .. }
            | Self::Yield { mem_out, .. } => Some(*mem_out),
            Self::Assign { .. }
            | Self::LoadField { .. }
            | Self::LoadElement { .. }
            | Self::LoadGlobal { .. }
            | Self::AddressOf { .. }
            | Self::Dereference { .. }
            | Self::Cast { .. }
            | Self::ExtractValue { .. }
            | Self::BinaryOp { .. }
            | Self::UnaryOp { .. } => None,
        }
    }

    /// Every variable this instruction defines: the value result first, then
    /// the memory-state output.
    #[must_use]
    pub fn defs(&self) -> Vec<VarId> {
        self.dest().into_iter().chain(self.mem_out()).collect()
    }
}

/// Determines how control flow exits a BasicBlock.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum Terminator {
    /// Unconditional jump to the given block.
    Jump(BlockId),
    /// Two-way conditional branch on `cond`.
    Branch {
        /// Condition operand.
        cond: Operand,
        /// Block taken when the condition is truthy.
        true_block: BlockId,
        /// Block taken when the condition is falsy.
        false_block: BlockId,
    },
    /// Multi-way branch on `cond`.
    Switch {
        /// Value being switched on.
        cond: Operand,
        /// `(case value, target block)` pairs in source order.
        cases: Vec<(Operand, BlockId)>,
        /// Block taken when no case matches.
        default_block: BlockId,
    },
    /// Returns from the function.
    Return {
        /// Returned value, or `None` for a bare return.
        src: Option<Operand>,
    },
    /// Raises an exception or panics with the given value.
    Throw {
        /// Value being thrown.
        src: Operand,
    },
    /// No terminator yet: the block is still under construction (the state of every block created by [`BasicBlock::new`]).
    None,
}

/// A straight-line sequence of instructions with a single entry and a single terminator.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicBlock {
    /// Identifier of this block within its function.
    pub id: BlockId,
    /// Phi nodes evaluated at block entry, before any instruction.
    pub phis: Vec<Phi>,
    /// Instructions in execution order.
    pub instructions: Vec<Instruction>,
    /// How control leaves the block.
    pub terminator: Terminator,
    /// Blocks with an edge into this one.
    pub predecessors: Vec<BlockId>,
    /// Blocks this one has an edge to.
    pub successors: Vec<BlockId>,
}

impl BasicBlock {
    /// Creates an empty block with the given id: no phis, no instructions, [`Terminator::None`] and no edges.
    pub fn new(id: BlockId) -> Self {
        Self {
            id,
            phis: Vec::new(),
            instructions: Vec::new(),
            terminator: Terminator::None,
            predecessors: Vec::new(),
            successors: Vec::new(),
        }
    }
}

/// The IR of one function: its parameters, control-flow graph and per-variable metadata.
///
/// The heap is modelled explicitly. Every function owns a hidden memory-state parameter ([`FunctionIR::initial_memory_state`]) and every memory-affecting instruction consumes and produces a memory-state variable, so flow-sensitive heap reasoning is ordinary SSA dataflow.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct FunctionIR {
    /// Program-level name of the function.
    pub name: String,
    /// Formal parameters in declaration order, not including the hidden memory-state parameter.
    pub parameters: Vec<VarId>,
    /// The initial Memory State parameter for the function (representing the heap upon entry)
    pub initial_memory_state: VarId,
    /// All basic blocks, keyed by their [`BlockId`].
    pub blocks: FxHashMap<BlockId, BasicBlock>,
    /// The block execution starts in.
    pub entry_block: BlockId,
    /// Source-level metadata for every variable, including memory states.
    pub var_metadata: FxHashMap<VarId, VarMetadata>,
    /// Language key this IR was lowered from (`spec.fact_language()`:
    /// `"typescript"`,
    /// `"rust"`, ...). Sink and sanitizer facts are language-keyed, so every
    /// call site must know its own language: without this, a Rust
    /// `File::create` signature would fire on a JavaScript `prisma.create`
    /// in the same mixed-language scan. Empty when the IR was built by hand
    /// (synthetic test IRs) or decoded from legacy data.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub language: String,
    /// Program name of the innermost enclosing extracted function, when this
    /// function was extracted from a nested position (None for module scope).
    /// Closure edges resolve free variables through this lexical chain.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub enclosing_fn: Option<String>,
    /// Decorator / attribute call names applied to this function's
    /// definition (`@guard`, `#[guard]`). A decorator executes before ANY
    /// statement of the body, so policy guard requirements are satisfied
    /// by a matching entry guard without a guard call inside the body.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub entry_guards: Vec<String>,
    /// This IR is a module-level *data* binding, not a callable function:
    /// `const tools = {...}`, `const client = require("pkg")`. The harness
    /// lowers such initializers so non-dataflow checkers can assert policy
    /// over static configuration, but a call written with the binding's name
    /// (`client(req, res)`) is a call into the library, never into this IR.
    /// Resolving it here would hand the call an empty parameter list and a
    /// vacuous summary, which deleted the call site's pass-through taint
    /// edges and made every call through a `require` binding read Unknown.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub is_static_data: bool,
    /// True when the per-function analysis budget ran out while preparing
    /// this IR (SSA construction degraded to flow-insensitive form), so this
    /// function was analyzed with less precision than usual. The scanner
    /// reports every such function as `analysis_incomplete` instead of
    /// silently producing weaker results for it.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub analysis_incomplete: bool,
    #[cfg_attr(feature = "serialize", serde(default))]
    // legacy safety: recompute via max ids if absent
    next_var_id: usize,
    #[cfg_attr(feature = "serialize", serde(default))]
    next_block_id: usize,
}

impl FunctionIR {
    /// Creates an empty function with one empty entry block, and allocates the hidden memory-state parameter as [`FunctionIR::initial_memory_state`].
    pub fn new(name: String) -> Self {
        let entry_id = BlockId(0);
        let mut blocks = FxHashMap::default();
        blocks.insert(entry_id, BasicBlock::new(entry_id));

        let mut f = Self {
            name,
            parameters: Vec::new(),
            initial_memory_state: VarId(0), // Placeholder
            blocks,
            entry_block: entry_id,
            var_metadata: FxHashMap::default(),
            language: String::new(),
            enclosing_fn: None,
            entry_guards: Vec::new(),
            is_static_data: false,
            analysis_incomplete: false,
            next_var_id: 1,
            next_block_id: 1,
        };

        // Allocate the hidden Memory State parameter
        f.initial_memory_state = f.new_var(VarMetadata {
            source_name: Some(INITIAL_HEAP_STATE.into()),
            type_name: None,
            byte_range: None,
            is_memory_state: true,
            object_keys: Vec::new(),
            declared: false,
        });

        f
    }

    /// Source name of `var`, or `v<id>` when lowering recorded none.
    pub(crate) fn var_name(&self, var: VarId) -> String {
        self.var_metadata
            .get(&var)
            .and_then(|m| m.source_name.clone())
            .unwrap_or_else(|| format!("v{}", var.0))
    }

    /// Byte range of the expression that produced `var`, if lowering recorded one.
    pub(crate) fn var_span(&self, var: VarId) -> Option<(usize, usize)> {
        self.var_metadata.get(&var).and_then(|m| m.byte_range)
    }

    /// The instruction that defines `var`, if any. The IR is SSA, so there is
    /// at most one.
    pub(crate) fn def_instruction(&self, var: VarId) -> Option<&Instruction> {
        self.blocks
            .values()
            .flat_map(|b| b.instructions.iter())
            .find(|instr| instr.dest() == Some(var))
    }

    /// Byte range of a call instruction: the call result variable carries the
    /// call expression's range. `None` for non-calls and calls with no result.
    pub(crate) fn instr_span(&self, instr: &Instruction) -> Option<(usize, usize)> {
        let dest = match instr {
            Instruction::CallStatic { dest, .. }
            | Instruction::CallVirtual { dest, .. }
            | Instruction::CallPointer { dest, .. } => (*dest)?,
            _ => return None,
        };
        self.var_span(dest)
    }

    /// Allocates a fresh variable id, records its `metadata` and returns the id.
    pub fn new_var(&mut self, metadata: VarMetadata) -> VarId {
        let id = VarId(self.next_var_id);
        self.next_var_id += 1;
        self.var_metadata.insert(id, metadata);
        id
    }

    /// Allocates a fresh, empty, unconnected block and returns its id.
    pub fn new_block(&mut self) -> BlockId {
        let id = BlockId(self.next_block_id);
        self.next_block_id += 1;
        self.blocks.insert(id, BasicBlock::new(id));
        id
    }

    /// Appends a phi node to `block`. Does nothing if the block does not exist.
    pub fn push_phi(&mut self, block: BlockId, phi: Phi) {
        if let Some(b) = self.blocks.get_mut(&block) {
            b.phis.push(phi);
        }
    }

    /// Appends an instruction to the end of `block`. Does nothing if the block does not exist.
    pub fn push_instruction(&mut self, block: BlockId, instr: Instruction) {
        if let Some(b) = self.blocks.get_mut(&block) {
            b.instructions.push(instr);
        }
    }

    /// Sets how `block` exits. Does nothing if the block does not exist; the CFG edges are recorded separately by [`FunctionIR::add_edge`].
    pub fn set_terminator(&mut self, block: BlockId, terminator: Terminator) {
        if let Some(b) = self.blocks.get_mut(&block) {
            b.terminator = terminator;
        }
    }

    /// Records a control-flow edge `from -> to` in both blocks' successor and predecessor lists. Idempotent: an edge that is already present is not added twice.
    pub fn add_edge(&mut self, from: BlockId, to: BlockId) {
        if let Some(f) = self.blocks.get_mut(&from)
            && !f.successors.contains(&to)
        {
            f.successors.push(to);
        }
        if let Some(t) = self.blocks.get_mut(&to)
            && !t.predecessors.contains(&from)
        {
            t.predecessors.push(from);
        }
    }

    /// The receiver operand of the virtual call whose result is `var`, if
    /// any: lets a chained call (`conn.cursor().execute(..)`) resolve to
    /// the root of its receiver chain.
    pub(crate) fn call_receiver_def(&self, var: VarId) -> Option<VarId> {
        for b in self.blocks.values() {
            for instr in &b.instructions {
                if let Instruction::CallVirtual {
                    dest: Some(d),
                    receiver: Operand::Var(r),
                    ..
                } = instr
                    && *d == var
                {
                    return Some(*r);
                }
            }
        }
        None
    }

    /// The `LoadField` instruction defining `var`, if any (first match - IR
    /// is SSA-shaped): returns the base var and the loaded field. Shared
    /// walk step for member-access path reconstruction.
    pub(crate) fn loadfield_def(&self, var: VarId) -> Option<(VarId, String)> {
        for b in self.blocks.values() {
            for instr in &b.instructions {
                if let Instruction::LoadField {
                    dest, base, field, ..
                } = instr
                    && *dest == var
                {
                    return Some((*base, field.clone()));
                }
            }
        }
        None
    }
}

/// Strips one pair of matching `'`, `"` or `` ` `` quotes from a string
/// literal's source text, after trimming. Unmatched or lone quotes are left as is.
pub(crate) fn strip_quotes(lit: &str) -> &str {
    let lit = lit.trim();
    let bytes = lit.as_bytes();
    if let (Some(&first), Some(&last)) = (bytes.first(), bytes.last())
        && bytes.len() >= 2
        && matches!(first, b'\'' | b'"' | b'`')
        && first == last
    {
        return &lit[1..bytes.len() - 1];
    }
    lit
}
