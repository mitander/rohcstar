# Rohcstar Naming Conventions

This document outlines specific naming conventions and clarifications adopted for the Rohcstar project, building upon standard Rust idioms. Adherence to these conventions is crucial for maintaining code clarity, consistency, and readability.

*Standard Rust casing conventions (e.g., `snake_case` for functions/variables/modules, `UpperCamelCase` for types, `SCREAMING_SNAKE_CASE` for constants) are assumed and generally not reiterated here.*

## Guiding Principles

1.  **Clarity Over Brevity:** Names should clearly communicate their purpose.
2.  **Consistency is Paramount:** Apply chosen conventions uniformly.
3.  **Reflect Semantics:** Names should provide strong hints about behavior or data.
4.  **Searchability:** Consistent naming aids in code discovery.

## Conventions

### 1. Types (Structs, Enums, Traits)

*   **Acronyms:**
    *   Prefer full words (e.g., `IrPacket` not `IRPacket`).
    *   For universally understood acronyms (e.g., IP, SSRC, SN, CRC), capitalize only the first letter if part of a longer `UpperCamelCase` name (e.g., `IpId`, `UdpPort`). If the acronym forms an entire segment, all letters can be capitalized (e.g., `SSRCValue`).
*   **Redundancy:** Avoid redundant prefixes/suffixes (e.g., `Profile1Handler`, not `Profile1ProfileHandler`).
*   **Standard Suffixes:**
    *   Error types: `...Error` (e.g., `RohcParsingError`).
    *   Context types: `...Context` (e.g., `Profile1CompressorContext`).
    *   Builder pattern types: `...Builder`.
*   **Newtypes:** `UpperCamelCase(InnerType)` (e.g., `SequenceNumber(u16)`). Name should reflect semantic meaning.

### 2. Functions and Methods

*   **General Actions:** Typically `verb_noun()` (e.g., `compress_packet()`, `initialize_context()`).
*   **Boolean Queries (Predicates):** Prefixed with `is_`, `has_`, `can_` (e.g., `is_valid()`, `has_pending_feedback()`).
*   **Fallible Operations (Returning `Result<T, E>`):**
    Most functions that can fail should be named for their primary action (e.g., `parse_header()`, `build_rohc_packet()`); the `Result<T, E>` return type itself clearly signals fallibility.
    *Example (Standard Fallible Function):*
    ```rust
    // Parsing can fail due to malformed input or CRC errors.
    // The name focuses on the action: "parse an IR packet".
    fn parse_ir_packet(bytes: &[u8]) -> Result<IrPacket, RohcParsingError>;
    ```
    The `try_` prefix (e.g., `try_send_feedback()`) is used **selectively**. It is reserved for functions where an `Err` outcome represents a common, expected, and often non-critical part of the immediate control flow, such as a non-blocking attempt or a check for a transient condition (like a temporarily full send buffer or an unavailable non-essential resource). It signals that the caller should typically be prepared to handle this "failure" gracefully and immediately, often without treating it as a deeper error.
    *Example (Selective `try_` Prefix):*
    ```rust
    // Attempts to send feedback. Failure (e.g., channel full) is an expected,
    // non-critical outcome the caller might immediately handle by deferring.
    fn try_send_feedback(feedback: &FeedbackData) -> Result<(), FeedbackError>;
    ```
    *This prefix is not applied to all `Result`-returning functions; its use should be deliberate to highlight specific "attempt" semantics.*
*   **`Option`-Returning Functions:**
    *   **Getters/Simple Retrievals:** `get_noun()` or simply `noun()` (e.g., `get_ssrc() -> Option<Ssrc>`).
    *   **Finders/Searchers:** `find_noun_by_criteria()` (e.g., `find_context_by_ssrc()`).
    *   A general `maybe_` prefix is typically **avoided**. Prefer descriptive verbs.
*   **Conversions:**
    *   **Borrowing:** `as_noun()` (e.g., `as_bytes()`).
    *   **Consuming/Owned:** `into_noun()` (e.g., `into_config()`).
*   **Setters:** `set_noun()` (e.g., `set_cid()`).

### 3. Constants

*   **Profile-Specific Prefix:** `P<rohc_profile_num>_<COMPONENT_GROUP>_<NAME>` (e.g., `P1_UO_1_SN_PACKET_TYPE_PREFIX`, `P1_DECOMPRESSOR_FC_TO_SC_THRESHOLD`).
*   **Generic ROHC Prefix:** `ROHC_<COMPONENT_GROUP>_<NAME>` (e.g., `ROHC_ADD_CID_FEEDBACK_PREFIX_MASK`).
*   **Standard Protocol Prefixes (If distinct from general constants):** `IPV4_...`, `UDP_...`, `RTP_...`.

### 4. Test Functions

Test function names should clearly describe the feature or unit of logic being tested and the specific scenario under examination.

*   **Integration Tests (in `tests/` directory):**
    *   Pattern: `p<rohc_profile_num>_<feature_or_packet_type>_<scenario_description>`
    *   Example: `p1_ir_handles_crc_corruption`, `p1_uo1_rtp_ts_scaled_overflow_triggers_ir`.
*   **Unit Tests (within modules `#[cfg(test)] mod tests { ... }`):**
    *   Pattern: `<function_or_logic_unit>_<scenario_description>` or `<feature>_<scenario_description>`
    *   The name should be descriptive enough to understand the test's purpose without requiring prefixes like `test_` or `unit_`.
    *   Example (for `compressor::should_force_ir`): `should_force_ir_on_ssrc_change`, `should_force_ir_when_refresh_interval_met`.
    *   Example (for a specific packet parsing function): `parse_uo0_packet_with_valid_crc_succeeds`.
