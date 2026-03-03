# Event Schema

Events represent immutable, append-only records of actions and state
changes during a scan. They form the audit trail.

## Required Fields

- **event_type**: Category of event (see types below)
- **phase**: Which phase emitted this event
- **payload**: JSON payload with event-specific data

## Event Types

| Type              | Description                              | Payload Keys              |
|-------------------|------------------------------------------|---------------------------|
| phase_started     | A scan phase began                       | phase, targets            |
| phase_completed   | A scan phase finished                    | phase, duration_ms, score |
| tool_called       | A tool was invoked                       | tool, args, phase         |
| tool_completed    | A tool returned results                  | tool, status, duration_ms |
| tool_failed       | A tool raised an error                   | tool, error, phase        |
| discovery_new     | A new discovery was persisted            | discovery_type, value     |
| strategy_updated  | Scan strategy was modified               | changes, source           |
| scan_paused       | Operator paused the scan                 | reason                    |
| scan_resumed      | Operator resumed the scan                | —                         |
| scan_cancelled    | Operator cancelled the scan              | reason                    |
| reasoning         | Agent reasoning trace                    | phase, content            |
| evaluation        | Phase quality evaluation result          | phase, score, completeness|

## Ordering

Events are ordered by `(scan_id, sequence_number)`. The sequence number
is monotonically increasing per scan. This guarantees deterministic replay.

## Immutability

Events are **never updated or deleted**. They are append-only.
