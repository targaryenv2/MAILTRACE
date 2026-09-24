// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MailCustody - append-only chain of custody for email forensic evidence
/// @notice Records the custody trail of a phishing investigation. Nothing here
///         stores email content or personal data: only keccak-256 digests,
///         short verdict labels and timestamps. The original evidence stays in
///         the case store, and this contract is what proves it was not edited
///         afterwards.
///
/// Design decisions worth defending:
///
/// * **Append-only with a per-case hash chain.** Each entry embeds the digest of
///   the previous entry for the same case, so the trail is verifiable as a chain
///   in addition to being immutable as a transaction. Deleting or reordering an
///   entry breaks the chain and `verifyChain` returns false.
/// * **No delete, no update, no `selfdestruct`.** There is deliberately no way to
///   amend a record. An evidence log with an edit function is not evidence.
/// * **Digests only.** Putting message bodies or recipient addresses on a public
///   chain would be an irreversible privacy breach and, under DPDP/GDPR, a
///   defect rather than a feature. Callers hash first; see
///   `backend/app/privacy/redact.py`.
/// * **Recorder allow-list.** Only addresses the owner has authorised can write,
///   so an attacker cannot pollute a case with fabricated custody entries.
contract MailCustody {
    enum Kind { Evidence, Step, Verdict, Action }

    struct Entry {
        Kind kind;
        bytes32 payloadHash;   // keccak256 of the canonical payload the app recorded
        bytes32 prevHash;      // hash of the previous entry for this case (0x0 for the first)
        uint64 timestamp;      // block time, set by the chain and not by the caller
        address recorder;
        string label;          // short human-readable label, e.g. "verdict:phishing risk=93"
    }

    address public owner;
    mapping(address => bool) public recorders;
    mapping(bytes32 => Entry[]) private _entries;   // caseKey => entries
    mapping(bytes32 => bytes32) public headHash;    // caseKey => hash of the latest entry
    bytes32[] private _caseKeys;
    mapping(bytes32 => bool) private _seenCase;

    event EntryRecorded(
        bytes32 indexed caseKey,
        uint256 indexed index,
        Kind kind,
        bytes32 payloadHash,
        bytes32 prevHash,
        bytes32 entryHash,
        address recorder,
        string label
    );
    event RecorderSet(address indexed recorder, bool allowed);

    error NotOwner();
    error NotRecorder();
    error EmptyCaseId();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyRecorder() {
        if (!recorders[msg.sender] && msg.sender != owner) revert NotRecorder();
        _;
    }

    constructor() {
        owner = msg.sender;
        recorders[msg.sender] = true;
        emit RecorderSet(msg.sender, true);
    }

    function setRecorder(address who, bool allowed) external onlyOwner {
        recorders[who] = allowed;
        emit RecorderSet(who, allowed);
    }

    /// @dev Cases are keyed by hash so the storage slot is fixed-width and the
    ///      case identifier itself (which may embed a ticket reference) is not
    ///      stored in plain form.
    function caseKey(string calldata caseId) public pure returns (bytes32) {
        if (bytes(caseId).length == 0) revert EmptyCaseId();
        return keccak256(abi.encodePacked(caseId));
    }

    function _record(
        string calldata caseId,
        Kind kind,
        bytes32 payloadHash,
        string calldata label
    ) internal returns (uint256 index, bytes32 entryHash) {
        bytes32 key = caseKey(caseId);
        bytes32 prev = headHash[key];
        index = _entries[key].length;
        entryHash = keccak256(
            abi.encode(key, index, uint8(kind), payloadHash, prev, uint64(block.timestamp), msg.sender)
        );
        _entries[key].push(Entry({
            kind: kind,
            payloadHash: payloadHash,
            prevHash: prev,
            timestamp: uint64(block.timestamp),
            recorder: msg.sender,
            label: label
        }));
        headHash[key] = entryHash;
        if (!_seenCase[key]) {
            _seenCase[key] = true;
            _caseKeys.push(key);
        }
        emit EntryRecorded(key, index, kind, payloadHash, prev, entryHash, msg.sender, label);
    }

    /// @notice Seal the received message. `emailHash` is the sha256 of the raw
    ///         .eml as stored; `metaHash` covers filename, size and reporter.
    function recordEvidence(string calldata caseId, bytes32 emailHash, string calldata label)
        external onlyRecorder returns (uint256 index, bytes32 entryHash)
    {
        return _record(caseId, Kind.Evidence, emailHash, label);
    }

    /// @notice One investigation step. `resultHash` binds the step's output so a
    ///         later edit to the stored result is detectable.
    function recordStep(
        string calldata caseId,
        uint256 stepIndex,
        bytes32 resultHash,
        string calldata label
    ) external onlyRecorder returns (uint256 index, bytes32 entryHash) {
        return _record(caseId, Kind.Step, keccak256(abi.encode(stepIndex, resultHash)), label);
    }

    /// @notice The verdict, with its risk score and confidence, bound together.
    function recordVerdict(
        string calldata caseId,
        uint256 riskScore,
        uint256 confidence,
        string calldata label
    ) external onlyRecorder returns (uint256 index, bytes32 entryHash) {
        return _record(caseId, Kind.Verdict, keccak256(abi.encode(riskScore, confidence, label)), label);
    }

    /// @notice An analyst decision (approve / override / escalate). Recording the
    ///         human step is what makes the audit trail complete.
    function recordAction(string calldata caseId, bytes32 analystHash, string calldata label)
        external onlyRecorder returns (uint256 index, bytes32 entryHash)
    {
        return _record(caseId, Kind.Action, analystHash, label);
    }

    // ---- views ----------------------------------------------------------

    function entryCount(string calldata caseId) external view returns (uint256) {
        return _entries[caseKey(caseId)].length;
    }

    function entryAt(string calldata caseId, uint256 index) external view returns (Entry memory) {
        return _entries[caseKey(caseId)][index];
    }

    function caseCount() external view returns (uint256) {
        return _caseKeys.length;
    }

    function caseKeyAt(uint256 index) external view returns (bytes32) {
        return _caseKeys[index];
    }

    /// @notice Recompute the per-case hash chain on-chain.
    /// @return ok true when every entry links to its predecessor and the head matches
    function verifyChain(string calldata caseId) external view returns (bool ok) {
        bytes32 key = caseKey(caseId);
        Entry[] storage list = _entries[key];
        bytes32 running = bytes32(0);
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i].prevHash != running) return false;
            running = keccak256(
                abi.encode(key, i, uint8(list[i].kind), list[i].payloadHash,
                           list[i].prevHash, list[i].timestamp, list[i].recorder)
            );
        }
        return running == headHash[key];
    }
}
