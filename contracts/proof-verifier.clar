;; proof-verifier.clar

(define-constant ERR-NOT-AUTHORIZED u1000)
(define-constant ERR-INVALID-PROOF u1001)
(define-constant ERR-INVALID_PUBLIC_INPUTS u1002)
(define-constant ERR-INVALID_VERIFICATION_KEY u1003)
(define-constant ERR-CIRCUIT_NOT_FOUND u1004)
(define-constant ERR-INVALID_CIRCUIT_ID u1005)
(define-constant ERR_INVALID_PROOF_STRUCTURE u1006)
(define-constant ERR_VERIFICATION_FAILED u1007)
(define-constant ERR_KEY_ALREADY_EXISTS u1008)
(define-constant ERR_INVALID_BUFFER_LENGTH u1009)
(define-constant ERR_INVALID_LIST_LENGTH u1010)
(define-constant ERR_GOVERNANCE_NOT_SET u1011)
(define-constant ERR_INVALID_TIMESTAMP u1012)
(define-constant ERR_PROOF_ALREADY_USED u1013)
(define-constant ERR_INVALID_SIGNAL u1014)
(define-constant ERR_INVALID_NULLIFIER u1015)
(define-constant ERR_INVALID_COMMITMENT u1016)
(define-constant ERR_MAX_CIRCUITS_EXCEEDED u1017)
(define-constant ERR_INVALID_CIRCUIT_TYPE u1018)
(define-constant ERR_INVALID_GROTH16_PARAMS u1019)
(define-constant ERR_INVALID_SNARK_PARAMS u1020)

(define-data-var next-circuit-id uint u0)
(define-data-var max-circuits uint u50)
(define-data-var governance-principal (optional principal) none)

(define-map verification-keys
  uint
  { vk-alpha: (buff 32),
    vk-beta: (buff 64),
    vk-gamma: (buff 64),
    vk-delta: (buff 64),
    vk-ic: (list 10 (buff 32)),
    circuit-type: (string-ascii 32),
    timestamp: uint,
    updater: principal }
)

(define-map circuit-metadata
  uint
  { input-size: uint,
    output-size: uint,
    description: (string-utf8 256),
    active: bool }
)

(define-map used-nullifiers
  (buff 32)
  bool)

(define-read-only (get-verification-key (circuit-id uint))
  (map-get? verification-keys circuit-id)
)

(define-read-only (get-circuit-metadata (circuit-id uint))
  (map-get? circuit-metadata circuit-id)
)

(define-read-only (is-circuit-active (circuit-id uint))
  (match (map-get? circuit-metadata circuit-id)
    meta (get active meta)
    false)
)

(define-private (validate-buffer-length (buf (buff 64)) (expected uint))
  (if (is-eq (len buf) expected)
    (ok true)
    (err ERR_INVALID_BUFFER_LENGTH))
)

(define-private (validate-list-length (lst (list 10 (buff 32))) (expected uint))
  (if (is-eq (len lst) expected)
    (ok true)
    (err ERR_INVALID_LIST_LENGTH))
)

(define-private (validate-circuit-id (id uint))
  (if (< id (var-get next-circuit-id))
    (ok true)
    (err ERR_INVALID_CIRCUIT_ID))
)

(define-private (validate-circuit-type (ctype (string-ascii 32)))
  (if (or (is-eq ctype "groth16") (is-eq ctype "snark"))
    (ok true)
    (err ERR_INVALID_CIRCUIT_TYPE))
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
    (ok true)
    (err ERR_INVALID_TIMESTAMP))
)

(define-private (validate-proof-structure (proof { a: (buff 32), b: (buff 64), c: (buff 32) }))
  (begin
    (try! (validate-buffer-length (get a proof) u32))
    (try! (validate-buffer-length (get b proof) u64))
    (try! (validate-buffer-length (get c proof) u32))
    (ok true))
)

(define-private (validate-public-inputs (inputs (list 10 uint)) (expected-size uint))
  (if (is-eq (len inputs) expected-size)
    (ok true)
    (err ERR_INVALID_PUBLIC_INPUTS))
)

(define-private (validate-nullifier (nullifier (buff 32)))
  (if (is-none (map-get? used-nullifiers nullifier))
    (ok true)
    (err ERR_PROOF_ALREADY_USED))
)

(define-private (is-governance (caller principal))
  (match (var-get governance-principal)
    gov (is-eq gov caller)
    false)
)

(define-public (set-governance (new-gov principal))
  (begin
    (asserts! (is-none (var-get governance-principal)) (err ERR_GOVERNANCE_NOT_SET))
    (var-set governance-principal (some new-gov))
    (ok true))
)

(define-public (add-verification-key
  (circuit-id uint)
  (vk-alpha (buff 32))
  (vk-beta (buff 64))
  (vk-gamma (buff 64))
  (vk-delta (buff 64))
  (vk-ic (list 10 (buff 32)))
  (circuit-type (string-ascii 32))
  (input-size uint)
  (output-size uint)
  (description (string-utf8 256)))
  (begin
    (asserts! (is-governance tx-sender) (err ERR_NOT-AUTHORIZED))
    (asserts! (< (var-get next-circuit-id) (var-get max-circuits)) (err ERR_MAX_CIRCUITS_EXCEEDED))
    (try! (validate-buffer-length vk-alpha u32))
    (try! (validate-buffer-length vk-beta u64))
    (try! (validate-buffer-length vk-gamma u64))
    (try! (validate-buffer-length vk-delta u64))
    (try! (validate-list-length vk-ic u10))
    (try! (validate-circuit-type circuit-type))
    (asserts! (is-none (map-get? verification-keys circuit-id)) (err ERR_KEY_ALREADY_EXISTS))
    (map-set verification-keys circuit-id
      { vk-alpha: vk-alpha,
        vk-beta: vk-beta,
        vk-gamma: vk-gamma,
        vk-delta: vk-delta,
        vk-ic: vk-ic,
        circuit-type: circuit-type,
        timestamp: block-height,
        updater: tx-sender })
    (map-set circuit-metadata circuit-id
      { input-size: input-size,
        output-size: output-size,
        description: description,
        active: true })
    (var-set next-circuit-id (+ circuit-id u1))
    (print { event: "key-added", circuit-id: circuit-id })
    (ok circuit-id))
)

(define-public (update-verification-key
  (circuit-id uint)
  (vk-alpha (buff 32))
  (vk-beta (buff 64))
  (vk-gamma (buff 64))
  (vk-delta (buff 64))
  (vk-ic (list 10 (buff 32))))
  (let ((key (map-get? verification-keys circuit-id)))
    (match key
      k
      (begin
        (asserts! (is-governance tx-sender) (err ERR_NOT-AUTHORIZED))
        (try! (validate-buffer-length vk-alpha u32))
        (try! (validate-buffer-length vk-beta u64))
        (try! (validate-buffer-length vk-gamma u64))
        (try! (validate-buffer-length vk-delta u64))
        (try! (validate-list-length vk-ic u10))
        (map-set verification-keys circuit-id
          { vk-alpha: vk-alpha,
            vk-beta: vk-beta,
            vk-gamma: vk-gamma,
            vk-delta: vk-delta,
            vk-ic: vk-ic,
            circuit-type: (get circuit-type k),
            timestamp: block-height,
            updater: tx-sender })
        (print { event: "key-updated", circuit-id: circuit-id })
        (ok true))
      (err ERR_CIRCUIT_NOT_FOUND))))
(define-public (deactivate-circuit (circuit-id uint))
  (begin
    (asserts! (is-governance tx-sender) (err ERR_NOT-AUTHORIZED))
    (try! (validate-circuit-id circuit-id))
    (match (map-get? circuit-metadata circuit-id)
      meta
      (begin
        (map-set circuit-metadata circuit-id
          (merge meta { active: false }))
        (ok true))
      (err ERR_CIRCUIT_NOT_FOUND))))

(define-public (verify-groth16-proof
  (circuit-id uint)
  (proof { a: (buff 32), b: (buff 64), c: (buff 32) })
  (public-inputs (list 10 uint))
  (nullifier (buff 32))
  (signal (buff 32)))
  (let ((key (unwrap! (map-get? verification-keys circuit-id) (err ERR_CIRCUIT_NOT_FOUND)))
        (meta (unwrap! (map-get? circuit-metadata circuit-id) (err ERR_CIRCUIT_NOT_FOUND))))
    (asserts! (get active meta) (err ERR_CIRCUIT_NOT_FOUND))
    (asserts! (is-eq (get circuit-type key) "groth16") (err ERR_INVALID_CIRCUIT_TYPE))
    (try! (validate-proof-structure proof))
    (try! (validate-public-inputs public-inputs (get input-size meta)))
    (try! (validate-nullifier nullifier))
    (asserts! (contract-call? .zk-lib verify-groth16
      (get a proof)
      (get b proof)
      (get c proof)
      public-inputs
      (get vk-alpha key)
      (get vk-beta key)
      (get vk-gamma key)
      (get vk-delta key)
      (get vk-ic key)) (err ERR_VERIFICATION_FAILED))
    (map-set used-nullifiers nullifier true)
    (print { event: "proof-verified", circuit-id: circuit-id, nullifier: nullifier })
    (ok true)))

(define-public (verify-snark-proof
  (circuit-id uint)
  (proof { pi-a: (buff 32), pi-b: (buff 64), pi-c: (buff 32) })
  (public-inputs (list 10 uint))
  (commitment (buff 32)))
  (let ((key (unwrap! (map-get? verification-keys circuit-id) (err ERR_CIRCUIT_NOT_FOUND)))
        (meta (unwrap! (map-get? circuit-metadata circuit-id) (err ERR_CIRCUIT_NOT_FOUND))))
    (asserts! (get active meta) (err ERR_CIRCUIT_NOT_FOUND))
    (asserts! (is-eq (get circuit-type key) "snark") (err ERR_INVALID_CIRCUIT_TYPE))
    (try! (validate-proof-structure { a: (get pi-a proof), b: (get pi-b proof), c: (get pi-c proof) }))
    (try! (validate-public-inputs public-inputs (get input-size meta)))
    (try! (validate-buffer-length commitment u32))
    (asserts! (contract-call? .zk-lib verify-snark
      (get pi-a proof)
      (get pi-b proof)
      (get pi-c proof)
      public-inputs
      (get vk-alpha key)
      (get vk-beta key)
      (get vk-gamma key)
      (get vk-delta key)
      (get vk-ic key)) (err ERR_VERIFICATION_FAILED))
    (print { event: "snark-verified", circuit-id: circuit-id, commitment: commitment })
    (ok true)))

(define-public (get-circuit-count)
  (ok (var-get next-circuit-id)))

(define-public (is-nullifier-used (nullifier (buff 32)))
  (ok (default-to false (map-get? used-nullifiers nullifier))))