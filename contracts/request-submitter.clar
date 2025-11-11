;; contracts/request-submitter.clar
(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-PROOF-VERIFIER-NOT-SET u101)
(define-constant ERR-IDENTITY-MANAGER-NOT-SET u102)
(define-constant ERR-INVALID-PROOF u103)
(define-constant ERR-REPLAY-ATTACK u104)
(define-constant ERR-REQUEST-NOT-FOUND u105)
(define-constant ERR-INVALID-STATUS-TRANSITION u106)
(define-constant ERR-REQUEST-EXPIRED u107)
(define-constant ERR-INVALID-METADATA u108)
(define-constant ERR-MAX-REQUESTS-REACHED u109)
(define-constant ERR-INVALID-NULLIFIER u110)
(define-constant ERR-VERIFICATION-FAILED u111)
(define-constant ERR-INVALID-REQUEST-TYPE u112)
(define-constant ERR-REQUEST-ALREADY-PROCESSED u113)
(define-constant ERR-INVALID-REQUEST-ID u114)
(define-constant ERR-PROOF-VERIFIER-CALL-FAILED u115)

(define-constant MAX-REQUESTS u10000)
(define-constant REQUEST-EXPIRY-BLOCKS u52560)

(define-data-var next-request-id uint u0)
(define-data-var proof-verifier-contract (optional principal) none)
(define-data-var identity-manager-contract (optional principal) none)
(define-data-var admin principal tx-sender)

(define-map requests
  uint
  {
    requester-commitment: (buff 32),
    nullifier-hash: (buff 32),
    proof-hash: (buff 32),
    request-type: (string-utf8 50),
    metadata-hash: (buff 32),
    status: (string-utf8 20),
    created-at: uint,
    expires-at: uint,
    verifier-notes: (optional (string-utf8 200))
  }
)

(define-map nullifier-used (buff 32) bool)
(define-map request-by-commitment (buff 32) uint)

(define-read-only (get-request (request-id uint))
  (map-get? requests request-id)
)

(define-read-only (get-request-id-by-commitment (commitment (buff 32)))
  (map-get? request-by-commitment commitment)
)

(define-read-only (is-nullifier-used (nullifier (buff 32)))
  (default-to false (map-get? nullifier-used nullifier))
)

(define-read-only (get-next-request-id)
  (ok (var-get next-request-id))
)

(define-read-only (get-proof-verifier)
  (var-get proof-verifier-contract)
)

(define-read-only (get-identity-manager)
  (var-get identity-manager-contract)
)

(define-private (validate-request-type (req-type (string-utf8 50)))
  (match req-type
    "aid" (ok true)
    "grant" (ok true)
    "report" (ok true)
    "access" (ok true)
    (err ERR-INVALID-REQUEST-TYPE))
)

(define-private (validate-metadata-hash (hash (buff 32)))
  (if (is-eq (len hash) u32)
      (ok true)
      (err ERR-INVALID-METADATA))
)

(define-private (validate-commitment (commitment (buff 32)))
  (if (is-eq (len commitment) u32)
      (ok true)
      (err ERR-INVALID-METADATA))
)

(define-private (validate-nullifier (nullifier (buff 32)))
  (if (is-eq (len nullifier) u32)
      (ok true)
      (err ERR-INVALID-NULLIFIER))
)

(define-private (validate-proof-hash (hash (buff 32)))
  (if (is-eq (len hash) u32)
      (ok true)
      (err ERR-INVALID-PROOF))
)

(define-public (set-proof-verifier (verifier principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-none (var-get proof-verifier-contract)) (err ERR-PROOF-VERIFIER-NOT-SET))
    (var-set proof-verifier-contract (some verifier))
    (ok true)
  )
)

(define-public (set-identity-manager (manager principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-none (var-get identity-manager-contract)) (err ERR-IDENTITY-MANAGER-NOT-SET))
    (var-set identity-manager-contract (some manager))
    (ok true)
  )
)

(define-public (submit-request
  (commitment (buff 32))
  (nullifier-hash (buff 32))
  (proof-hash (buff 32))
  (request-type (string-utf8 50))
  (metadata-hash (buff 32))
  (public-signals (list 10 uint))
)
  (let (
    (request-id (var-get next-request-id))
    (current-block block-height)
    (expires-at (+ current-block REQUEST-EXPIRY-BLOCKS))
    (verifier (unwrap! (var-get proof-verifier-contract) (err ERR-PROOF-VERIFIER-NOT-SET)))
  )
    (asserts! (< request-id MAX-REQUESTS) (err ERR-MAX-REQUESTS-REACHED))
    (try! (validate-commitment commitment))
    (try! (validate-nullifier nullifier-hash))
    (try! (validate-proof-hash proof-hash))
    (try! (validate-request-type request-type))
    (try! (validate-metadata-hash metadata-hash))
    (asserts! (not (is-nullifier-used nullifier-hash)) (err ERR-REPLAY-ATTACK))
    (asserts! (is-none (map-get? request-by-commitment commitment)) (err ERR-REPLAY-ATTACK))

    (let ((proof-result (contract-call? verifier verify-proof proof-hash public-signals)))
      (asserts! (is-ok proof-result) (err ERR-VERIFICATION-FAILED))
      (asserts! (unwrap! proof-result (err ERR-PROOF-VERIFIER-CALL-FAILED)) (err ERR-VERIFICATION-FAILED))
    )

    (map-set requests request-id
      {
        requester-commitment: commitment,
        nullifier-hash: nullifier-hash,
        proof-hash: proof-hash,
        request-type: request-type,
        metadata-hash: metadata-hash,
        status: "pending",
        created-at: current-block,
        expires-at: expires-at,
        verifier-notes: none
      }
    )

    (map-set nullifier-used nullifier-hash true)
    (map-set request-by-commitment commitment request-id)
    (var-set next-request-id (+ request-id u1))
    (print { event: "request-submitted", id: request-id, type: request-type })
    (ok request-id)
  )
)

(define-public (update-request-status
  (request-id uint)
  (new-status (string-utf8 20))
  (notes (optional (string-utf8 200)))
)
  (let ((request (unwrap! (map-get? requests request-id) (err ERR-REQUEST-NOT-FOUND))))
    (asserts! (is-eq tx-sender (var-get admin)) (err ERR-NOT-AUTHORIZED))
    (asserts! (> (get expires-at request) block-height) (err ERR-REQUEST-EXPIRED))

    (let ((current-status (get status request)))
      (asserts!
        (or
          (and (is-eq current-status "pending") (or (is-eq new-status "approved") (is-eq new-status "rejected")))
          (and (is-eq current-status "approved") (is-eq new-status "fulfilled"))
          (and (is-eq current-status "rejected") (is-eq new-status "closed"))
        )
        (err ERR-INVALID-STATUS-TRANSITION)
      )

      (map-set requests request-id
        (merge request
          {
            status: new-status,
            verifier-notes: (if (is-some notes) notes (get verifier-notes request))
          }
        )
      )

      (print { event: "request-status-updated", id: request-id, status: new-status })
      (ok true)
    )
  )
)

(define-public (withdraw-request (commitment (buff 32)))
  (let (
    (request-id (unwrap! (map-get? request-by-commitment commitment) (err ERR-REQUEST-NOT-FOUND)))
    (request (unwrap! (map-get? requests request-id) (err ERR-REQUEST-NOT-FOUND)))
  )
    (asserts! (is-eq (get status request) "pending") (err ERR-INVALID-STATUS-TRANSITION))
    (asserts! (> (get expires-at request) block-height) (err ERR-REQUEST-EXPIRED))

    (map-delete requests request-id)
    (map-delete request-by-commitment commitment)
    (map-delete nullifier-used (get nullifier-hash request))

    (print { event: "request-withdrawn", id: request-id })
    (ok true)
  )
)

(define-public (admin-withdraw-stuck-request (request-id uint))
  (let ((request (unwrap! (map-get? requests request-id) (err ERR-REQUEST-NOT-FOUND))))
    (asserts! (is-eq tx-sender (var-get admin)) (err ERR-NOT-AUTHORIZED))
    (asserts! (<= (get expires-at request) block-height) (err ERR-REQUEST-NOT-EXPIRED))

    (map-delete requests request-id)
    (map-delete request-by-commitment (get requester-commitment request))
    (map-delete nullifier-used (get nullifier-hash request))

    (print { event: "request-expired-cleaned", id: request-id })
    (ok true)
  )
)

(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err ERR-NOT-AUTHORIZED))
    (var-set admin new-admin)
    (ok true)
  )
)