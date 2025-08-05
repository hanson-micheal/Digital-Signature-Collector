;; Digital Signature Collector - Main Contract
;; A comprehensive petition and agreement signing system with verification and versioning

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-DOCUMENT-NOT-FOUND (err u101))
(define-constant ERR-ALREADY-SIGNED (err u102))
(define-constant ERR-DOCUMENT-EXPIRED (err u103))
(define-constant ERR-INVALID-SIGNATURE (err u104))
(define-constant ERR-DOCUMENT-LOCKED (err u105))
(define-constant ERR-INSUFFICIENT-VERIFICATION (err u106))

;; Contract owner
(define-constant CONTRACT-OWNER tx-sender)

;; Data structures
(define-map documents
  { document-id: uint }
  {
    title: (string-ascii 256),
    content-hash: (buff 32),
    creator: principal,
    created-at: uint,
    expires-at: (optional uint),
    required-verification-level: uint,
    is-locked: bool,
    version: uint,
    signature-count: uint
  }
)

(define-map document-signatures
  { document-id: uint, signer: principal }
  {
    signature-hash: (buff 32),
    signed-at: uint,
    verification-level: uint,
    metadata: (string-ascii 512)
  }
)

(define-map user-verification-levels
  { user: principal }
  { level: uint, verified-at: uint, verifier: principal }
)

(define-map document-versions
  { document-id: uint, version: uint }
  {
    content-hash: (buff 32),
    updated-at: uint,
    updated-by: principal,
    change-log: (string-ascii 512)
  }
)

;; Global counters
(define-data-var next-document-id uint u1)

;; Verification levels
(define-constant VERIFICATION-NONE u0)
(define-constant VERIFICATION-BASIC u1)
(define-constant VERIFICATION-ENHANCED u2)
(define-constant VERIFICATION-PREMIUM u3)

;; === DOCUMENT MANAGEMENT ===

;; Create a new document
(define-public (create-document
  (title (string-ascii 256))
  (content-hash (buff 32))
  (expires-at-block (optional uint))
  (required-verification-level uint))
  (let ((document-id (var-get next-document-id)))
    (asserts! (<= required-verification-level VERIFICATION-PREMIUM) ERR-NOT-AUTHORIZED)
    (map-set documents
      { document-id: document-id }
      {
        title: title,
        content-hash: content-hash,
        creator: tx-sender,
        created-at: stacks-block-height,
        expires-at: expires-at-block,
        required-verification-level: required-verification-level,
        is-locked: false,
        version: u1,
        signature-count: u0
      }
    )
    (map-set document-versions
      { document-id: document-id, version: u1 }
      {
        content-hash: content-hash,
        updated-at: stacks-block-height,
        updated-by: tx-sender,
        change-log: "Initial version"
      }
    )
    (var-set next-document-id (+ document-id u1))
    (ok document-id)
  )
)

;; Update document (creates new version)
(define-public (update-document
  (document-id uint)
  (new-content-hash (buff 32))
  (change-log (string-ascii 512)))
  (let ((document (unwrap! (map-get? documents { document-id: document-id }) ERR-DOCUMENT-NOT-FOUND)))
    (asserts! (is-eq (get creator document) tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (not (get is-locked document)) ERR-DOCUMENT-LOCKED)

    (let ((new-version (+ (get version document) u1)))
      (map-set documents
        { document-id: document-id }
        (merge document {
          content-hash: new-content-hash,
          version: new-version
        })
      )
      (map-set document-versions
        { document-id: document-id, version: new-version }
        {
          content-hash: new-content-hash,
          updated-at: stacks-block-height,
          updated-by: tx-sender,
          change-log: change-log
        }
      )
    )
    (ok true)
  )
)

;; Lock document (prevents further updates)
(define-public (lock-document (document-id uint))
  (let ((document (unwrap! (map-get? documents { document-id: document-id }) ERR-DOCUMENT-NOT-FOUND)))
    (asserts! (is-eq (get creator document) tx-sender) ERR-NOT-AUTHORIZED)
    (map-set documents
      { document-id: document-id }
      (merge document { is-locked: true })
    )
    (ok true)
  )
)

;; === SIGNATURE MANAGEMENT ===

;; Sign a document
(define-public (sign-document
  (document-id uint)
  (signature-hash (buff 32))
  (metadata (string-ascii 512)))
  (let (
    (document (unwrap! (map-get? documents { document-id: document-id }) ERR-DOCUMENT-NOT-FOUND))
    (user-verification (default-to { level: VERIFICATION-NONE, verified-at: u0, verifier: tx-sender }
                                   (map-get? user-verification-levels { user: tx-sender })))
  )
    ;; Check if document exists and is not expired
    (asserts! (match (get expires-at document)
                some-expiry (> some-expiry stacks-block-height)
                true) ERR-DOCUMENT-EXPIRED)

    ;; Check if user hasn't already signed
    (asserts! (is-none (map-get? document-signatures { document-id: document-id, signer: tx-sender }))
              ERR-ALREADY-SIGNED)

    ;; Check verification level requirement
    (asserts! (>= (get level user-verification) (get required-verification-level document))
              ERR-INSUFFICIENT-VERIFICATION)

    ;; Record the signature
    (map-set document-signatures
      { document-id: document-id, signer: tx-sender }
      {
        signature-hash: signature-hash,
        signed-at: stacks-block-height,
        verification-level: (get level user-verification),
        metadata: metadata
      }
    )

    ;; Update signature count
    (map-set documents
      { document-id: document-id }
      (merge document { signature-count: (+ (get signature-count document) u1) })
    )

    (ok true)
  )
)

;; Remove signature (only by signer or document creator)
(define-public (remove-signature (document-id uint) (signer principal))
  (let (
    (document (unwrap! (map-get? documents { document-id: document-id }) ERR-DOCUMENT-NOT-FOUND))
    (signature (unwrap! (map-get? document-signatures { document-id: document-id, signer: signer })
                        ERR-INVALID-SIGNATURE))
  )
    (asserts! (or (is-eq tx-sender signer) (is-eq tx-sender (get creator document)))
              ERR-NOT-AUTHORIZED)

    (map-delete document-signatures { document-id: document-id, signer: signer })

    ;; Update signature count
    (map-set documents
      { document-id: document-id }
      (merge document { signature-count: (- (get signature-count document) u1) })
    )

    (ok true)
  )
)

;; === VERIFICATION MANAGEMENT ===

;; Set user verification level (only contract owner or authorized verifiers)
(define-public (set-user-verification
  (user principal)
  (level uint)
  (verifier principal))
  (begin
    (asserts! (or (is-eq tx-sender CONTRACT-OWNER)
                  (is-eq tx-sender verifier)) ERR-NOT-AUTHORIZED)
    (asserts! (<= level VERIFICATION-PREMIUM) ERR-NOT-AUTHORIZED)

    (map-set user-verification-levels
      { user: user }
      {
        level: level,
        verified-at: stacks-block-height,
        verifier: verifier
      }
    )
    (ok true)
  )
)

;; === READ-ONLY FUNCTIONS ===

;; Get document details
(define-read-only (get-document (document-id uint))
  (map-get? documents { document-id: document-id })
)

;; Get document version
(define-read-only (get-document-version (document-id uint) (version uint))
  (map-get? document-versions { document-id: document-id, version: version })
)

;; Get signature details
(define-read-only (get-signature (document-id uint) (signer principal))
  (map-get? document-signatures { document-id: document-id, signer: signer })
)

;; Check if user has signed document
(define-read-only (has-signed (document-id uint) (signer principal))
  (is-some (map-get? document-signatures { document-id: document-id, signer: signer }))
)

;; Get user verification level
(define-read-only (get-user-verification (user principal))
  (map-get? user-verification-levels { user: user })
)

;; Get signature count for document
(define-read-only (get-signature-count (document-id uint))
  (match (map-get? documents { document-id: document-id })
    some-doc (ok (get signature-count some-doc))
    ERR-DOCUMENT-NOT-FOUND
  )
)

;; Check if document is active (not expired)
(define-read-only (is-document-active (document-id uint))
  (match (map-get? documents { document-id: document-id })
    some-doc (match (get expires-at some-doc)
                some-expiry (> some-expiry stacks-block-height)
                true)
    false
  )
)

;; Get next document ID
(define-read-only (get-next-document-id)
  (var-get next-document-id)
)
