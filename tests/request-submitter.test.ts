// tests/request-submitter.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { Cl, uintCV, buffCV, stringUtf8CV, someCV, noneCV, Response } from "@stacks/transactions";

interface Request {
  "requester-commitment": Uint8Array;
  "nullifier-hash": Uint8Array;
  "proof-hash": Uint8Array;
  "request-type": string;
  "metadata-hash": Uint8Array;
  status: string;
  "created-at": bigint;
  "expires-at": bigint;
  "verifier-notes": string | null;
}

const ERR_NOT_AUTHORIZED = 100;
const ERR_PROOF_VERIFIER_NOT_SET = 101;
const ERR_IDENTITY_MANAGER_NOT_SET = 102;
const ERR_INVALID_PROOF = 103;
const ERR_REPLAY_ATTACK = 104;
const ERR_REQUEST_NOT_FOUND = 105;
const ERR_INVALID_STATUS_TRANSITION = 106;
const ERR_REQUEST_EXPIRED = 107;
const ERR_INVALID_METADATA = 108;
const ERR_MAX_REQUESTS_REACHED = 109;
const ERR_INVALID_NULLIFIER = 110;
const ERR_VERIFICATION_FAILED = 111;
const ERR_INVALID_REQUEST_TYPE = 112;
const ERR_REQUEST_ALREADY_PROCESSED = 113;
const ERR_INVALID_REQUEST_ID = 114;
const ERR_PROOF_VERIFIER_CALL_FAILED = 115;
const ERR_REQUEST_NOT_EXPIRED = 116;

const MAX_REQUESTS = 10000;
const REQUEST_EXPIRY_BLOCKS = 52560;

class RequestSubmitterMock {
  private state = {
    nextRequestId: 0,
    proofVerifierContract: null as string | null,
    identityManagerContract: null as string | null,
    admin: "ST1ADMIN",
    requests: new Map<number, Request>(),
    nullifierUsed: new Map<string, boolean>(),
    requestByCommitment: new Map<string, number>(),
  };

  public blockHeight = 1000;
  public txSender = "ST1USER";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextRequestId: 0,
      proofVerifierContract: null,
      identityManagerContract: null,
      admin: "ST1ADMIN",
      requests: new Map(),
      nullifierUsed: new Map(),
      requestByCommitment: new Map(),
    };
    this.blockHeight = 1000;
    this.txSender = "ST1USER";
  }

  setProofVerifier(verifier: string): Response<boolean, number> {
    if (this.txSender !== this.state.admin) return { success: false, result: uintCV(ERR_NOT_AUTHORIZED) };
    if (this.state.proofVerifierContract !== null) return { success: false, result: uintCV(ERR_PROOF_VERIFIER_NOT_SET) };
    this.state.proofVerifierContract = verifier;
    return { success: true, result: Cl.bool(true) };
  }

  setIdentityManager(manager: string): Response<boolean, number> {
    if (this.txSender !== this.state.admin) return { success: false, result: uintCV(ERR_NOT_AUTHORIZED) };
    if (this.state.identityManagerContract !== null) return { success: false, result: uintCV(ERR_IDENTITY_MANAGER_NOT_SET) };
    this.state.identityManagerContract = manager;
    return { success: true, result: Cl.bool(true) };
  }

  submitRequest(
    commitment: Uint8Array,
    nullifierHash: Uint8Array,
    proofHash: Uint8Array,
    requestType: string,
    metadataHash: Uint8Array,
    publicSignals: bigint[]
  ): Response<number, number> {
    if (this.state.nextRequestId >= MAX_REQUESTS) return { success: false, result: uintCV(ERR_MAX_REQUESTS_REACHED) };
    if (commitment.length !== 32) return { success: false, result: uintCV(ERR_INVALID_METADATA) };
    if (nullifierHash.length !== 32) return { success: false, result: uintCV(ERR_INVALID_NULLIFIER) };
    if (proofHash.length !== 32) return { success: false, result: uintCV(ERR_INVALID_PROOF) };
    if (metadataHash.length !== 32) return { success: false, result: uintCV(ERR_INVALID_METADATA) };
    if (!["aid", "grant", "report", "access"].includes(requestType)) return { success: false, result: uintCV(ERR_INVALID_REQUEST_TYPE) };

    const commitmentHex = Buffer.from(commitment).toString("hex");
    const nullifierHex = Buffer.from(nullifierHash).toString("hex");

    if (this.state.nullifierUsed.get(nullifierHex)) return { success: false, result: uintCV(ERR_REPLAY_ATTACK) };
    if (this.state.requestByCommitment.has(commitmentHex)) return { success: false, result: uintCV(ERR_REPLAY_ATTACK) };
    if (!this.state.proofVerifierContract) return { success: false, result: uintCV(ERR_PROOF_VERIFIER_NOT_SET) };

    const requestId = this.state.nextRequestId;
    const expiresAt = this.blockHeight + REQUEST_EXPIRY_BLOCKS;

    this.state.requests.set(requestId, {
      "requester-commitment": commitment,
      "nullifier-hash": nullifierHash,
      "proof-hash": proofHash,
      "request-type": requestType,
      "metadata-hash": metadataHash,
      status: "pending",
      "created-at": BigInt(this.blockHeight),
      "expires-at": BigInt(expiresAt),
      "verifier-notes": null,
    });

    this.state.nullifierUsed.set(nullifierHex, true);
    this.state.requestByCommitment.set(commitmentHex, requestId);
    this.state.nextRequestId += 1;

    return { success: true, result: uintCV(requestId) };
  }

  getRequest(requestId: number): Request | null {
    return this.state.requests.get(requestId) ?? null;
  }

  updateRequestStatus(requestId: number, newStatus: string, notes?: string): Response<boolean, number> {
    const request = this.state.requests.get(requestId);
    if (!request) return { success: false, result: uintCV(ERR_REQUEST_NOT_FOUND) };
    if (this.txSender !== this.state.admin) return { success: false, result: uintCV(ERR_NOT_AUTHORIZED) };

    if (request["expires-at"] <= BigInt(this.blockHeight)) return { success: false, result: uintCV(ERR_REQUEST_EXPIRED) };

    const currentStatus = request.status;
    const validTransition =
      (currentStatus === "pending" && (newStatus === "approved" || newStatus === "rejected")) ||
      (currentStatus === "approved" && newStatus === "fulfilled") ||
      (currentStatus === "rejected" && newStatus === "closed");

    if (!validTransition) return { success: false, result: uintCV(ERR_INVALID_STATUS_TRANSITION) };

    this.state.requests.set(requestId, {
      ...request,
      status: newStatus,
      "verifier-notes": notes ?? request["verifier-notes"],
    });

    return { success: true, result: Cl.bool(true) };
  }

  withdrawRequest(commitment: Uint8Array): Response<boolean, number> {
    const commitmentHex = Buffer.from(commitment).toString("hex");
    const requestId = this.state.requestByCommitment.get(commitmentHex);
    if (requestId === undefined) return { success: false, result: uintCV(ERR_REQUEST_NOT_FOUND) };

    const request = this.state.requests.get(requestId)!;
    if (request.status !== "pending") return { success: false, result: uintCV(ERR_INVALID_STATUS_TRANSITION) };
    if (request["expires-at"] <= BigInt(this.blockHeight)) return { success: false, result: uintCV(ERR_REQUEST_EXPIRED) };

    this.state.requests.delete(requestId);
    this.state.requestByCommitment.delete(commitmentHex);
    this.state.nullifierUsed.delete(Buffer.from(request["nullifier-hash"]).toString("hex"));

    return { success: true, result: Cl.bool(true) };
  }

  adminWithdrawStuckRequest(requestId: number): Response<boolean, number> {
    if (this.txSender !== this.state.admin) return { success: false, result: uintCV(ERR_NOT_AUTHORIZED) };
    const request = this.state.requests.get(requestId);
    if (!request) return { success: false, result: uintCV(ERR_REQUEST_NOT_FOUND) };
    if (request["expires-at"] > BigInt(this.blockHeight)) return { success: false, result: uintCV(ERR_REQUEST_NOT_EXPIRED) };

    const commitmentHex = Buffer.from(request["requester-commitment"]).toString("hex");
    this.state.requests.delete(requestId);
    this.state.requestByCommitment.delete(commitmentHex);
    this.state.nullifierUsed.delete(Buffer.from(request["nullifier-hash"]).toString("hex"));

    return { success: true, result: Cl.bool(true) };
  }

  transferAdmin(newAdmin: string): Response<boolean, number> {
    if (this.txSender !== this.state.admin) return { success: false, result: uintCV(ERR_NOT_AUTHORIZED) };
    this.state.admin = newAdmin;
    return { success: true, result: Cl.bool(true) };
  }

  getNextRequestId(): Response<number, never> {
    return { success: true, result: uintCV(this.state.nextRequestId) };
  }
}

describe("request-submitter.clar", () => {
  let mock: RequestSubmitterMock;
  let commitment: Uint8Array;
  let nullifierHash: Uint8Array;
  let proofHash: Uint8Array;
  let metadataHash: Uint8Array;
  let publicSignals: bigint[];

  beforeEach(() => {
    mock = new RequestSubmitterMock();
    mock.reset();
    commitment = Buffer.alloc(32, 1);
    nullifierHash = Buffer.alloc(32, 2);
    proofHash = Buffer.alloc(32, 3);
    metadataHash = Buffer.alloc(32, 4);
    publicSignals = [BigInt(1), BigInt(2), BigInt(3)];
    mock.txSender = "ST1ADMIN";
    mock.setProofVerifier("ST2VERIFIER");
  });

  it("rejects setting proof verifier twice", () => {
    mock.setProofVerifier("ST2VERIFIER");
    const result = mock.setProofVerifier("ST3VERIFIER");
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_PROOF_VERIFIER_NOT_SET));
  });

  it("rejects non-admin setting proof verifier", () => {
    mock.txSender = "ST1HACKER";
    const result = mock.setProofVerifier("ST2VERIFIER");
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_NOT_AUTHORIZED));
  });

  it("submits aid request successfully", () => {
    mock.txSender = "ST1USER";
    const result = mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    expect(result.success).toBe(true);
    expect(result.result.value).toBe(BigInt(0));

    const request = mock.getRequest(0);
    expect(request).not.toBeNull();
    expect(request!.status).toBe("pending");
    expect(request!["request-type"]).toBe("aid");
  });

  it("submits grant request successfully", () => {
    mock.txSender = "ST1USER";
    const result = mock.submitRequest(commitment, nullifierHash, proofHash, "grant", metadataHash, publicSignals);
    expect(result.success).toBe(true);
    expect(result.result.value).toBe(BigInt(0));
  });

  it("submits report request successfully", () => {
    mock.txSender = "ST1USER";
    const result = mock.submitRequest(commitment, nullifierHash, proofHash, "report", metadataHash, publicSignals);
    expect(result.success).toBe(true);
  });

  it("submits access request successfully", () => {
    mock.txSender = "ST1USER";
    const result = mock.submitRequest(commitment, nullifierHash, proofHash, "access", metadataHash, publicSignals);
    expect(result.success).toBe(true);
  });

  it("rejects invalid request type", () => {
    mock.txSender = "ST1USER";
    const result = mock.submitRequest(commitment, nullifierHash, proofHash, "invalid", metadataHash, publicSignals);
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_INVALID_REQUEST_TYPE));
  });

  it("rejects replay attack via nullifier", () => {
    mock.txSender = "ST1USER";
    mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    const result = mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_REPLAY_ATTACK));
  });

  it("rejects replay attack via commitment", () => {
    mock.txSender = "ST1USER";
    mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    const newNullifier = Buffer.alloc(32, 5);
    const result = mock.submitRequest(commitment, newNullifier, proofHash, "aid", metadataHash, publicSignals);
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_REPLAY_ATTACK));
  });

  it("rejects submission without proof verifier", () => {
    mock = new RequestSubmitterMock();
    mock.txSender = "ST1USER";
    const result = mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_PROOF_VERIFIER_NOT_SET));
  });

  it("rejects max requests exceeded", () => {
    mock.state.nextRequestId = MAX_REQUESTS;
    mock.txSender = "ST1USER";
    const result = mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_MAX_REQUESTS_REACHED));
  });

  it("rejects invalid commitment length", () => {
    mock.txSender = "ST1USER";
    const badCommitment = Buffer.alloc(31);
    const result = mock.submitRequest(badCommitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_INVALID_METADATA));
  });

  it("rejects invalid nullifier length", () => {
    mock.txSender = "ST1USER";
    const badNullifier = Buffer.alloc(31);
    const result = mock.submitRequest(commitment, badNullifier, proofHash, "aid", metadataHash, publicSignals);
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_INVALID_NULLIFIER));
  });

  it("rejects invalid proof hash length", () => {
    mock.txSender = "ST1USER";
    const badProof = Buffer.alloc(31);
    const result = mock.submitRequest(commitment, nullifierHash, badProof, "aid", metadataHash, publicSignals);
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_INVALID_PROOF));
  });

  it("rejects invalid metadata hash length", () => {
    mock.txSender = "ST1USER";
    const badMetadata = Buffer.alloc(31);
    const result = mock.submitRequest(commitment, nullifierHash, proofHash, "aid", badMetadata, publicSignals);
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_INVALID_METADATA));
  });

  it("updates request status from pending to approved", () => {
    mock.txSender = "ST1USER";
    mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    mock.txSender = "ST1ADMIN";
    const result = mock.updateRequestStatus(0, "approved", "Verified eligibility");
    expect(result.success).toBe(true);
    const request = mock.getRequest(0);
    expect(request!.status).toBe("approved");
    expect(request!["verifier-notes"]).toBe("Verified eligibility");
  });

  it("updates request status from approved to fulfilled", () => {
    mock.txSender = "ST1USER";
    mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    mock.txSender = "ST1ADMIN";
    mock.updateRequestStatus(0, "approved");
    const result = mock.updateRequestStatus(0, "fulfilled");
    expect(result.success).toBe(true);
    expect(mock.getRequest(0)!.status).toBe("fulfilled");
  });

  it("rejects invalid status transition", () => {
    mock.txSender = "ST1USER";
    mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    mock.txSender = "ST1ADMIN";
    const result = mock.updateRequestStatus(0, "fulfilled");
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_INVALID_STATUS_TRANSITION));
  });

  it("rejects non-admin status update", () => {
    mock.txSender = "ST1USER";
    mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    mock.txSender = "ST1HACKER";
    const result = mock.updateRequestStatus(0, "approved");
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_NOT_AUTHORIZED));
  });

  it("rejects status update on expired request", () => {
    mock.txSender = "ST1USER";
    mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    mock.blockHeight += REQUEST_EXPIRY_BLOCKS + 1;
    mock.txSender = "ST1ADMIN";
    const result = mock.updateRequestStatus(0, "approved");
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_REQUEST_EXPIRED));
  });

  it("allows user to withdraw pending request", () => {
    mock.txSender = "ST1USER";
    mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    const result = mock.withdrawRequest(commitment);
    expect(result.success).toBe(true);
    expect(mock.getRequest(0)).toBeNull();
  });

  it("rejects withdraw of non-pending request", () => {
    mock.txSender = "ST1USER";
    mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    mock.txSender = "ST1ADMIN";
    mock.updateRequestStatus(0, "approved");
    mock.txSender = "ST1USER";
    const result = mock.withdrawRequest(commitment);
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_INVALID_STATUS_TRANSITION));
  });

  it("admin cleans expired request", () => {
    mock.txSender = "ST1USER";
    mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    mock.blockHeight += REQUEST_EXPIRY_BLOCKS + 1;
    mock.txSender = "ST1ADMIN";
    const result = mock.adminWithdrawStuckRequest(0);
    expect(result.success).toBe(true);
    expect(mock.getRequest(0)).toBeNull();
  });

  it("rejects admin clean of non-expired request", () => {
    mock.txSender = "ST1USER";
    mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    mock.txSender = "ST1ADMIN";
    const result = mock.adminWithdrawStuckRequest(0);
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_REQUEST_NOT_EXPIRED));
  });

  it("rejects non-admin transfer", () => {
    mock.txSender = "ST1HACKER";
    const result = mock.transferAdmin("ST2NEWADMIN");
    expect(result.success).toBe(false);
    expect(result.result.value).toBe(BigInt(ERR_NOT_AUTHORIZED));
  });

  it("gets next request ID correctly", () => {
    const result = mock.getNextRequestId();
    expect(result.success).toBe(true);
    expect(result.result.value).toBe(BigInt(0));
  });

  it("increments request ID after submission", () => {
    mock.txSender = "ST1USER";
    mock.submitRequest(commitment, nullifierHash, proofHash, "aid", metadataHash, publicSignals);
    const result = mock.getNextRequestId();
    expect(result.result.value).toBe(BigInt(1));
  });
});