// proof-verifier.test.ts

import { describe, it, expect, beforeEach, vi } from "vitest";
import { cvToValue, stringAsciiCV, uintCV } from "@stacks/transactions";
import { Buffer } from 'node:buffer';

const ERR_NOT_AUTHORIZED = 1000;
const ERR_INVALID_PUBLIC_INPUTS = 1002;
const ERR_CIRCUIT_NOT_FOUND = 1004;
const ERR_INVALID_CIRCUIT_ID = 1005;
const ERR_INVALID_PROOF_STRUCTURE = 1006;
const ERR_VERIFICATION_FAILED = 1007;
const ERR_INVALID_BUFFER_LENGTH = 1009;
const ERR_INVALID_LIST_LENGTH = 1010;
const ERR_GOVERNANCE_NOT_SET = 1011;
const ERR_PROOF_ALREADY_USED = 1013;
const ERR_MAX_CIRCUITS_EXCEEDED = 1017;
const ERR_INVALID_CIRCUIT_TYPE = 1018;

interface VerificationKey {
  vkAlpha: Buffer;
  vkBeta: Buffer;
  vkGamma: Buffer;
  vkDelta: Buffer;
  vkIc: Buffer[];
  circuitType: string;
  timestamp: number;
  updater: string;
}

interface CircuitMetadata {
  inputSize: number;
  outputSize: number;
  description: string;
  active: boolean;
}

interface Proof {
  a: Buffer;
  b: Buffer;
  c: Buffer;
}

type Result<T> = { ok: true; value: T } | { ok: false; value: number };

class ProofVerifierMock {
  state: {
    nextCircuitId: number;
    maxCircuits: number;
    governancePrincipal: string | null;
    verificationKeys: Map<number, VerificationKey>;
    circuitMetadata: Map<number, CircuitMetadata>;
    usedNullifiers: Map<string, boolean>;
  } = {
    nextCircuitId: 0,
    maxCircuits: 50,
    governancePrincipal: null,
    verificationKeys: new Map(),
    circuitMetadata: new Map(),
    usedNullifiers: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1GOV";
  zkLib: { verifyGroth16: ViMock; verifySnark: ViMock } = {
    verifyGroth16: vi.fn().mockReturnValue(true),
    verifySnark: vi.fn().mockReturnValue(true),
  };

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextCircuitId: 0,
      maxCircuits: 50,
      governancePrincipal: null,
      verificationKeys: new Map(),
      circuitMetadata: new Map(),
      usedNullifiers: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1GOV";
    this.zkLib.verifyGroth16.mockReturnValue(true);
    this.zkLib.verifySnark.mockReturnValue(true);
  }

  setGovernance(newGov: string): Result<boolean> {
    if (this.state.governancePrincipal !== null) return { ok: false, value: ERR_GOVERNANCE_NOT_SET };
    this.state.governancePrincipal = newGov;
    return { ok: true, value: true };
  }

  addVerificationKey(
    circuitId: number,
    vkAlpha: Buffer,
    vkBeta: Buffer,
    vkGamma: Buffer,
    vkDelta: Buffer,
    vkIc: Buffer[],
    circuitType: string,
    inputSize: number,
    outputSize: number,
    description: string
  ): Result<number> {
    if (this.state.governancePrincipal !== this.caller) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (this.state.nextCircuitId >= this.state.maxCircuits) return { ok: false, value: ERR_MAX_CIRCUITS_EXCEEDED };
    if (vkAlpha.length !== 32) return { ok: false, value: ERR_INVALID_BUFFER_LENGTH };
    if (vkBeta.length !== 64) return { ok: false, value: ERR_INVALID_BUFFER_LENGTH };
    if (vkGamma.length !== 64) return { ok: false, value: ERR_INVALID_BUFFER_LENGTH };
    if (vkDelta.length !== 64) return { ok: false, value: ERR_INVALID_BUFFER_LENGTH };
    if (vkIc.length !== 10) return { ok: false, value: ERR_INVALID_LIST_LENGTH };
    if (!["groth16", "snark"].includes(circuitType)) return { ok: false, value: ERR_INVALID_CIRCUIT_TYPE };

    this.state.verificationKeys.set(circuitId, {
      vkAlpha,
      vkBeta,
      vkGamma,
      vkDelta,
      vkIc,
      circuitType,
      timestamp: this.blockHeight,
      updater: this.caller,
    });
    this.state.circuitMetadata.set(circuitId, {
      inputSize,
      outputSize,
      description,
      active: true,
    });
    this.state.nextCircuitId = circuitId + 1;
    return { ok: true, value: circuitId };
  }

  updateVerificationKey(
    circuitId: number,
    vkAlpha: Buffer,
    vkBeta: Buffer,
    vkGamma: Buffer,
    vkDelta: Buffer,
    vkIc: Buffer[]
  ): Result<boolean> {
    const key = this.state.verificationKeys.get(circuitId);
    if (!key) return { ok: false, value: ERR_CIRCUIT_NOT_FOUND };
    if (this.state.governancePrincipal !== this.caller) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (vkAlpha.length !== 32) return { ok: false, value: ERR_INVALID_BUFFER_LENGTH };
    if (vkBeta.length !== 64) return { ok: false, value: ERR_INVALID_BUFFER_LENGTH };
    if (vkGamma.length !== 64) return { ok: false, value: ERR_INVALID_BUFFER_LENGTH };
    if (vkDelta.length !== 64) return { ok: false, value: ERR_INVALID_BUFFER_LENGTH };
    if (vkIc.length !== 10) return { ok: false, value: ERR_INVALID_LIST_LENGTH };

    this.state.verificationKeys.set(circuitId, {
      ...key,
      vkAlpha,
      vkBeta,
      vkGamma,
      vkDelta,
      vkIc,
      timestamp: this.blockHeight,
      updater: this.caller,
    });
    return { ok: true, value: true };
  }

  deactivateCircuit(circuitId: number): Result<boolean> {
    if (this.state.governancePrincipal !== this.caller) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (circuitId >= this.state.nextCircuitId) return { ok: false, value: ERR_INVALID_CIRCUIT_ID };
    const meta = this.state.circuitMetadata.get(circuitId);
    if (!meta) return { ok: false, value: ERR_CIRCUIT_NOT_FOUND };
    this.state.circuitMetadata.set(circuitId, { ...meta, active: false });
    return { ok: true, value: true };
  }

  verifyGroth16Proof(
    circuitId: number,
    proof: Proof,
    publicInputs: number[],
    nullifier: Buffer,
    signal: Buffer
  ): Result<boolean> {
    const key = this.state.verificationKeys.get(circuitId);
    const meta = this.state.circuitMetadata.get(circuitId);
    if (!key || !meta) return { ok: false, value: ERR_CIRCUIT_NOT_FOUND };
    if (!meta.active) return { ok: false, value: ERR_CIRCUIT_NOT_FOUND };
    if (key.circuitType !== "groth16") return { ok: false, value: ERR_INVALID_CIRCUIT_TYPE };
    if (proof.a.length !== 32 || proof.b.length !== 64 || proof.c.length !== 32) return { ok: false, value: ERR_INVALID_PROOF_STRUCTURE };
    if (publicInputs.length !== meta.inputSize) return { ok: false, value: ERR_INVALID_PUBLIC_INPUTS };
    if (this.state.usedNullifiers.has(nullifier.toString("hex"))) return { ok: false, value: ERR_PROOF_ALREADY_USED };
    if (!this.zkLib.verifyGroth16(proof.a, proof.b, proof.c, publicInputs, key.vkAlpha, key.vkBeta, key.vkGamma, key.vkDelta, key.vkIc)) {
      return { ok: false, value: ERR_VERIFICATION_FAILED };
    }
    this.state.usedNullifiers.set(nullifier.toString("hex"), true);
    return { ok: true, value: true };
  }

  verifySnarkProof(
    circuitId: number,
    proof: { piA: Buffer; piB: Buffer; piC: Buffer },
    publicInputs: number[],
    commitment: Buffer
  ): Result<boolean> {
    const key = this.state.verificationKeys.get(circuitId);
    const meta = this.state.circuitMetadata.get(circuitId);
    if (!key || !meta) return { ok: false, value: ERR_CIRCUIT_NOT_FOUND };
    if (!meta.active) return { ok: false, value: ERR_CIRCUIT_NOT_FOUND };
    if (key.circuitType !== "snark") return { ok: false, value: ERR_INVALID_CIRCUIT_TYPE };
    if (proof.piA.length !== 32 || proof.piB.length !== 64 || proof.piC.length !== 32) return { ok: false, value: ERR_INVALID_PROOF_STRUCTURE };
    if (publicInputs.length !== meta.inputSize) return { ok: false, value: ERR_INVALID_PUBLIC_INPUTS };
    if (commitment.length !== 32) return { ok: false, value: ERR_INVALID_BUFFER_LENGTH };
    if (!this.zkLib.verifySnark(proof.piA, proof.piB, proof.piC, publicInputs, key.vkAlpha, key.vkBeta, key.vkGamma, key.vkDelta, key.vkIc)) {
      return { ok: false, value: ERR_VERIFICATION_FAILED };
    }
    return { ok: true, value: true };
  }

  getCircuitCount(): Result<number> {
    return { ok: true, value: this.state.nextCircuitId };
  }

  isNullifierUsed(nullifier: Buffer): Result<boolean> {
    return { ok: true, value: this.state.usedNullifiers.has(nullifier.toString("hex")) };
  }
}

type ViMock = ReturnType<typeof vi.fn>;

describe("ProofVerifier", () => {
  let contract: ProofVerifierMock;

  beforeEach(() => {
    contract = new ProofVerifierMock();
    contract.reset();
  });

  it("sets governance successfully", () => {
    const result = contract.setGovernance("ST1GOV");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.governancePrincipal).toBe("ST1GOV");
  });

  it("adds verification key successfully", () => {
    contract.setGovernance("ST1GOV");
    const vkAlpha = Buffer.alloc(32);
    const vkBeta = Buffer.alloc(64);
    const vkGamma = Buffer.alloc(64);
    const vkDelta = Buffer.alloc(64);
    const vkIc = Array(10).fill(Buffer.alloc(32));
    const result = contract.addVerificationKey(0, vkAlpha, vkBeta, vkGamma, vkDelta, vkIc, "groth16", 5, 1, "Age proof");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);
    const key = contract.state.verificationKeys.get(0);
    expect(key?.circuitType).toBe("groth16");
    const meta = contract.state.circuitMetadata.get(0);
    expect(meta?.inputSize).toBe(5);
    expect(meta?.active).toBe(true);
  });

  it("rejects add key without governance", () => {
    const vkAlpha = Buffer.alloc(32);
    const vkBeta = Buffer.alloc(64);
    const vkGamma = Buffer.alloc(64);
    const vkDelta = Buffer.alloc(64);
    const vkIc = Array(10).fill(Buffer.alloc(32));
    const result = contract.addVerificationKey(0, vkAlpha, vkBeta, vkGamma, vkDelta, vkIc, "groth16", 5, 1, "Age proof");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("rejects add key with invalid type", () => {
    contract.setGovernance("ST1GOV");
    const vkAlpha = Buffer.alloc(32);
    const vkBeta = Buffer.alloc(64);
    const vkGamma = Buffer.alloc(64);
    const vkDelta = Buffer.alloc(64);
    const vkIc = Array(10).fill(Buffer.alloc(32));
    const result = contract.addVerificationKey(0, vkAlpha, vkBeta, vkGamma, vkDelta, vkIc, "invalid", 5, 1, "Age proof");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_CIRCUIT_TYPE);
  });

  it("updates verification key successfully", () => {
    contract.setGovernance("ST1GOV");
    const vkAlpha = Buffer.alloc(32);
    const vkBeta = Buffer.alloc(64);
    const vkGamma = Buffer.alloc(64);
    const vkDelta = Buffer.alloc(64);
    const vkIc = Array(10).fill(Buffer.alloc(32));
    contract.addVerificationKey(0, vkAlpha, vkBeta, vkGamma, vkDelta, vkIc, "groth16", 5, 1, "Age proof");
    const newVkAlpha = Buffer.alloc(32, 1);
    const result = contract.updateVerificationKey(0, newVkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const key = contract.state.verificationKeys.get(0);
    expect(key?.vkAlpha).toEqual(newVkAlpha);
  });

  it("deactivates circuit successfully", () => {
    contract.setGovernance("ST1GOV");
    const vkAlpha = Buffer.alloc(32);
    const vkBeta = Buffer.alloc(64);
    const vkGamma = Buffer.alloc(64);
    const vkDelta = Buffer.alloc(64);
    const vkIc = Array(10).fill(Buffer.alloc(32));
    contract.addVerificationKey(0, vkAlpha, vkBeta, vkGamma, vkDelta, vkIc, "groth16", 5, 1, "Age proof");
    const result = contract.deactivateCircuit(0);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const meta = contract.state.circuitMetadata.get(0);
    expect(meta?.active).toBe(false);
  });

  it("verifies groth16 proof successfully", () => {
    contract.setGovernance("ST1GOV");
    const vkAlpha = Buffer.alloc(32);
    const vkBeta = Buffer.alloc(64);
    const vkGamma = Buffer.alloc(64);
    const vkDelta = Buffer.alloc(64);
    const vkIc = Array(10).fill(Buffer.alloc(32));
    contract.addVerificationKey(0, vkAlpha, vkBeta, vkGamma, vkDelta, vkIc, "groth16", 5, 1, "Age proof");
    const proof = { a: Buffer.alloc(32), b: Buffer.alloc(64), c: Buffer.alloc(32) };
    const publicInputs = [1, 2, 3, 4, 5];
    const nullifier = Buffer.alloc(32);
    const signal = Buffer.alloc(32);
    const result = contract.verifyGroth16Proof(0, proof, publicInputs, nullifier, signal);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.zkLib.verifyGroth16).toHaveBeenCalled();
  });

  it("rejects groth16 verification with invalid inputs", () => {
    contract.setGovernance("ST1GOV");
    const vkAlpha = Buffer.alloc(32);
    const vkBeta = Buffer.alloc(64);
    const vkGamma = Buffer.alloc(64);
    const vkDelta = Buffer.alloc(64);
    const vkIc = Array(10).fill(Buffer.alloc(32));
    contract.addVerificationKey(0, vkAlpha, vkBeta, vkGamma, vkDelta, vkIc, "groth16", 5, 1, "Age proof");
    const proof = { a: Buffer.alloc(32), b: Buffer.alloc(64), c: Buffer.alloc(32) };
    const publicInputs = [1, 2, 3];
    const nullifier = Buffer.alloc(32);
    const signal = Buffer.alloc(32);
    const result = contract.verifyGroth16Proof(0, proof, publicInputs, nullifier, signal);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_PUBLIC_INPUTS);
  });

  it("rejects groth16 on used nullifier", () => {
    contract.setGovernance("ST1GOV");
    const vkAlpha = Buffer.alloc(32);
    const vkBeta = Buffer.alloc(64);
    const vkGamma = Buffer.alloc(64);
    const vkDelta = Buffer.alloc(64);
    const vkIc = Array(10).fill(Buffer.alloc(32));
    contract.addVerificationKey(0, vkAlpha, vkBeta, vkGamma, vkDelta, vkIc, "groth16", 5, 1, "Age proof");
    const proof = { a: Buffer.alloc(32), b: Buffer.alloc(64), c: Buffer.alloc(32) };
    const publicInputs = [1, 2, 3, 4, 5];
    const nullifier = Buffer.alloc(32);
    const signal = Buffer.alloc(32);
    contract.verifyGroth16Proof(0, proof, publicInputs, nullifier, signal);
    const result = contract.verifyGroth16Proof(0, proof, publicInputs, nullifier, signal);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_PROOF_ALREADY_USED);
  });

  it("verifies snark proof successfully", () => {
    contract.setGovernance("ST1GOV");
    const vkAlpha = Buffer.alloc(32);
    const vkBeta = Buffer.alloc(64);
    const vkGamma = Buffer.alloc(64);
    const vkDelta = Buffer.alloc(64);
    const vkIc = Array(10).fill(Buffer.alloc(32));
    contract.addVerificationKey(0, vkAlpha, vkBeta, vkGamma, vkDelta, vkIc, "snark", 5, 1, "Location proof");
    const proof = { piA: Buffer.alloc(32), piB: Buffer.alloc(64), piC: Buffer.alloc(32) };
    const publicInputs = [1, 2, 3, 4, 5];
    const commitment = Buffer.alloc(32);
    const result = contract.verifySnarkProof(0, proof, publicInputs, commitment);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.zkLib.verifySnark).toHaveBeenCalled();
  });

  it("gets circuit count correctly", () => {
    contract.setGovernance("ST1GOV");
    const vkAlpha = Buffer.alloc(32);
    const vkBeta = Buffer.alloc(64);
    const vkGamma = Buffer.alloc(64);
    const vkDelta = Buffer.alloc(64);
    const vkIc = Array(10).fill(Buffer.alloc(32));
    contract.addVerificationKey(0, vkAlpha, vkBeta, vkGamma, vkDelta, vkIc, "groth16", 5, 1, "Age proof");
    contract.addVerificationKey(1, vkAlpha, vkBeta, vkGamma, vkDelta, vkIc, "snark", 3, 2, "Location proof");
    const result = contract.getCircuitCount();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });

  it("checks nullifier used correctly", () => {
    contract.setGovernance("ST1GOV");
    const vkAlpha = Buffer.alloc(32);
    const vkBeta = Buffer.alloc(64);
    const vkGamma = Buffer.alloc(64);
    const vkDelta = Buffer.alloc(64);
    const vkIc = Array(10).fill(Buffer.alloc(32));
    contract.addVerificationKey(0, vkAlpha, vkBeta, vkGamma, vkDelta, vkIc, "groth16", 5, 1, "Age proof");
    const proof = { a: Buffer.alloc(32), b: Buffer.alloc(64), c: Buffer.alloc(32) };
    const publicInputs = [1, 2, 3, 4, 5];
    const nullifier = Buffer.alloc(32);
    const signal = Buffer.alloc(32);
    contract.verifyGroth16Proof(0, proof, publicInputs, nullifier, signal);
    const result = contract.isNullifierUsed(nullifier);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });

  it("parses clarity values", () => {
    const ctype = stringAsciiCV("groth16");
    const cid = uintCV(0);
    expect(cvToValue(ctype)).toBe("groth16");
    expect(cvToValue(cid)).toEqual(BigInt(0));
  });
});