/**
 * Approver keys and signed approvals (mirror of python/gleipnir/src/gleipnir/approvals.py).
 *
 * The agent's process should never hold an approver's key: the approver signs the action digest
 * elsewhere (`gleipnir approve sign`, or a passkey on site/approve/index.html) and the vendor records
 * the signature with `rec.approve(tool, args, { signature })`.
 */

import { actionDigest, approvalChallenge, approvalMessage as messageForDigest } from "@getgleipnir/verify";
import { EcdsaP256Signer, Ed25519Signer } from "./keys.js";
import { toJsonable } from "./util.js";

/** The action digest an approval of `tool(args)` on `system` commits to (`args` as the action records them). */
export function approvalDigest(tool: string, args: Record<string, unknown>, system: string): string {
  return actionDigest(tool, system, toJsonable({ ...args }));
}

/** The exact bytes an approver signs: `"gleipnir/approval/v1\n" + action_digest`. */
export function approvalMessage(tool: string, args: Record<string, unknown>, system: string): Uint8Array {
  return messageForDigest(approvalDigest(tool, args, system));
}

/** An approver's own signing key (Ed25519 or ECDSA P-256). Keep it on the approver's device. */
export class ApproverKey {
  readonly approverId: string;
  readonly #signer: Ed25519Signer | EcdsaP256Signer;

  constructor(signer: Ed25519Signer | EcdsaP256Signer, approverId: string) {
    if (typeof approverId !== "string" || !approverId) throw new Error("approverId must be a non-empty string");
    this.#signer = signer;
    this.approverId = approverId;
  }

  static generate(approverId: string, kind: "ed25519" | "ecdsa-p256" = "ed25519"): ApproverKey {
    return new ApproverKey(kind === "ed25519" ? Ed25519Signer.generate() : EcdsaP256Signer.generate(), approverId);
  }

  /** Load a PKCS#8 PEM (Ed25519 or P-256), as `gleipnir approve keygen` writes it. */
  static fromPem(pem: string, approverId: string): ApproverKey {
    let signer: Ed25519Signer | EcdsaP256Signer;
    try {
      signer = Ed25519Signer.fromPem(pem);
    } catch {
      signer = EcdsaP256Signer.fromPem(pem);
    }
    return new ApproverKey(signer, approverId);
  }

  get publicKey(): string {
    return this.#signer.publicKey;
  }

  privatePem(): string {
    return this.#signer.privatePem();
  }

  /** Sign an approval of the action with this digest; returns `review.signature`. */
  sign(actionDigest: string): Record<string, unknown> {
    approvalChallenge(actionDigest); // validates the digest's form
    return { type: "key", approver_id: this.approverId, public_key: this.publicKey, sig: this.#signer.sign(messageForDigest(actionDigest)) };
  }

  /** This approver's entry for the buyer's approver registry (`gleipnir-verify --approvers`). */
  registryEntry(name: string, roles?: string[]): Record<string, unknown> {
    const entry: Record<string, unknown> = { id: this.approverId, name, public_key: this.publicKey };
    if (roles && roles.length) entry["roles"] = [...roles];
    return entry;
  }
}
