import { NextResponse, type NextRequest } from "next/server";
import {
  MOCK_SBT_ADDRESS,
  MOCK_SBT_CHAIN_ID,
  createPersonhoodCommitment,
  createVerificationId,
  hashStructuredFields,
  isSameWalletAddress,
  normalizeWalletAddress,
  sanitizeProof,
  validateVerificationProof,
  validateWalletAddress,
  type VerificationRecord,
  type VerificationRequestPayload,
  type VerificationResponse,
  type VerificationMethod,
} from "@/lib/utils/verification";

type VerificationRegistry = {
  byWallet: Map<string, string>;
  byPersonhood: Map<string, VerificationRecord>;
};

declare global {
  // eslint-disable-next-line no-var
  var __olympusVerificationRegistry: VerificationRegistry | undefined;
}

const registry: VerificationRegistry =
  globalThis.__olympusVerificationRegistry ?? {
    byWallet: new Map(),
    byPersonhood: new Map(),
  };

globalThis.__olympusVerificationRegistry = registry;

const allowedMethods: VerificationMethod[] = [
  "world-id",
  "gitcoin-passport",
  "social-graph",
];

export async function POST(request: NextRequest) {
  let payload: VerificationRequestPayload;
  try {
    payload = (await request.json()) as VerificationRequestPayload;
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON payload." },
      { status: 400 },
    );
  }

  const issues: string[] = [];
  if (!payload?.walletAddress || !validateWalletAddress(payload.walletAddress)) {
    issues.push("A valid wallet address is required.");
  }
  if (!payload?.method || !allowedMethods.includes(payload.method)) {
    issues.push("A supported verification method is required.");
  }
  if (!payload?.location?.locationHash || !payload?.location?.display) {
    issues.push("Location verification is required.");
  }
  if (!payload?.consent || !payload?.assertion) {
    issues.push("Humanity assertion and consent are required.");
  }

  const sanitizedProof = payload?.method
    ? sanitizeProof(payload.method, payload?.proof ?? {})
    : {};
  const proofCheck = payload?.method
    ? validateVerificationProof(payload.method, sanitizedProof)
    : { valid: false, issues: ["Proof payload missing."] };
  if (!proofCheck.valid) {
    issues.push(...proofCheck.issues);
  }

  if (issues.length > 0) {
    return NextResponse.json(
      { error: issues.join(" ") },
      { status: 400 },
    );
  }

  const walletAddress = normalizeWalletAddress(payload.walletAddress);
  const personhoodId = createPersonhoodCommitment(
    payload.method,
    sanitizedProof,
  );

  const existingPersonhood = registry.byPersonhood.get(personhoodId);
  if (
    existingPersonhood &&
    !isSameWalletAddress(existingPersonhood.walletAddress, walletAddress)
  ) {
    return NextResponse.json(
      { error: "This proof of personhood is already linked to a wallet." },
      { status: 409 },
    );
  }

  const existingWallet = registry.byWallet.get(walletAddress);
  if (existingWallet && existingWallet !== personhoodId) {
    return NextResponse.json(
      { error: "This wallet is already linked to another human proof." },
      { status: 409 },
    );
  }

  if (existingPersonhood) {
    return buildVerificationResponse(existingPersonhood, "already_verified");
  }

  const verificationId = createVerificationId(walletAddress, personhoodId);
  // Canonical seed format: label | verificationId (deterministic mock metadata).
  const tokenSeed = hashStructuredFields("sbt", verificationId);
  const txSeed = hashStructuredFields("tx", verificationId);

  const record: VerificationRecord = {
    verificationId,
    walletAddress,
    method: payload.method,
    personhoodId,
    location: payload.location,
    sbt: {
      chainId: MOCK_SBT_CHAIN_ID,
      contractAddress: MOCK_SBT_ADDRESS,
      tokenId: tokenSeed.slice(0, 16),
      txHash: `0x${txSeed.slice(0, 64)}`,
    },
    issuedAt: new Date().toISOString(),
  };

  registry.byWallet.set(walletAddress, personhoodId);
  registry.byPersonhood.set(personhoodId, record);

  return buildVerificationResponse(record, "verified");
}

export async function DELETE() {
  const response = NextResponse.json({ status: "cleared" }, { status: 200 });
  response.cookies.set({
    name: "olympus_verified",
    value: "",
    path: "/",
    expires: new Date(0),
  });
  response.cookies.set({
    name: "olympus_verification_id",
    value: "",
    path: "/",
    expires: new Date(0),
  });
  return response;
}

function buildVerificationResponse(
  record: VerificationRecord,
  status: VerificationResponse["status"],
) {
  const response = NextResponse.json({ status, record }, { status: 200 });
  response.cookies.set({
    name: "olympus_verified",
    value: "1",
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
  });
  response.cookies.set({
    name: "olympus_verification_id",
    value: record.verificationId,
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
  });
  return response;
}
