import { parentPort } from "node:worker_threads";
import { detectCryptographicKeys, detectDeepKeySchedules } from "./detectors/keys.js";
import { detectConfigurationSecrets } from "./detectors/config-secrets.js";
import { detectProviderCredentials } from "./detectors/providers.js";
import { detectStructuredArtifacts } from "./detectors/structured.js";
import { detectWalletSecrets } from "./detectors/wallets.js";
import type { DetectorRuntimeState } from "./detectors/types.js";
import { MAX_CANDIDATE_BYTES_PER_DETECTOR_JOB, MAX_STREAMING_CANDIDATE_BYTES_PER_DETECTOR_JOB } from "./limits.js";
import { STREAMING_DETECTOR_NAMES } from "./worker-protocol.js";
import type { DetectorBatchResult, DetectorJobRequest, DetectorJobResponse } from "./worker-protocol.js";

if (parentPort === null) throw new Error("detector worker must run inside a worker thread");
const port = parentPort;

function invoke(
  name: string,
  detector: typeof detectCryptographicKeys,
  request: DetectorJobRequest,
  data: Buffer,
  wholeFile = request.context.wholeFile,
): DetectorBatchResult {
  try {
    const runtimeState: DetectorRuntimeState = {
      candidateLimitReached: false,
      validationLimitReached: false,
      structuralValidations: 0,
      candidateBytes: 0,
      candidateByteLimit: name === "structured-artifacts"
        ? MAX_CANDIDATE_BYTES_PER_DETECTOR_JOB
        : MAX_STREAMING_CANDIDATE_BYTES_PER_DETECTOR_JOB,
    };
    const candidates = detector(data, { ...request.context, wholeFile, runtimeState });
    const limits = [
      ...(runtimeState.candidateLimitReached ? ["candidate"] : []),
      ...(runtimeState.validationLimitReached ? ["structural-validation"] : []),
    ];
    return {
      detector: name,
      candidates,
      ...(limits.length > 0
        ? { error: `detector ${limits.join(" and ")} limit reached; the bounded window may contain additional matches` }
        : {}),
    };
  } catch (error) {
    return { detector: name, candidates: [], error: error instanceof Error ? error.message : String(error) };
  }
}

port.on("message", (request: DetectorJobRequest) => {
  const response: DetectorJobResponse = { id: request.id, results: [] };
  try {
    const data = Buffer.from(request.data.buffer, request.data.byteOffset, request.data.byteLength);
    if (request.kind === "streaming" || request.kind === "small-file") {
      const detectors = {
        "cryptographic-keys": detectCryptographicKeys,
        "configuration-secrets": detectConfigurationSecrets,
        "wallet-secrets": detectWalletSecrets,
        "provider-credentials": detectProviderCredentials,
      } as const;
      response.results = STREAMING_DETECTOR_NAMES.map((name) => invoke(name, detectors[name], request, data));
      if (request.kind === "small-file") {
        response.results.push(invoke("structured-artifacts", detectStructuredArtifacts, request, data, true));
      }
    } else if (request.kind === "deep-key-schedules") {
      response.results = [invoke("deep-key-schedules", detectDeepKeySchedules, request, data)];
    } else if (request.kind === "structured") {
      response.results = [invoke("structured-artifacts", detectStructuredArtifacts, request, data)];
    } else {
      const detector = {
        "cryptographic-keys": detectCryptographicKeys,
        "configuration-secrets": detectConfigurationSecrets,
        "wallet-secrets": detectWalletSecrets,
        "provider-credentials": detectProviderCredentials,
      }[request.kind];
      response.results = [invoke(request.kind, detector, request, data)];
    }
  } catch (error) {
    response.fatalError = error instanceof Error ? error.message : String(error);
  }
  port.postMessage(response);
});
