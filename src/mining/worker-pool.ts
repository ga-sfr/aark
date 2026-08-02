import { Worker } from "node:worker_threads";
import type { DetectionContext } from "./detectors/types.js";
import { isSafeDetectorIdentifier, MAX_CANDIDATES_PER_DETECTOR_JOB } from "./limits.js";
import type { DetectorBatchResult, DetectorJobKind, DetectorJobRequest, DetectorJobResponse } from "./worker-protocol.js";

const MAX_ACTIVE_DETECTOR_BYTES = 256 * 1024 * 1024;
const MAX_QUEUED_DETECTOR_JOBS = 64;

interface QueuedJob {
  id: number;
  kind: DetectorJobKind;
  data: Buffer;
  context: DetectionContext;
  resolve: (value: DetectorBatchResult[]) => void;
  reject: (error: Error) => void;
}

interface WorkerSlot {
  worker: Worker;
  active?: QueuedJob;
}

export class DetectorWorkerPool {
  private readonly slots: WorkerSlot[] = [];
  private readonly queue: QueuedJob[] = [];
  private nextId = 1;
  private failure?: Error;
  private closed = false;
  private closing?: Promise<void>;

  public constructor(public readonly size: number) {
    if (!Number.isSafeInteger(size) || size < 1 || size > 4) throw new Error("worker count must be an integer from 1 through 4");
    try {
      for (let index = 0; index < size; index += 1) this.slots.push(this.createSlot());
    } catch (error) {
      this.closed = true;
      void Promise.all(this.slots.map(async (slot) => slot.worker.terminate())).catch(() => undefined);
      throw error;
    }
  }

  private createSlot(): WorkerSlot {
    const worker = new Worker(new URL("./detector-worker.js", import.meta.url), {
      // Host launchers and test runners commonly inject process flags that Node
      // rejects for Worker instances. The detector needs no process flags.
      execArgv: [],
    });
    const slot: WorkerSlot = { worker };
    worker.on("message", (value: unknown) => {
      if (this.closed || this.failure !== undefined) return;
      const active = slot.active;
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        this.fail(new Error("detector worker returned an invalid response"));
        return;
      }
      const response = value as Partial<DetectorJobResponse>;
      if (
        active === undefined
        || response.id !== active.id
        || !Array.isArray(response.results)
        || (response.fatalError === undefined ? response.results.length !== 1 : response.results.length !== 0)
        || (response.fatalError !== undefined && typeof response.fatalError !== "string")
        || (typeof response.fatalError === "string" && response.fatalError.length > 4_096)
        || response.results.some((batch) => (
          typeof batch !== "object"
          || batch === null
          || !isSafeDetectorIdentifier(batch.detector)
          || !Array.isArray(batch.candidates)
          || batch.candidates.length > MAX_CANDIDATES_PER_DETECTOR_JOB
          || (batch.error !== undefined && typeof batch.error !== "string")
          || (typeof batch.error === "string" && batch.error.length > 4_096)
        ))
      ) {
        this.fail(new Error("detector worker returned an unexpected job identifier"));
        return;
      }
      delete slot.active;
      if (response.fatalError === undefined) active.resolve(response.results as DetectorBatchResult[]);
      else active.reject(new Error(`detector worker failed: ${response.fatalError}`));
      this.dispatch();
    });
    worker.on("error", (error) => this.fail(new Error("detector worker crashed", { cause: error })));
    worker.on("messageerror", (error) => this.fail(new Error("detector worker response could not be decoded", { cause: error })));
    worker.on("exit", (code) => {
      if (!this.closed) this.fail(new Error(`detector worker exited unexpectedly with code ${code}`));
    });
    return slot;
  }

  private fail(error: Error): void {
    if (this.failure !== undefined || this.closed) return;
    this.failure = error;
    this.closed = true;
    for (const slot of this.slots) {
      slot.active?.reject(error);
      delete slot.active;
    }
    for (const job of this.queue.splice(0)) job.reject(error);
    this.closing = Promise.all(this.slots.map(async (slot) => slot.worker.terminate())).then(() => undefined);
    void this.closing.catch(() => undefined);
  }

  private dispatch(): void {
    if (this.closed || this.failure !== undefined) return;
    let activeBytes = this.slots.reduce((sum, slot) => sum + (slot.active?.data.byteLength ?? 0), 0);
    for (const slot of this.slots) {
      if (slot.active !== undefined) continue;
      const job = this.queue[0];
      if (job === undefined) break;
      if (activeBytes > 0 && activeBytes + job.data.byteLength > MAX_ACTIVE_DETECTOR_BYTES) break;
      this.queue.shift();
      slot.active = job;
      activeBytes += job.data.byteLength;
      try {
        const payload = new Uint8Array(job.data.byteLength);
        payload.set(job.data);
        const request: DetectorJobRequest = {
          id: job.id,
          kind: job.kind,
          data: payload,
          context: { ...job.context },
        };
        slot.worker.postMessage(request, [payload.buffer]);
      } catch (error) {
        this.fail(new Error("detector work could not be sent to a worker", { cause: error }));
        return;
      }
    }
  }

  public run(kind: DetectorJobKind, data: Buffer, context: DetectionContext): Promise<DetectorBatchResult[]> {
    if (this.failure !== undefined) return Promise.reject(this.failure);
    if (this.closed) return Promise.reject(new Error("detector worker pool is closed"));
    if (data.byteLength > MAX_ACTIVE_DETECTOR_BYTES) {
      return Promise.reject(new Error("detector job exceeds the bounded worker input size"));
    }
    if (this.queue.length >= MAX_QUEUED_DETECTOR_JOBS) {
      return Promise.reject(new Error("detector worker queue reached its bounded job limit"));
    }
    return new Promise<DetectorBatchResult[]>((resolve, reject) => {
      this.queue.push({ id: this.nextId++, kind, data, context: { ...context }, resolve, reject });
      this.dispatch();
    });
  }

  public close(terminate = false): Promise<void> {
    if (this.closing !== undefined) return this.closing;
    if (this.closed) return Promise.resolve();
    this.closed = true;
    const error = new Error(terminate ? "detector work was cancelled" : "detector worker pool closed");
    for (const slot of this.slots) {
      slot.active?.reject(error);
      delete slot.active;
    }
    for (const job of this.queue.splice(0)) job.reject(error);
    this.closing = Promise.all(this.slots.map(async (slot) => slot.worker.terminate())).then(() => undefined);
    return this.closing;
  }
}
