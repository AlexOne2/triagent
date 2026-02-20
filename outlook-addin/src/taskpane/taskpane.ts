import "./taskpane.css";
import config from "../../config.json";

Office.onReady(() => {
  const button = document.getElementById("reportButton") as HTMLButtonElement | null;
  if (button) {
    button.onclick = () => reportSuspicious();
  }
});

const statusEl = () => document.getElementById("status") as HTMLParagraphElement | null;

function setStatus(message: string, isError = false) {
  const el = statusEl();
  if (!el) return;
  el.textContent = message;
  el.style.color = isError ? "#b42318" : "#334155";
}

type UploadFormat = "msg" | "eml";

class UnsupportedRawUploadError extends Error {}

async function reportSuspicious() {
  const button = document.getElementById("reportButton") as HTMLButtonElement | null;
  if (button) button.disabled = true;
  try {
    const item = Office.context.mailbox.item as Office.MessageRead | undefined;
    if (!item) {
      throw new Error("No message is available.");
    }

    setStatus("Collecting message...");
    const rawUpload = await trySendRawMessage(item);
    if (!rawUpload) {
      setStatus("Raw file upload unavailable, sending normalized payload...");
      const payload = await buildPayload(item);
      await sendJsonReport(payload);
    }
    setStatus("Report submitted.");
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Failed to send report", true);
  } finally {
    if (button) button.disabled = false;
  }
}

function authHeaders(json = false): Record<string, string> {
  const headers: Record<string, string> = {};
  if (json) {
    headers["Content-Type"] = "application/json";
  }
  if (config.apiKey) {
    headers["X-API-Key"] = config.apiKey;
  }
  return headers;
}

async function sendJsonReport(payload: Record<string, unknown>) {
  setStatus("Sending normalized report...");
  const response = await fetch(`${config.backendUrl}/api/report`, {
    method: "POST",
    headers: authHeaders(true),
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
}

async function trySendRawMessage(item: Office.MessageRead): Promise<boolean> {
  let officeFile: Office.File | null = null;
  try {
    officeFile = await getAsFile(item);
    const bytes = await readOfficeFile(officeFile);
    if (bytes.length === 0) {
      throw new Error("Raw message file is empty.");
    }
    const format = detectUploadFormat(bytes);
    await sendRawReport(bytes, format);
    return true;
  } catch (error) {
    if (error instanceof UnsupportedRawUploadError) {
      return false;
    }
    if (!officeFile) {
      return false;
    }
    throw error;
  } finally {
    if (officeFile) {
      await closeOfficeFile(officeFile);
    }
  }
}

function getAsFile(item: Office.MessageRead): Promise<Office.File> {
  return new Promise((resolve, reject) => {
    const fileCapable = item as Office.MessageRead & {
      getAsFileAsync?: (callback: (result: Office.AsyncResult<Office.File>) => void) => void;
    };
    if (typeof fileCapable.getAsFileAsync !== "function") {
      reject(new UnsupportedRawUploadError("Raw file upload is not supported in this Outlook client."));
      return;
    }
    fileCapable.getAsFileAsync((result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value);
        return;
      }
      const errorMessage = result.error?.message || "Failed to read raw message file.";
      const lowered = errorMessage.toLowerCase();
      if (lowered.includes("not supported") || lowered.includes("unsupported")) {
        reject(new UnsupportedRawUploadError(errorMessage));
        return;
      }
      reject(new Error(errorMessage));
    });
  });
}

function getFileSlice(file: Office.File, index: number): Promise<Office.Slice> {
  return new Promise((resolve, reject) => {
    file.getSliceAsync(index, (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value);
      } else {
        reject(new Error(result.error?.message || "Failed to read message slice."));
      }
    });
  });
}

function decodeBase64(value: string): Uint8Array | null {
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

function sliceDataToBytes(data: unknown): Uint8Array {
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (Array.isArray(data)) {
    return Uint8Array.from(data as number[]);
  }
  if (typeof data === "string") {
    const maybeBase64 = decodeBase64(data);
    if (maybeBase64) {
      return maybeBase64;
    }
    return new TextEncoder().encode(data);
  }
  return new Uint8Array(0);
}

async function readOfficeFile(file: Office.File): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for (let index = 0; index < file.sliceCount; index += 1) {
    const slice = await getFileSlice(file, index);
    chunks.push(sliceDataToBytes(slice.data));
  }
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const merged = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return merged;
}

function closeOfficeFile(file: Office.File): Promise<void> {
  return new Promise((resolve) => {
    try {
      file.closeAsync(() => resolve());
    } catch {
      resolve();
    }
  });
}

function detectUploadFormat(bytes: Uint8Array): UploadFormat {
  const msgMagic = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
  const isMsg = bytes.length >= msgMagic.length && msgMagic.every((part, idx) => bytes[idx] === part);
  return isMsg ? "msg" : "eml";
}

async function sendRawReport(bytes: Uint8Array, format: UploadFormat) {
  const endpoint = format === "msg" ? "/api/report-msg" : "/api/report-eml";
  const filename = `reported-email-${Date.now()}.${format}`;
  const mimeType = format === "msg" ? "application/vnd.ms-outlook" : "message/rfc822";
  const form = new FormData();
  form.append("file", new Blob([bytes], { type: mimeType }), filename);

  setStatus(`Sending raw ${format.toUpperCase()} message...`);
  const response = await fetch(`${config.backendUrl}${endpoint}`, {
      method: "POST",
      headers: authHeaders(false),
      body: form
    });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed: ${response.status}`);
  }
}

async function buildPayload(item: Office.MessageRead) {
  const bodyText = await getBody(item, Office.CoercionType.Text);
  const bodyHtml = await getBody(item, Office.CoercionType.Html);
  const headers = await getHeaders(item);
  const userEmail = Office.context.mailbox.userProfile.emailAddress;

  const toAddrs = (item.to || []).map((entry) => entry.emailAddress);
  const ccAddrs = (item.cc || []).map((entry) => entry.emailAddress);

  const messageId = (item as any).internetMessageId || item.itemId;
  const fromAddr = (item.from && item.from.emailAddress) || "";
  const fromDisplayName = (item.from && item.from.displayName) || undefined;
  const received = (item as any).dateTimeReceived || (item as any).dateTimeCreated;

  return {
    message_id: messageId,
    subject: item.subject,
    from_addr: fromAddr,
    to_addrs: toAddrs,
    cc_addrs: ccAddrs,
    date: received ? new Date(received).toISOString() : undefined,
    body_text: bodyText,
    body_html: bodyHtml,
    headers_json: headers ? { raw: headers } : undefined,
    reporter_hash: await hashReporter(userEmail, config.reporterSalt),
    mailbox_domain: emailDomain(userEmail),
    from_display_name: fromDisplayName
  };
}

function getBody(item: Office.MessageRead, coercionType: Office.CoercionType) {
  return new Promise<string | undefined>((resolve, reject) => {
    item.body.getAsync(coercionType, (result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value as string);
      } else {
        reject(result.error?.message || "Failed to read body");
      }
    });
  });
}

function getHeaders(item: Office.MessageRead) {
  return new Promise<string | undefined>((resolve) => {
    if (!item.getAllInternetHeadersAsync) {
      resolve(undefined);
      return;
    }
    item.getAllInternetHeadersAsync((result) => {
      if (result.status === Office.AsyncResultStatus.Succeeded) {
        resolve(result.value as string);
      } else {
        resolve(undefined);
      }
    });
  });
}

async function hashReporter(email: string, salt: string) {
  if (!email) return undefined;
  const payload = `${salt}:${email.toLowerCase()}`;
  const encoder = new TextEncoder();
  const data = encoder.encode(payload);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function emailDomain(email: string) {
  if (!email || !email.includes("@")) return undefined;
  return email.split("@")[1].toLowerCase();
}
