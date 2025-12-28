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

async function reportSuspicious() {
  const button = document.getElementById("reportButton") as HTMLButtonElement | null;
  if (button) button.disabled = true;
  try {
    setStatus("Collecting message...");
    const payload = await buildPayload();
    setStatus("Sending report...");
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    const authHeader = buildBasicAuth(config.apiUsername, config.apiPassword);
    if (authHeader) headers.Authorization = authHeader;
    const response = await fetch(`${config.backendUrl}/api/report`, {
      method: "POST",
      headers,
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `Request failed: ${response.status}`);
    }
    setStatus("Report submitted.");
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Failed to send report", true);
  } finally {
    if (button) button.disabled = false;
  }
}

async function buildPayload() {
  const item = Office.context.mailbox.item;
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

function getBody(item: Office.Item, coercionType: Office.CoercionType) {
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

function getHeaders(item: Office.Item) {
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

function buildBasicAuth(username?: string, password?: string) {
  if (!username || !password) return undefined;
  const token = `${username}:${password}`;
  return `Basic ${btoa(token)}`;
}
