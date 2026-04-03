import { FlaggedArtifact, Report } from "./api";

function domainFromAddress(value?: string | null): string | null {
  if (!value) return null;
  const at = value.indexOf("@");
  if (at === -1 || at === value.length - 1) return null;
  return value.slice(at + 1).toLowerCase();
}

export function domainFromUrl(value: string): string | null {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function artifactKey(artifact: Pick<FlaggedArtifact, "kind" | "value">): string {
  return `${artifact.kind}::${artifact.value}`;
}

export function buildReportArtifacts(report: Report): FlaggedArtifact[] {
  const items: FlaggedArtifact[] = [];
  const authSummary = report.auth_summary;
  const push = (artifact: FlaggedArtifact) => {
    if (!items.some((item) => item.kind === artifact.kind && item.value === artifact.value)) {
      items.push(artifact);
    }
  };

  if (report.from_addr) {
    push({
      kind: "FROM_ADDR",
      value: report.from_addr,
      label: `From email address - ${report.from_addr}`,
    });
    const fromDomain = domainFromAddress(report.from_addr);
    if (fromDomain) {
      push({
        kind: "FROM_DOMAIN",
        value: fromDomain,
        label: `From domain - ${fromDomain}`,
      });
    }
  }

  for (const replyTo of report.reply_to || []) {
    push({
      kind: "REPLY_TO",
      value: replyTo,
      label: `Reply-To - ${replyTo}`,
    });
  }

  if (report.return_path) {
    push({
      kind: "RETURN_PATH",
      value: report.return_path,
      label: `Return-Path email address - ${report.return_path}`,
    });
    const returnPathDomain = domainFromAddress(report.return_path);
    if (returnPathDomain) {
      push({
        kind: "RETURN_PATH_DOMAIN",
        value: returnPathDomain,
        label: `Return-Path domain - ${returnPathDomain}`,
      });
    }
  }

  if (report.originating_ip) {
    push({
      kind: "ORIGINATING_IP",
      value: report.originating_ip,
      label: `Originating IP - ${report.originating_ip}${report.originating_rdns ? ` (${report.originating_rdns})` : ""}`,
    });
  }

  if (authSummary?.spf.originating_ip) {
    push({
      kind: "ORIGINATING_IP",
      value: authSummary.spf.originating_ip,
      label: `Originating IP - ${authSummary.spf.originating_ip}${
        authSummary.spf.originating_rdns ? ` (${authSummary.spf.originating_rdns})` : ""
      }`,
    });
  }

  if (authSummary?.spf.return_path_domain) {
    push({
      kind: "RETURN_PATH_DOMAIN",
      value: authSummary.spf.return_path_domain.toLowerCase(),
      label: `Return-Path domain - ${authSummary.spf.return_path_domain.toLowerCase()}`,
    });
  }

  if (authSummary?.dmarc.header_from) {
    push({
      kind: "FROM_DOMAIN",
      value: authSummary.dmarc.header_from.toLowerCase(),
      label: `From domain - ${authSummary.dmarc.header_from.toLowerCase()}`,
    });
  }

  for (const url of report.urls_json || []) {
    push({
      kind: "URL",
      value: url,
      label: `Message URL - ${url}`,
    });
    const urlDomain = domainFromUrl(url);
    if (urlDomain) {
      push({
        kind: "URL_DOMAIN",
        value: urlDomain,
        label: `Message URL domain - ${urlDomain}`,
      });
    }
  }

  return items;
}
