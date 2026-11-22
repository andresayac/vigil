// Fictitious Microsoft Defender state for previewing the Protection page in a browser.
// Nothing here describes a real computer; the threat names are made up.
import type { Protection } from "./types";

const HOUR = 3_600_000;

export function protectionState(): Protection {
  const now = Date.now();
  return {
    available: true, problem: "", serviceEnabled: true, antivirusEnabled: true, mode: "normal",
    switches: [
      { key: "realtime", state: "on" }, { key: "behavior", state: "on" }, { key: "tamper", state: "on" },
      { key: "cloud", state: "on" }, { key: "samples", state: "off" }, { key: "pua", state: "audit" },
      { key: "network", state: "off" }, { key: "cfa", state: "off" },
    ],
    signatureVersion: "1.421.300.0", signatureUpdatedMs: now - 5 * HOUR, signatureAgeDays: 0, signatureOutOfDate: false,
    engineVersion: "1.1.24090.11", platformVersion: "4.18.24090.11",
    quickScan: { startMs: now - 26 * HOUR, endMs: now - 26 * HOUR + 4 * 60_000, ageDays: 1 },
    fullScan: { startMs: 0, endMs: 0, ageDays: null },
    fullScanRequired: false, runningScan: null, tamperSource: "UI",
    otherAntivirus: [], defenderRegistered: true,
    threats: [
      {
        id: "2147812345", name: "Trojan:Win32/Fakeloader.A!ml", severity: "severe", category: "trojan",
        resources: ["C:\\Users\\jdoe\\AppData\\Local\\Temp\\upd4te\\loader.exe"], active: true, executed: false,
        status: "failed", actionSuccess: false, detectedMs: now - 2 * HOUR, changedMs: now - 2 * HOUR,
        process: "C:\\Windows\\explorer.exe", detections: 1,
      },
      {
        id: "2147735503", name: "PUA:Win32/ExampleBundler", severity: "low", category: "pua",
        resources: ["C:\\Users\\jdoe\\Downloads\\free-converter-setup.exe"], active: false, executed: false,
        status: "quarantined", actionSuccess: true, detectedMs: now - 9 * 24 * HOUR, changedMs: now - 9 * 24 * HOUR,
        process: "Unknown", detections: 2,
      },
      {
        id: "2147766001", name: "HackTool:Win32/ExampleKeygen", severity: "high", category: "tool",
        resources: ["C:\\Users\\jdoe\\Downloads\\tools.zip", "C:\\Users\\jdoe\\Downloads\\tools\\keygen.exe"],
        active: false, executed: false, status: "removed", actionSuccess: true, detectedMs: now - 30 * 24 * HOUR,
        changedMs: now - 30 * 24 * HOUR, process: "C:\\Program Files\\7-Zip\\7zFM.exe", detections: 1,
      },
    ],
    exclusions: [
      { kind: "path", value: "C:\\Users\\jdoe\\Downloads", flags: ["writable"] },
      { kind: "path", value: "D:\\Games\\Library", flags: [] },
      { kind: "process", value: "node.exe", flags: ["anyFolder"] },
      { kind: "extension", value: ".log", flags: [] },
    ],
    exclusionsHidden: false,
    scan: null,
  };
}
