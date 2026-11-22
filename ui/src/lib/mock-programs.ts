// Fictitious installed programs for previewing the Installed programs page in a browser.
// Nothing here describes a real computer.
import type { InstalledProgram, StartupSignature } from "./types";

const UNINSTALL = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
const UNINSTALL_32 = "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
const USER_UNINSTALL = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

/** The local day `days` ago, YYYY-MM-DD. */
function daysAgo(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() - days);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function program(name: string, extra: Partial<InstalledProgram>): InstalledProgram {
  const base: InstalledProgram = {
    id: `${UNINSTALL}\\${name}`, keyName: name, name, publisher: "", version: "1.0", installed: daysAgo(200),
    installedEstimated: false, size: 0, location: "", locationExists: false, locationEmpty: false, uninstall: "",
    quietUninstall: "", uninstaller: "", uninstallerExists: true, uninstallerHost: false, icon: "", executable: "",
    msi: false, productCode: "", msiKnown: false, noRemove: false, scope: "machine", sid: "", account: "",
    leftover: false, remote: false, microsoft: false,
  };
  return { ...base, ...extra };
}

const MB = 1024 * 1024;

export function programsList(): InstalledProgram[] {
  return [
    program("Contoso Notes", {
      publisher: "Contoso Ltd.", version: "4.2.1", installed: daysAgo(120), size: 248 * MB,
      location: "C:\\Program Files\\Contoso\\Notes", locationExists: true,
      uninstall: "\"C:\\Program Files\\Contoso\\Notes\\uninstall.exe\" /remove",
      quietUninstall: "\"C:\\Program Files\\Contoso\\Notes\\uninstall.exe\" /remove /quiet",
      uninstaller: "C:\\Program Files\\Contoso\\Notes\\uninstall.exe",
      icon: "C:\\Program Files\\Contoso\\Notes\\notes.exe", executable: "C:\\Program Files\\Contoso\\Notes\\notes.exe",
    }),
    program("Contoso Remote Assist", {
      id: `${UNINSTALL_32}\\ContosoRemoteAssist`, keyName: "ContosoRemoteAssist", scope: "machine32",
      publisher: "Contoso Ltd.", version: "9.0.4", installed: daysAgo(40), size: 12 * MB, remote: true,
      location: "C:\\Program Files (x86)\\Contoso Remote Assist", locationExists: true,
      uninstall: "\"C:\\Program Files (x86)\\Contoso Remote Assist\\assist.exe\" --uninstall",
      uninstaller: "C:\\Program Files (x86)\\Contoso Remote Assist\\assist.exe",
      icon: "C:\\Program Files (x86)\\Contoso Remote Assist\\assist.exe",
      executable: "C:\\Program Files (x86)\\Contoso Remote Assist\\assist.exe",
    }),
    program("Fabrikam Viewer", {
      id: `${USER_UNINSTALL}\\Fabrikam Viewer_is1`, keyName: "Fabrikam Viewer_is1", scope: "user",
      publisher: "Fabrikam, Inc.", version: "2.0", installed: daysAgo(400), size: 31 * MB, leftover: true,
      location: "C:\\Users\\jdoe\\AppData\\Local\\Programs\\Fabrikam Viewer",
      uninstall: "\"C:\\Users\\jdoe\\AppData\\Local\\Programs\\Fabrikam Viewer\\unins000.exe\"",
      uninstaller: "C:\\Users\\jdoe\\AppData\\Local\\Programs\\Fabrikam Viewer\\unins000.exe", uninstallerExists: false,
    }),
    program("Northwind Agent", {
      id: `${UNINSTALL_32}\\{3F2C8A10-5B7E-4C1D-9E6F-0A1B2C3D4E5F}`, keyName: "{3F2C8A10-5B7E-4C1D-9E6F-0A1B2C3D4E5F}",
      scope: "machine32", publisher: "Northwind Traders", version: "1.4.0.7", installed: daysAgo(2), size: 64 * MB,
      msi: true, msiKnown: true, productCode: "{3F2C8A10-5B7E-4C1D-9E6F-0A1B2C3D4E5F}",
      uninstall: "MsiExec.exe /X{3F2C8A10-5B7E-4C1D-9E6F-0A1B2C3D4E5F}",
      uninstaller: "C:\\Windows\\System32\\msiexec.exe", uninstallerHost: true,
      location: "C:\\Program Files (x86)\\Northwind\\Agent", locationExists: true,
      icon: "C:\\Program Files (x86)\\Northwind\\Agent\\agent.exe", executable: "C:\\Program Files (x86)\\Northwind\\Agent\\agent.exe",
    }),
    program("Woodgrove Tools", {
      id: `${USER_UNINSTALL}\\WoodgroveTools`, keyName: "WoodgroveTools", scope: "user", publisher: "", version: "0.9.3",
      installed: daysAgo(5), installedEstimated: true,
      location: "C:\\Users\\jdoe\\AppData\\Local\\Woodgrove", locationExists: true,
      uninstall: "C:\\Users\\jdoe\\AppData\\Local\\Woodgrove\\Uninstall.exe",
      uninstaller: "C:\\Users\\jdoe\\AppData\\Local\\Woodgrove\\Uninstall.exe",
      icon: "C:\\Users\\jdoe\\AppData\\Local\\Woodgrove\\tools.exe", executable: "C:\\Users\\jdoe\\AppData\\Local\\Woodgrove\\tools.exe",
    }),
    program("Microsoft Visual C++ 2015-2022 Redistributable (x64)", {
      id: `${UNINSTALL}\\{0A7E4F2B-9C3D-4E5F-8A1B-2C3D4E5F6A7B}`, keyName: "{0A7E4F2B-9C3D-4E5F-8A1B-2C3D4E5F6A7B}",
      publisher: "Microsoft Corporation", version: "14.40.33810.0", installed: daysAgo(90), size: 20 * MB,
      microsoft: true, msi: true, msiKnown: true, productCode: "{0A7E4F2B-9C3D-4E5F-8A1B-2C3D4E5F6A7B}",
      uninstall: "MsiExec.exe /X{0A7E4F2B-9C3D-4E5F-8A1B-2C3D4E5F6A7B}",
      uninstaller: "C:\\Windows\\System32\\msiexec.exe", uninstallerHost: true,
    }),
    program("Litware Backup", {
      publisher: "Litware, Inc.", version: "7.1", installed: daysAgo(300), size: 410 * MB, noRemove: true,
      location: "C:\\Program Files\\Litware\\Backup", locationExists: true,
      uninstall: "\"C:\\Program Files\\Litware\\Backup\\setup.exe\" /uninstall",
      uninstaller: "C:\\Program Files\\Litware\\Backup\\setup.exe",
      icon: "C:\\Program Files\\Litware\\Backup\\backup.exe", executable: "C:\\Program Files\\Litware\\Backup\\backup.exe",
    }),
    program("Adatum Media Player", {
      publisher: "Adatum Corporation", version: "12.0.2", installed: daysAgo(15), size: 96 * MB,
      location: "C:\\Program Files\\Adatum\\Media Player", locationExists: true,
      uninstall: "\"C:\\Program Files\\Adatum\\Media Player\\uninst.exe\"",
      uninstaller: "C:\\Program Files\\Adatum\\Media Player\\uninst.exe",
      icon: "C:\\Program Files\\Adatum\\Media Player\\player.exe", executable: "C:\\Program Files\\Adatum\\Media Player\\player.exe",
    }),
    program("Tailspin Launcher", {
      id: "HKU\\S-1-5-21-1111111111-2222222222-3333333333-1002\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TailspinLauncher",
      keyName: "TailspinLauncher", scope: "user", sid: "S-1-5-21-1111111111-2222222222-3333333333-1002",
      account: "PC-VICTIM\\jdoe", publisher: "Tailspin Toys", version: "3.3", installed: daysAgo(60), size: 180 * MB,
      location: "C:\\Users\\jdoe\\AppData\\Local\\Tailspin", locationExists: true,
      uninstall: "\"C:\\Users\\jdoe\\AppData\\Local\\Tailspin\\Update.exe\" --uninstall",
      uninstaller: "C:\\Users\\jdoe\\AppData\\Local\\Tailspin\\Update.exe",
    }),
    program("Proseware Sync", {
      id: `${UNINSTALL}\\Proseware Sync`, publisher: "Proseware, Inc.", version: "5.8.0", installed: daysAgo(700),
      location: "C:\\Program Files\\Proseware\\Sync", locationExists: true, locationEmpty: true,
      uninstall: "\"C:\\Program Files\\Proseware\\Sync\\Uninstall Proseware Sync.exe\"",
      uninstaller: "C:\\Program Files\\Proseware\\Sync\\Uninstall Proseware Sync.exe", uninstallerExists: false, leftover: true,
    }),
  ].sort((a, b) => a.name.localeCompare(b.name));
}

const UNSIGNED = ["agent.exe", "tools.exe", "uninstall.exe"];

export function programSignatures(paths: string[]): Record<string, StartupSignature> {
  const out: Record<string, StartupSignature> = {};
  for (const path of paths) {
    const file = (path.split("\\").pop() ?? "").toLowerCase();
    const folder = path.toLowerCase();
    if (UNSIGNED.includes(file) && (folder.includes("northwind") || folder.includes("woodgrove"))) {
      out[path] = { status: "unsigned", signer: "" };
    } else {
      const vendor = programsList().find((p) => p.executable === path || p.uninstaller === path)?.publisher ?? "";
      out[path] = { status: "valid", signer: vendor };
    }
  }
  return out;
}
