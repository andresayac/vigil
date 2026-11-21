//! Names of the operations in History (the History page).

use vigil_i18n::{tl, tr};

const OP_LABELS: &[(&str, &str)] = &[
    ("process.terminate", tl!("End process")),
    ("process.suspend", tl!("Suspend process")),
    ("process.resume", tl!("Resume process")),
    ("service.stop", tl!("Stop service")),
    ("service.disable", tl!("Disable service")),
    ("service.delete", tl!("Delete service")),
    ("service.start", tl!("Start service")),
    ("service.restart", tl!("Restart service")),
    ("service.start_type", tl!("Change service startup type")),
    ("driver.disable", tl!("Disable driver")),
    ("task.disable", tl!("Disable task")),
    ("task.delete", tl!("Delete task")),
    ("startup.disable", tl!("Disable startup entry")),
    ("startup.enable", tl!("Enable startup entry")),
    ("registry.delete", tl!("Delete registry value")),
    ("winlogon.restore", tl!("Restore Winlogon value")),
    ("appinit.off", tl!("Turn off AppInit DLLs")),
    ("wmi.remove", tl!("Remove WMI subscription")),
    ("file.quarantine", tl!("Quarantine file")),
    ("program.uninstall", tl!("Uninstall program")),
    ("firewall.block", tl!("Block network access")),
    ("firewall.enable", tl!("Turn firewall on")),
    ("defender.scan_file", tl!("Defender file scan")),
    ("defender.full_scan", tl!("Defender full scan")),
    ("defender.update", tl!("Update Defender")),
    ("defender.realtime_on", tl!("Real-time protection on")),
    ("defender.remove_exclusion", tl!("Remove Defender exclusion")),
    ("rdp.disable", tl!("Turn Remote Desktop off")),
    ("proxy.disable", tl!("Turn proxy off")),
    ("account.disable", tl!("Disable account")),
    ("system.restore_point", tl!("Restore point")),
    ("process.priority", tl!("Change priority")),
    ("process.efficiency", tl!("Efficiency mode")),
    ("process.background", tl!("Low disk and memory priority")),
    ("process.affinity", tl!("Processor affinity")),
    ("process.trim", tl!("Trim memory")),
    ("process.run", tl!("Run new task")),
    ("memory.trim_all", tl!("Trim all programs")),
    ("memory.purge_standby", tl!("Free standby memory")),
    ("power.plan", tl!("Switch power plan")),
    ("power.ultimate", tl!("Add Ultimate Performance")),
    ("power.hibernate", tl!("Hibernation")),
    ("gpu.preference", tl!("GPU preference")),
    ("gaming.game_mode", tl!("Game Mode")),
    ("gaming.hags", tl!("GPU scheduling")),
    ("service.manual", tl!("Service on demand")),
    ("disk.optimize", tl!("Optimize drive")),
    ("disk.component_cleanup", tl!("Component store cleanup")),
    ("storage.clean", tl!("Clean up junk")),
    ("storage.empty_bin", tl!("Empty Recycle Bin")),
    ("storage.recycle", tl!("Send to Recycle Bin")),
];

/// The History name of an operation, in the current language; an unknown operation is shown by its id.
pub fn op_label(op: &str) -> String {
    OP_LABELS
        .iter()
        .find(|(id, _)| *id == op)
        .map_or_else(|| op.to_string(), |(_, label)| tr!(*label))
}

/// The History name of a known operation (`None` for an unknown one).
pub fn known_op_label(op: &str) -> Option<&'static str> {
    OP_LABELS.iter().find(|(id, _)| *id == op).map(|(_, label)| *label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        assert_eq!(op_label("file.quarantine"), "Quarantine file");
        assert_eq!(op_label("storage.recycle"), "Send to Recycle Bin");
        assert_eq!(op_label("new.op"), "new.op");
        assert_eq!(known_op_label("new.op"), None);
    }

    #[test]
    fn labels_follow_the_language() {
        assert_eq!(
            vigil_i18n::with_language("es", || op_label("service.disable")),
            "Deshabilitar servicio"
        );
        assert_eq!(
            vigil_i18n::with_language("zh", || op_label("file.quarantine")),
            "隔离文件"
        );
        assert_eq!(vigil_i18n::with_language("fr", || op_label("new.op")), "new.op");
        assert_eq!(known_op_label("file.quarantine"), Some("Quarantine file"));
    }
}
