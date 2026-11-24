import GObject from 'gi://GObject';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import { Extension } from 'resource:///org/gnome/shell/extensions/extension.js';
import { QuickToggle, SystemIndicator } from 'resource:///org/gnome/shell/ui/quickSettings.js';

const DEFAULT_ICON = 'io.github.securepin.Settings-symbolic';

const SecurePinToggle = GObject.registerClass(
class SecurePinToggle extends QuickToggle {
    _init() {
        super._init({
            title: 'Secure PIN',
            subtitle: 'Checking…',
            iconName: DEFAULT_ICON,
            toggleMode: false,
        });

        this._destroyed = false;
        this._cancellable = null;

        this.connect('clicked', () => {
            try {
                let appInfo = Gio.DesktopAppInfo.new('io.github.securepin.Settings.desktop');
                if (!appInfo) {
                    appInfo = Gio.AppInfo.create_from_commandline('tpm-pin-settings', 'Secure PIN', 0);
                }
                appInfo.launch([], null);
            } catch (e) {
                console.error('Failed to launch Secure PIN Settings:', e);
            }
        });
    }

    refreshStatus() {
        if (this._destroyed)
            return;

        if (this._cancellable) {
            this._cancellable.cancel();
            this._cancellable = null;
        }

        const cancellable = new Gio.Cancellable();
        this._cancellable = cancellable;

        try {
            const proc = Gio.Subprocess.new(
                ['tpm-pin-ctl', 'status', '--json'],
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_SILENCE
            );

            proc.communicate_utf8_async(null, cancellable, (subproc, res) => {
                if (this._cancellable === cancellable)
                    this._cancellable = null;

                if (this._destroyed || cancellable.is_cancelled())
                    return;

                try {
                    const [, stdout] = subproc.communicate_utf8_finish(res);
                    if (!subproc.get_successful() || !stdout) {
                        this.iconName = DEFAULT_ICON;
                        this.subtitle = 'Unavailable';
                        return;
                    }

                    const data = JSON.parse(stdout);
                    if (!data.tpm_present) {
                        this.iconName = DEFAULT_ICON;
                        this.subtitle = 'No TPM 2.0';
                    } else if (data.is_locked_out) {
                        this.iconName = 'dialog-warning-symbolic';
                        this.subtitle = 'Locked Out';
                    } else if (data.is_enrolled && data.pam_enabled) {
                        this.iconName = DEFAULT_ICON;
                        this.subtitle = data.pcr7_bound ? 'Active (PCR 7)' : 'Active';
                    } else if (data.is_enrolled && !data.pam_enabled) {
                        this.iconName = DEFAULT_ICON;
                        this.subtitle = 'PAM Disabled';
                    } else {
                        this.iconName = DEFAULT_ICON;
                        this.subtitle = 'Not Configured';
                    }
                } catch (err) {
                    if (!err.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.CANCELLED) &&
                        !err.matches?.(GLib.SpawnError, GLib.SpawnErrorEnum.NOENT)) {
                        console.debug('Failed to parse Secure PIN status:', err);
                    }
                    if (!this._destroyed) {
                        this.iconName = DEFAULT_ICON;
                        this.subtitle = 'Unavailable';
                    }
                }
            });
        } catch (err) {
            if (this._cancellable === cancellable)
                this._cancellable = null;
            this.iconName = DEFAULT_ICON;
            this.subtitle = 'Unavailable';
        }
    }

    cleanup() {
        this._destroyed = true;
        if (this._cancellable) {
            this._cancellable.cancel();
            this._cancellable = null;
        }
    }
});

export default class SecurePinExtension extends Extension {
    enable() {
        this._indicator = new SystemIndicator();
        this._toggle = new SecurePinToggle();
        this._indicator.quickSettingsItems.push(this._toggle);
        Main.panel.statusArea.quickSettings.addExternalIndicator(this._indicator);

        this._toggle.refreshStatus();

        const menu = Main.panel.statusArea.quickSettings?.menu;
        if (menu) {
            this._menuSignalId = menu.connect('open-state-changed', (_menu, open) => {
                if (open && this._toggle)
                    this._toggle.refreshStatus();
            });
        }
    }

    disable() {
        if (this._menuSignalId) {
            Main.panel.statusArea.quickSettings?.menu?.disconnect(this._menuSignalId);
            this._menuSignalId = 0;
        }
        if (this._toggle) {
            this._toggle.cleanup();
        }
        if (this._indicator) {
            this._indicator.quickSettingsItems.forEach(item => item.destroy());
            this._indicator.destroy();
            this._indicator = null;
        }
        this._toggle = null;
    }
}
