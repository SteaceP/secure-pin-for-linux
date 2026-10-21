import GLib from 'gi://GLib';
import Gio from 'gi://Gio';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import { Extension } from 'resource:///org/gnome/shell/extensions/extension.js';
import { QuickMenuToggle, SystemIndicator } from 'resource:///org/gnome/shell/ui/quickSettings.js';

class SecurePinToggle extends QuickMenuToggle {
    constructor() {
        super({
            title: 'Secure PIN',
            iconName: 'dialog-password-symbolic',
            toggleMode: false,
        });

        this.connect('clicked', () => {
            try {
                Gio.AppInfo.create_from_commandline('tpm-pin-settings', 'Secure PIN', 0).launch([], null);
            } catch (e) {
                logError(e, 'Failed to launch tpm-pin-settings');
            }
        });
    }
}

export default class SecurePinExtension extends Extension {
    enable() {
        this._indicator = new SystemIndicator();
        this._toggle = new SecurePinToggle();
        this._indicator.quickSettingsItems.push(this._toggle);
        Main.panel.statusArea.quickSettings.addExternalIndicator(this._indicator);
    }

    disable() {
        this._indicator?.destroy();
        this._indicator = null;
        this._toggle = null;
    }
}
