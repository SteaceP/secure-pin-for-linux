import GObject from 'gi://GObject';
import Gio from 'gi://Gio';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import { Extension } from 'resource:///org/gnome/shell/extensions/extension.js';
import { QuickToggle, SystemIndicator } from 'resource:///org/gnome/shell/ui/quickSettings.js';

const SecurePinToggle = GObject.registerClass(
class SecurePinToggle extends QuickToggle {
    _init() {
        super._init({
            title: 'Secure PIN',
            iconName: 'io.github.securepin.Settings-symbolic',
            toggleMode: false,
        });

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
});

export default class SecurePinExtension extends Extension {
    enable() {
        this._indicator = new SystemIndicator();
        this._toggle = new SecurePinToggle();
        this._indicator.quickSettingsItems.push(this._toggle);
        Main.panel.statusArea.quickSettings.addExternalIndicator(this._indicator);
    }

    disable() {
        if (this._indicator) {
            this._indicator.quickSettingsItems.forEach(item => item.destroy());
            this._indicator.destroy();
            this._indicator = null;
        }
        this._toggle = null;
    }
}
