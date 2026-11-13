// Official Capacitor 8 imports. esbuild bundles this file into www/native.js (APK only);
// index.html loads it on the native platform before the app script runs.
import { Filesystem, Directory, Encoding } from '@capacitor/filesystem';
import { Share } from '@capacitor/share';
import { LocalNotifications } from '@capacitor/local-notifications';

window.NativePlugins = { Filesystem, Directory, Encoding, Share, LocalNotifications };
