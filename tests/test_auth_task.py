from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "Android/app/src/main/java/com/randiny_games/fingerprintauthenticator"
ANDROID = "{http://schemas.android.com/apk/res/android}"


class AuthenticationTaskTests(unittest.TestCase):
    def test_authentication_has_separate_non_reparenting_task_affinity(self):
        application = ET.parse(ROOT / "Android/app/src/main/AndroidManifest.xml").getroot().find("application")
        activities = {node.get(ANDROID+"name"): node for node in application.findall("activity")}
        auth = activities[".AuthActivity"]
        affinity = auth.get(ANDROID+"taskAffinity")
        self.assertEqual(affinity, "com.randiny_games.fingerprintauthenticator.authentication")
        self.assertNotEqual(affinity, activities[".MainActivity"].get(ANDROID+"taskAffinity"))
        self.assertEqual(auth.get(ANDROID+"allowTaskReparenting"), "false")
        self.assertEqual(auth.get(ANDROID+"excludeFromRecents"), "true")
        self.assertIn(auth.get(ANDROID+"launchMode"), (None, "standard"))

    def test_lan_and_adb_allocate_a_task_per_request(self):
        network = (SOURCE / "NetworkService.java").read_text()
        desktop = (ROOT / "Desktop/main.py").read_text()
        self.assertIn(".addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_MULTIPLE_TASK)", network)
        self.assertIn('"shell", "am", "start", "-f", "0x18000000"', desktop)
        self.assertEqual(0x10000000 | 0x08000000, 0x18000000)

    def test_all_exit_paths_finish_only_the_authentication_instance(self):
        source = (SOURCE / "AuthActivity.java").read_text()
        method = re.search(r"private void closeWindow\(\) \{(.*?)\n    \}", source, re.S).group(1)
        self.assertIn("finish();", method)
        self.assertNotIn("finishAndRemoveTask", source)
        self.assertNotIn("finishAffinity", source)
        self.assertNotIn("finish();", source.replace(method, ""))
        self.assertIn("handler.postDelayed(this::closeWindow, 1400)", source)
        self.assertNotIn("moveTaskToBack", source)

    @unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK required")
    def test_old_feedback_cannot_remove_new_legacy_request_in_same_task(self):
        source = (SOURCE / "AuthActivity.java").read_text()
        method = re.search(r"private void closeWindow\(\) \{(.*?)\n    \}", source, re.S).group(1)
        harness = """
import java.util.ArrayList;
public class TaskExitCheck {
    static class Window {
        final ArrayList<Window> task;
        Window(ArrayList<Window> task) { this.task = task; task.add(this); }
        void finish() { task.remove(this); }
        boolean isTaskRoot() { return task.indexOf(this) == 0; }
        void finishAndRemoveTask() { task.clear(); }
        void closeWindow() { BODY }
    }
    public static void main(String[] args) {
        ArrayList<Window> settings = new ArrayList<>(), authentication = new ArrayList<>();
        Window main = new Window(settings);
        Window old = new Window(authentication), next = new Window(authentication);
        // Legacy launch without MULTIPLE_TASK reuses the authentication task.
        if (!old.isTaskRoot()) throw new AssertionError();
        old.closeWindow();
        if (authentication.size() != 1 || authentication.get(0) != next)
            throw new AssertionError("Old feedback removed new request");
        if (settings.size() != 1 || settings.get(0) != main)
            throw new AssertionError("Settings task modified");
        next.closeWindow();
        if (!authentication.isEmpty()) throw new AssertionError("Authentication not finished");
    }
}
""".replace("BODY", method)
        with tempfile.TemporaryDirectory(prefix="pam-task-exit-") as temporary:
            path = Path(temporary) / "TaskExitCheck.java"
            path.write_text(harness)
            subprocess.run(["javac", str(path)], check=True, capture_output=True, timeout=20)
            subprocess.run(["java", "-cp", temporary, "TaskExitCheck"],
                           check=True, capture_output=True, timeout=10)
