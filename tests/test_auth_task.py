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
        auth = activities[".ConfirmationActivity"]
        self.assertEqual(auth.get(ANDROID+"exported"), "false")
        self.assertEqual(activities[".AuthActivity"].get(ANDROID+"exported"), "true")
        self.assertNotEqual(auth.get(ANDROID+"taskAffinity"),
                            activities[".AuthActivity"].get(ANDROID+"taskAffinity"))
        affinity = auth.get(ANDROID+"taskAffinity")
        self.assertEqual(affinity, "com.randiny_games.fingerprintauthenticator.authentication")
        self.assertNotEqual(affinity, activities[".MainActivity"].get(ANDROID+"taskAffinity"))
        self.assertEqual(auth.get(ANDROID+"allowTaskReparenting"), "false")
        self.assertEqual(auth.get(ANDROID+"excludeFromRecents"), "true")
        self.assertIn(auth.get(ANDROID+"launchMode"), (None, "standard"))

    def test_lan_and_adb_allocate_a_task_per_request(self):
        ui = (SOURCE / "RequestUi.java").read_text()
        desktop = (ROOT / "Desktop/main.py").read_text()
        self.assertIn(".addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_NEW_DOCUMENT)", ui)
        self.assertIn('identity = Uri.parse("pam-confirm:" + owner.token)', ui)
        self.assertIn(".setData(identity)", ui)
        self.assertIn('"shell", "am", "start", "-f", "0x18000000"', desktop)
        self.assertEqual(0x10000000 | 0x08000000, 0x18000000)

    def test_all_exit_paths_finish_only_the_authentication_instance(self):
        source = (SOURCE / "ConfirmationActivity.java").read_text()
        method = re.search(r"private void closeWindow\(\) \{(.*?)\n    \}", source, re.S).group(1)
        self.assertIn("finish();", method)
        self.assertNotIn("finishAndRemoveTask", source)
        self.assertNotIn("finishAffinity", source)
        self.assertIn("ui.removeTask(this)", method)
        self.assertIn("handler.postDelayed(this::closeWindow, 1400)", source)
        self.assertNotIn("moveTaskToBack", source)

    @unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK required")
    def test_pause_epochs_and_task_binding_never_revive_or_migrate(self):
        harness = """
package com.randiny_games.fingerprintauthenticator;
public class TaskExitCheck {
    static void check(boolean value) { if (!value) throw new AssertionError(); }
    public static void main(String[] args) {
        AttemptState state = new AttemptState();
        check(!state.canStart()); state.foreground();
        int first = state.begin(); check(state.accepts(first) && !state.canStart());
        state.background(); check(!state.accepts(first) && !state.canStart());
        state.foreground(); int next = state.begin();
        check(next != first && !state.accepts(first) && state.accepts(next));
        int retry = state.pause(); check(state.rearm(retry));
        state.background(); state.foreground(); check(!state.rearm(retry));
        int last = state.begin(); state.end();
        check(!state.accepts(last) && !state.canStart());
        state.foreground(); check(!state.canStart());
        UiTaskBinding old = new UiTaskBinding("old"), fresh = new UiTaskBinding("new");
        check(!old.bind(1, "wrong", true) && !old.bound());
        check(!old.bind(1, "old", false) && !old.bound());
        check(old.bind(1, "old", true) && old.matches(1, "old", true));
        check(!old.bind(2, "old", true)); // Notification after swipe cannot rebind.
        check(fresh.bind(2, "new", true));
        check(!old.matches(2, "new", true) && !old.matches(1, "old", false));
        check(!fresh.matches(1, "old", true));
    }
}
"""
        with tempfile.TemporaryDirectory(prefix="pam-task-exit-") as temporary:
            path = Path(temporary) / "TaskExitCheck.java"
            path.write_text(harness)
            subprocess.run(["javac", "-d", temporary, str(SOURCE / "AttemptState.java"),
                            str(SOURCE / "UiTaskBinding.java"), str(path)], check=True, capture_output=True, timeout=20)
            subprocess.run(["java", "-cp", temporary, "com.randiny_games.fingerprintauthenticator.TaskExitCheck"],
                           check=True, capture_output=True, timeout=10)

    def test_bootstrap_registers_before_handoff_and_never_signs(self):
        source = (SOURCE / "AuthActivity.java").read_text()
        self.assertLess(source.index("RequestOwner.start"), source.index("RequestUi.open"))
        self.assertNotIn("Signature", source)
        self.assertNotIn("BiometricPrompt", source)
        self.assertIn("finally { finish(); }", source)

    def test_notifications_are_direct_and_future_cleanup_is_always_queued(self):
        source = (SOURCE / "RequestUi.java").read_text()
        self.assertIn("PendingIntent.getActivity(context, 0, intent()", source)
        self.assertIn("PendingIntent.getBroadcast(context, 0, cancel", source)
        self.assertIn("whenComplete((value, error) -> handler.post(this::ended))", source)
        self.assertIn("setExcludeFromRecents(!owner.unlimited)", source)
        self.assertNotIn("RequestOwner.close", source)
        self.assertNotIn("Results.abandon", source)
        cleanup = source[source.index("private void cleanup()"):]
        self.assertLess(cleanup.index("binding.matches"), cleanup.index("finishAndRemoveTask"))
        self.assertIn("info.numActivities == 1", cleanup)
