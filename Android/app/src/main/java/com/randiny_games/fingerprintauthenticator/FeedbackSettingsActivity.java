package com.randiny_games.fingerprintauthenticator;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

public final class FeedbackSettingsActivity extends Activity {
    private CheckBox haptic, sound;
    private SuccessFeedback feedback;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        feedback = new SuccessFeedback(this);
        SharedPreferences saved = SuccessFeedback.preferences(this);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int padding = Math.round(20 * getResources().getDisplayMetrics().density);
        layout.setPadding(padding, padding, padding, padding);
        TextView description = new TextView(this);
        description.setText("Success feedback\n\n" +
                "A brief local signal after the phone creates and publishes a biometric signature. " +
                "The PC still verifies that signature before authorizing anything.\n\n" +
                "No app success signal on failure, cancellation or timeout. Android may also " +
                "provide its own biometric feedback.\n");
        layout.addView(description);
        haptic = new CheckBox(this);
        haptic.setId(201);
        haptic.setText("Short PAM vibration (independent of system touch feedback)");
        haptic.setChecked(saved.getBoolean("haptic", true));
        layout.addView(haptic);
        sound = new CheckBox(this);
        sound.setId(202);
        sound.setText("Quiet 36 ms tone (off in Silent/Vibrate/Do Not Disturb)");
        sound.setChecked(saved.getBoolean("sound", false));
        layout.addView(sound);
        TextView note = new TextView(this);
        note.setText("Sound is off by default. It uses system sound volume without changing it. " +
                "PAM vibration does not enable vibration for the rest of the interface. It respects " +
                "Silent / Do Not Disturb and notification-vibration intensity. The pulse is 32 ms " +
                "on amplitude-capable hardware; other devices use a short system tick.\n");
        layout.addView(note);
        Button save = new Button(this);
        save.setText("Save");
        save.setOnClickListener(v -> { if (save()) finish(); });
        layout.addView(save);
        Button preview = new Button(this);
        preview.setText("Save & preview feedback (not authentication)");
        preview.setOnClickListener(v -> { if (save()) feedback.play(); });
        layout.addView(preview);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(layout);
        setContentView(scroll);
    }

    private boolean save() {
        boolean saved = SuccessFeedback.preferences(this).edit()
                .putBoolean("haptic", haptic.isChecked()).putBoolean("sound", sound.isChecked()).commit();
        if (!saved) Toast.makeText(this, "Could not save feedback settings.", Toast.LENGTH_LONG).show();
        return saved;
    }

    @Override protected void onPause() {
        if (feedback != null) feedback.close();
        super.onPause();
    }
}
