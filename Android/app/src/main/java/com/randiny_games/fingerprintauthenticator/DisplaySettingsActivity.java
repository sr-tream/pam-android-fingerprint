package com.randiny_games.fingerprintauthenticator;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.text.InputType;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

public final class DisplaySettingsActivity extends Activity {
    private CheckBox custom;
    private EditText left, top, width, height;
    private Spinner orientation;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        DisplaySettings saved = DisplaySettings.load(this);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int padding = Math.round(20 * getResources().getDisplayMetrics().density);
        layout.setPadding(padding, padding, padding, padding);
        TextView description = new TextView(this);
        description.setText("Confirmation display\n\nChoose a usable part of a damaged screen. " +
                "Coordinates are percentages of the display AFTER rotation, measured from " +
                "its top-left corner. This affects the app panel, not Android's biometric dialog.\n");
        layout.addView(description);
        custom = new CheckBox(this);
        custom.setId(106);
        custom.setText("Use a custom screen area");
        custom.setChecked(saved.custom);
        layout.addView(custom);
        left = number(layout, "Left (%)", saved.area.left, 101);
        top = number(layout, "Top (%)", saved.area.top, 102);
        width = number(layout, "Width (%)", saved.area.width, 103);
        height = number(layout, "Height (%)", saved.area.height, 104);
        TextView label = new TextView(this);
        label.setText("Forced orientation (confirmation and preview only)");
        layout.addView(label);
        orientation = new Spinner(this);
        orientation.setId(105);
        ArrayAdapter<String> choices = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item, new String[]{
                "Follow system", "Portrait", "Landscape", "Reverse portrait", "Reverse landscape"});
        choices.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        orientation.setAdapter(choices);
        orientation.setSelection(saved.orientation);
        layout.addView(orientation);
        Button save = new Button(this);
        save.setText("Save");
        save.setOnClickListener(v -> { if (save()) finish(); });
        layout.addView(save);
        Button preview = new Button(this);
        preview.setText("Save & preview (10 seconds)");
        preview.setOnClickListener(v -> {
            if (save()) startActivity(new Intent(this, DisplayPreviewActivity.class));
        });
        layout.addView(preview);
        Button reset = new Button(this);
        reset.setText("Reset display settings");
        reset.setOnClickListener(v -> {
            custom.setChecked(false);
            left.setText("0");
            top.setText("0");
            width.setText("100");
            height.setText("100");
            orientation.setSelection(0);
        });
        layout.addView(reset);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(layout);
        setContentView(scroll);
    }

    private EditText number(LinearLayout layout, String label, int value, int id) {
        TextView text = new TextView(this);
        text.setText(label);
        layout.addView(text);
        EditText input = new EditText(this);
        input.setId(id);
        input.setInputType(InputType.TYPE_CLASS_NUMBER);
        input.setSingleLine(true);
        input.setText(String.valueOf(value));
        input.setContentDescription(label);
        layout.addView(input);
        return input;
    }

    private boolean save() {
        try {
            DisplayArea area = new DisplayArea(
                    Integer.parseInt(left.getText().toString().trim()),
                    Integer.parseInt(top.getText().toString().trim()),
                    Integer.parseInt(width.getText().toString().trim()),
                    Integer.parseInt(height.getText().toString().trim()));
            new DisplaySettings(custom.isChecked(), area, orientation.getSelectedItemPosition()).save(this);
            Toast.makeText(this, "Display settings saved", Toast.LENGTH_SHORT).show();
            return true;
        } catch (IllegalArgumentException | IllegalStateException error) {
            Toast.makeText(this, error.getMessage(), Toast.LENGTH_LONG).show();
            return false;
        }
    }
}
