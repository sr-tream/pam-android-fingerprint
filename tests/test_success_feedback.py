from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "Android/app/src/main/java/com/randiny_games/fingerprintauthenticator"


class FeedbackIntegrationTests(unittest.TestCase):
    def test_feedback_follows_only_accepted_successful_publication(self):
        source = (SOURCE / "ConfirmationActivity.java").read_text()
        self.assertEqual(source.count("feedback.play()"), 1)
        complete = source[source.index("private void complete("):source.index("@Override protected void onDestroy")]
        self.assertLess(complete.index("if (completed) return;"), complete.index("Results.complete"))
        self.assertLess(complete.index("Results.complete"), complete.index("feedback.play()"))
        self.assertIn('if (published && !response.has("error")) feedback.play();', complete)
        self.assertIn("if (feedback != null) feedback.close();", source[source.index("onDestroy()"):])
        self.assertLess(source.index("signature.sign()"), source.index("complete(response)"))

    def test_only_normal_vibration_permission_and_private_settings(self):
        manifest = ET.parse(ROOT / "Android/app/src/main/AndroidManifest.xml").getroot()
        name = "{http://schemas.android.com/apk/res/android}name"
        permissions = {node.get(name) for node in manifest.findall("uses-permission")}
        self.assertIn("android.permission.VIBRATE", permissions)
        self.assertNotIn("android.permission.ACCESS_NOTIFICATION_POLICY", permissions)
        self.assertNotIn("android.permission.MODIFY_AUDIO_SETTINGS", permissions)
        settings = next(node for node in manifest.find("application").findall("activity")
                        if node.get(name) == ".FeedbackSettingsActivity")
        self.assertEqual(settings.get("{http://schemas.android.com/apk/res/android}exported"), "false")
        text = (SOURCE / "FeedbackSettingsActivity.java").read_text()
        self.assertIn("not authentication", text)
        self.assertIn('saved.getBoolean("sound", false)', text)
        self.assertIn('saved.getBoolean("haptic", true)', text)
        for forbidden in ("setStreamVolume", "adjustVolume", "requestAudioFocus", "FLAG_AUDIBILITY_ENFORCED",
                          "FLAG_IGNORE_GLOBAL_SETTING", "FLAG_IGNORE_VIEW_SETTING",
                          "FLAG_BYPASS_INTERRUPTION_POLICY", "performHapticFeedback", ".cancel(",
                          "Settings.System.put", "Settings.Secure.put"):
            self.assertNotIn(forbidden, (SOURCE / "SuccessFeedback.java").read_text())

    @unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK required")
    def test_tone_and_feedback_lifecycle_with_android_api_doubles(self):
        # Run the real implementation against small deterministic API doubles:
        # no phone, audio device, permissions or authentication are used.
        stubs = {
            "android/content/SharedPreferences.java": """
package android.content;
public interface SharedPreferences { boolean getBoolean(String key, boolean fallback); }
""",
            "android/content/Context.java": """
package android.content;
public class Context {
 public static final int MODE_PRIVATE=0;
 public boolean haptic=true,sound=false,badPrefs=false;
 public android.media.AudioManager audio=new android.media.AudioManager();
 public android.app.NotificationManager notifications=new android.app.NotificationManager();
 public android.os.Vibrator vibrator=new android.os.Vibrator();
 public android.os.VibratorManager manager=new android.os.VibratorManager(vibrator);
 public boolean missingManager,missingVibrator;
 public SharedPreferences getSharedPreferences(String name,int mode) {
  return (key,fallback)->{if(badPrefs)throw new IllegalStateException();return key.equals("haptic")?haptic:sound;};
 }
 public <T>T getSystemService(Class<T> kind) {
  Object value;
  if(kind==android.media.AudioManager.class)value=audio;
  else if(kind==android.app.NotificationManager.class)value=notifications;
  else if(kind==android.os.VibratorManager.class)value=missingManager?null:manager;
  else value=missingVibrator?null:vibrator;
  return kind.cast(value);
 }
}
""",
            "android/app/Activity.java": """
package android.app;
public class Activity extends android.content.Context {}
""",
            "android/app/NotificationManager.java": """
package android.app;
public class NotificationManager {
 public static final int INTERRUPTION_FILTER_ALL=1;
 public int filter=1; public boolean denied=false;
 public int getCurrentInterruptionFilter(){if(denied)throw new SecurityException();return filter;}
}
""",
            "android/os/Looper.java": """
package android.os;
public class Looper { public static Looper getMainLooper(){return new Looper();} }
""",
            "android/os/Build.java": """
package android.os;
public class Build { public static class VERSION { public static int SDK_INT=34; } }
""",
            "android/os/VibrationEffect.java": """
package android.os;
public class VibrationEffect {
 public static final int EFFECT_TICK=2;
 public long duration; public int amplitude,tick=-1;
 public static VibrationEffect createOneShot(long duration,int amplitude){
  VibrationEffect value=new VibrationEffect();value.duration=duration;value.amplitude=amplitude;return value;
 }
 public static VibrationEffect createPredefined(int tick){
  VibrationEffect value=new VibrationEffect();value.tick=tick;return value;
 }
}
""",
            "android/os/VibrationAttributes.java": """
package android.os;
public class VibrationAttributes {
 public static final int USAGE_NOTIFICATION=49;
 public int usage;
 public static class Builder {
  VibrationAttributes value=new VibrationAttributes();
  public Builder setUsage(int n){value.usage=n;return this;}
  public VibrationAttributes build(){return value;}
 }
}
""",
            "android/os/Vibrator.java": """
package android.os;
public class Vibrator {
 public boolean present=true,amplitude=true,fail; public int pulses,usage; public VibrationEffect last;
 public boolean hasVibrator(){return present;}
 public boolean hasAmplitudeControl(){return amplitude;}
 public void vibrate(VibrationEffect effect,VibrationAttributes attributes){record(effect,attributes.usage);}
 public void vibrate(VibrationEffect effect,android.media.AudioAttributes attributes){record(effect,attributes.usage);}
 private void record(VibrationEffect effect,int type){
  if(fail)throw new SecurityException();pulses++;last=effect;usage=type;
 }
}
""",
            "android/os/VibratorManager.java": """
package android.os;
public class VibratorManager {
 private final Vibrator vibrator;
 public VibratorManager(Vibrator vibrator){this.vibrator=vibrator;}
 public Vibrator getDefaultVibrator(){return vibrator;}
}
""",
            "android/os/Handler.java": """
package android.os;
public class Handler {
 public java.util.ArrayList<Runnable> pending=new java.util.ArrayList<>();
 public Handler(Looper ignored){}
 public boolean postDelayed(Runnable job,long millis){pending.add(job);return true;}
 public void removeCallbacksAndMessages(Object ignored){pending.clear();}
 public void fire(){for(Runnable job:new java.util.ArrayList<>(pending))job.run();}
}
""",
            "android/media/AudioManager.java": """
package android.media;
public class AudioManager {
 public static final int RINGER_MODE_NORMAL=2,RINGER_MODE_SILENT=0,STREAM_SYSTEM=1;
 public int ringer=2,volume=5; public boolean muted;
 public int getRingerMode(){return ringer;}
 public int getStreamVolume(int stream){return volume;}
 public boolean isStreamMute(int stream){return muted;}
}
""",
            "android/media/AudioAttributes.java": """
package android.media;
public class AudioAttributes {
 public static final int USAGE_ASSISTANCE_SONIFICATION=13,CONTENT_TYPE_SONIFICATION=4,USAGE_NOTIFICATION_EVENT=10;
 public int usage,content;
 public static class Builder {
  AudioAttributes value=new AudioAttributes();
  public Builder setUsage(int n){value.usage=n;return this;}
  public Builder setContentType(int n){value.content=n;return this;}
  public AudioAttributes build(){return value;}
 }
}
""",
            "android/media/AudioFormat.java": """
package android.media;
public class AudioFormat {
 public static final int ENCODING_PCM_16BIT=2,CHANNEL_OUT_MONO=4;
 public static class Builder {
  public Builder setSampleRate(int n){return this;} public Builder setEncoding(int n){return this;}
  public Builder setChannelMask(int n){return this;} public AudioFormat build(){return new AudioFormat();}
 }
}
""",
            "android/media/AudioTrack.java": """
package android.media;
public class AudioTrack {
 public static final int MODE_STATIC=0,STATE_UNINITIALIZED=0,WRITE_BLOCKING=0,SUCCESS=0;
 public static int count,fail; public static AudioTrack last;
 public int releases,plays,written; public float volume;
 public android.os.Handler handler; public AudioAttributes attributes;
 public OnPlaybackPositionUpdateListener listener;
 public interface OnPlaybackPositionUpdateListener {
  void onMarkerReached(AudioTrack track); void onPeriodicNotification(AudioTrack track);
 }
 public static class Builder {
  AudioAttributes attrs;
  public Builder setAudioAttributes(AudioAttributes n){attrs=n;return this;}
  public Builder setAudioFormat(AudioFormat n){return this;}
  public Builder setTransferMode(int n){return this;}
  public Builder setBufferSizeInBytes(int n){return this;}
  public AudioTrack build(){if(fail==1)throw new IllegalStateException();count++;last=new AudioTrack();last.attributes=attrs;return last;}
 }
 public int getState(){return fail==2?0:2;}
 public int write(short[] data,int offset,int size,int mode){written=size;return fail==3?size-1:size;}
 public int setVolume(float value){volume=value;return fail==4?-1:0;}
 public void setPlaybackPositionUpdateListener(OnPlaybackPositionUpdateListener value,android.os.Handler h){listener=value;handler=h;}
 public void setPlaybackPositionUpdateListener(OnPlaybackPositionUpdateListener value){listener=value;}
 public int setNotificationMarkerPosition(int n){return fail==5?-1:0;}
 public void play(){if(fail==6)throw new IllegalStateException();plays++;}
 public void release(){if(++releases!=1)throw new AssertionError("Double release");}
}
""",
        }
        harness = """
package com.randiny_games.fingerprintauthenticator;
import android.app.Activity;
import android.media.AudioTrack;
public final class FeedbackCheck {
 static void check(boolean value){if(!value)throw new AssertionError();}
 public static void main(String[] args) {
  short[] tone=FeedbackTone.samples();
  check(tone.length==1728 && tone[0]==0 && tone[tone.length-1]==0);
  double sum=0,squares=0; int peak=0,delta=0;
  for(int i=0;i<tone.length;i++){
   sum+=tone[i];squares+=(double)tone[i]*tone[i];peak=Math.max(peak,Math.abs((int)tone[i]));
   if(i>0)delta=Math.max(delta,Math.abs(tone[i]-tone[i-1]));
  }
  check(peak<5250 && peak>4500 && delta<650 && Math.abs(sum/tone.length)<5);
  check(Math.sqrt(squares/tone.length)>1500 && Math.sqrt(squares/tone.length)<2500);
  Activity a=new Activity(); SuccessFeedback f=new SuccessFeedback(a);
  f.play();check(a.vibrator.pulses==1 && AudioTrack.count==0);
  check(a.vibrator.last.duration==32 && a.vibrator.last.amplitude==96 && a.vibrator.usage==49);
  a.haptic=false;f.play();check(a.vibrator.pulses==1);
  Activity v=new Activity();SuccessFeedback vf=new SuccessFeedback(v);
  for(int sdk:new int[]{30,31,33,34}){
   android.os.Build.VERSION.SDK_INT=sdk;vf.play();
   check(v.vibrator.usage==(sdk>=33?49:10));
   check(v.vibrator.last.duration==32 && v.vibrator.last.amplitude==96);
  }
  int pulses=v.vibrator.pulses;
  v.audio.ringer=0;vf.play();check(v.vibrator.pulses==pulses);
  v.audio.ringer=1;vf.play();check(v.vibrator.pulses==++pulses);
  v.audio.ringer=2;
  for(int filter=0;filter<5;filter++){
   if(filter==1)continue;v.notifications.filter=filter;vf.play();check(v.vibrator.pulses==pulses);
  }
  v.notifications.filter=1;v.notifications.denied=true;vf.play();check(v.vibrator.pulses==pulses);
  v.notifications.denied=false;v.vibrator.amplitude=false;vf.play();check(v.vibrator.pulses==++pulses);
  check(v.vibrator.last.tick==android.os.VibrationEffect.EFFECT_TICK);
  v.vibrator.present=false;vf.play();check(v.vibrator.pulses==pulses);v.vibrator.present=true;
  v.missingManager=true;vf.play();check(v.vibrator.pulses==pulses);v.missingManager=false;
  android.os.Build.VERSION.SDK_INT=30;v.missingVibrator=true;vf.play();check(v.vibrator.pulses==pulses);
  android.os.Build.VERSION.SDK_INT=34;v.missingVibrator=false;
  v.vibrator.fail=true;vf.play();check(v.vibrator.pulses==pulses);vf.close();
  check(v.vibrator.pulses==pulses);
  a.sound=true;
  for(int ringer=0;ringer<2;ringer++){a.audio.ringer=ringer;f.play();check(AudioTrack.count==0);}
  a.audio.ringer=2;
  for(int filter=0;filter<5;filter++){if(filter==1)continue;a.notifications.filter=filter;f.play();check(AudioTrack.count==0);}
  a.notifications.filter=1;a.notifications.denied=true;f.play();check(AudioTrack.count==0);
  a.notifications.denied=false;a.audio.muted=true;f.play();check(AudioTrack.count==0);
  a.audio.muted=false;a.audio.volume=0;f.play();check(AudioTrack.count==0);
  a.audio.volume=5;f.play();AudioTrack first=AudioTrack.last;
  check(first.plays==1 && first.written==1728 && first.volume==0.25f);
  check(first.attributes.usage==13 && first.attributes.content==4);
  AudioTrack.OnPlaybackPositionUpdateListener stale=first.listener;
  first.listener.onMarkerReached(first);check(first.releases==1);
  f.close();check(first.releases==1);
  f.play();AudioTrack second=AudioTrack.last;
  stale.onMarkerReached(first);check(second.releases==0);
  second.handler.fire();check(second.releases==1);
  for(int error=1;error<=6;error++){
   AudioTrack.fail=error;int before=AudioTrack.count;f.play();
   if(AudioTrack.count>before)check(AudioTrack.last.releases==1);
  }
  AudioTrack.fail=0;a.badPrefs=true;f.play();f.close();
  a.badPrefs=false;a.haptic=true;a.vibrator.fail=true;f.play();
  check(AudioTrack.last.plays==1);f.close();check(AudioTrack.last.releases==1);
 }
}
"""
        with tempfile.TemporaryDirectory(prefix="pam-feedback-") as temporary:
            base = Path(temporary)
            files = []
            for relative, body in stubs.items():
                path = base / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
                files.append(str(path))
            path = base / "FeedbackCheck.java"
            path.write_text(harness)
            subprocess.run(["javac", "-d", temporary, *files, str(SOURCE / "FeedbackTone.java"),
                            str(SOURCE / "SuccessFeedback.java"), str(path)],
                           check=True, capture_output=True, timeout=30)
            result = subprocess.run(["java", "-cp", temporary,
                                     "com.randiny_games.fingerprintauthenticator.FeedbackCheck"],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
