from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "Android/app/src/main/java/com/randiny_games/fingerprintauthenticator"


@unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "JDK required")
class RequestUiTests(unittest.TestCase):
    def test_real_controller_with_deterministic_android_task_and_queue_doubles(self):
        stubs = {
            "android/os/Looper.java": """
package android.os; public class Looper { public static Looper getMainLooper(){return new Looper();} }
""",
            "android/os/SystemClock.java": """
package android.os; public class SystemClock { public static long now; public static long elapsedRealtime(){return now;} }
""",
            "android/os/Handler.java": """
package android.os;
public class Handler {
 static class Job {Handler owner;Runnable run;long at;Job(Handler o,Runnable r,long a){owner=o;run=r;at=a;}}
 static java.util.ArrayList<Job> jobs=new java.util.ArrayList<>();
 public Handler(Looper l){}
 public boolean post(Runnable r){return postDelayed(r,0);}
 public boolean postDelayed(Runnable r,long delay){jobs.add(new Job(this,r,SystemClock.now+delay));return true;}
 public void removeCallbacksAndMessages(Object ignored){jobs.removeIf(job->job.owner==this);}
 public static void advance(long amount){
  long end=SystemClock.now+amount;
  for(int guard=0;guard<10000;guard++){
   Job next=null;for(Job job:jobs)if(job.at<=end&&(next==null||job.at<next.at))next=job;
   if(next==null){SystemClock.now=end;return;}
   jobs.remove(next);SystemClock.now=next.at;next.run.run();
  }
  throw new AssertionError("Queue did not settle");
 }
}
""",
            "android/net/Uri.java": """
package android.net; public class Uri {
 String value;private Uri(String n){value=n;}public static Uri parse(String n){return new Uri(n);}
 public boolean equals(Object n){return n instanceof Uri&&value.equals(((Uri)n).value);}
 public int hashCode(){return value.hashCode();}
}
""",
            "android/content/ComponentName.java": """
package android.content; public class ComponentName {
 String name;public ComponentName(String n){name=n;}public String getClassName(){return name;}
}
""",
            "android/content/Context.java": """
package android.content;
public class Context {
 public android.app.ActivityManager tasks=new android.app.ActivityManager();
 public android.app.NotificationManager notifications=new android.app.NotificationManager();
 public Intent launched;public int launches;
 public Context getApplicationContext(){return this;}
 public <T>T getSystemService(Class<T> kind){
  return kind.cast(kind==android.app.ActivityManager.class?tasks:notifications);
 }
 public void startActivity(Intent value){launched=value;launches++;}
}
""",
            "android/content/Intent.java": """
package android.content;
public class Intent {
 public static final int FLAG_ACTIVITY_NEW_TASK=0x10000000,FLAG_ACTIVITY_NEW_DOCUMENT=0x80000;
 android.net.Uri data;ComponentName component;int flags;
 java.util.HashMap<String,String> extras=new java.util.HashMap<>();
 public Intent(Context c,Class<?> type){component=new ComponentName(type.getName());}
 public Intent setData(android.net.Uri n){data=n;return this;}public android.net.Uri getData(){return data;}
 public Intent addFlags(int n){flags|=n;return this;}
 public Intent setAction(String n){return this;}
 public Intent putExtra(String k,String v){extras.put(k,v);return this;}
 public String getStringExtra(String n){return extras.get(n);}
 public ComponentName getComponent(){return component;}
}
""",
            "android/app/ActivityManager.java": """
package android.app;
public class ActivityManager {
 public boolean denied;public java.util.ArrayList<AppTask> tasks=new java.util.ArrayList<>();
 public java.util.List<AppTask> getAppTasks(){if(denied)throw new SecurityException();return tasks;}
 public static class RecentTaskInfo {public int taskId,numActivities=1;public android.content.Intent baseIntent;}
 public static class AppTask {
  public RecentTaskInfo info=new RecentTaskInfo();public boolean alive=true,excluded=true;public int removed;
  public RecentTaskInfo getTaskInfo(){if(!alive)throw new IllegalArgumentException();return info;}
  public void setExcludeFromRecents(boolean value){excluded=value;}
  public void finishAndRemoveTask(){removed++;alive=false;}
 }
}
""",
            "android/app/NotificationChannel.java": """
package android.app;public class NotificationChannel{
 int importance;public NotificationChannel(String id,String name,int n){importance=n;}
 public int getImportance(){return importance;}
}
""",
            "android/app/NotificationManager.java": """
package android.app;
public class NotificationManager {
 public static final int IMPORTANCE_HIGH=4,IMPORTANCE_NONE=0;
 public boolean allowed=true,failNotify;public int importance=4;
 public java.util.HashSet<String> active=new java.util.HashSet<>();
 public boolean areNotificationsEnabled(){return allowed;}
 public void createNotificationChannel(NotificationChannel c){}
 public NotificationChannel getNotificationChannel(String id){return new NotificationChannel(id,id,importance);}
 public void notify(String tag,int id,Notification n){if(failNotify)throw new SecurityException();active.add(tag);}
 public void cancel(String tag,int id){active.remove(tag);}
 public android.service.notification.StatusBarNotification[] getActiveNotifications(){
  return active.stream().map(tag->new android.service.notification.StatusBarNotification(tag,41))
   .toArray(android.service.notification.StatusBarNotification[]::new);
 }
}
""",
            "android/service/notification/StatusBarNotification.java": """
package android.service.notification;
public class StatusBarNotification {
 String tag;int id;public StatusBarNotification(String tag,int id){this.tag=tag;this.id=id;}
 public int getId(){return id;}public String getTag(){return tag;}
}
""",
            "android/app/Notification.java": """
package android.app;
public class Notification {
 public static final int VISIBILITY_PRIVATE=0;
 public static class Builder {
  public Builder(android.content.Context c,String channel){}
  public Builder setSmallIcon(int n){return this;}public Builder setContentTitle(String n){return this;}
  public Builder setContentText(String n){return this;}public Builder setVisibility(int n){return this;}
  public Builder setOnlyAlertOnce(boolean n){return this;}public Builder setOngoing(boolean n){return this;}
  public Builder setAutoCancel(boolean n){return this;}public Builder setContentIntent(PendingIntent n){return this;}
  public Builder setDeleteIntent(PendingIntent n){return this;}
  public Builder addAction(int n,String s,PendingIntent p){return this;}public Notification build(){return new Notification();}
 }
}
""",
            "android/app/PendingIntent.java": """
package android.app;
public class PendingIntent {
 public static final int FLAG_UPDATE_CURRENT=1,FLAG_IMMUTABLE=2;
 public static PendingIntent getActivity(android.content.Context c,int id,android.content.Intent i,int f){return new PendingIntent();}
 public static PendingIntent getBroadcast(android.content.Context c,int id,android.content.Intent i,int f){return new PendingIntent();}
}
""",
            "android/R.java": """
package android;public class R{public static class drawable{public static final int ic_lock_lock=1,ic_menu_close_clear_cancel=2;}}
""",
            "com/randiny_games/fingerprintauthenticator/RequestActionReceiver.java": """
package com.randiny_games.fingerprintauthenticator;public class RequestActionReceiver {}
""",
            "com/randiny_games/fingerprintauthenticator/ConfirmationActivity.java": """
package com.randiny_games.fingerprintauthenticator;
public class ConfirmationActivity extends android.content.Context {
 public boolean destroyed,finishing,feedback;public int id,finished,ended;public android.content.Intent intent;
 public android.content.Intent getIntent(){return intent;}public int getTaskId(){return id;}
 public boolean isTaskRoot(){return true;}public boolean isDestroyed(){return destroyed;}
 public boolean isFinishing(){return finishing;}public boolean keepFeedbackVisible(){return feedback;}
 public void requestEnded(){ended++;finish();}public void finish(){finished++;finishing=true;}
}
""",
        }
        harness = """
package com.randiny_games.fingerprintauthenticator;
import android.app.ActivityManager;
import android.content.Context;
import android.os.Handler;
import android.os.SystemClock;
public class UiCheck {
 static int sequence;
 static void check(boolean value){if(!value)throw new AssertionError();}
 static RequestOwner owner(boolean unlimited,boolean network){
  return RequestOwner.start(String.format("%064x",++sequence),"pc","alice",
    unlimited?"kde-fingerprint":"sudo",network,unlimited,SystemClock.now);
 }
 static ConfirmationActivity attach(Context c,RequestUi ui,int id){
  ConfirmationActivity a=new ConfirmationActivity();a.id=id;a.intent=c.launched;
  ActivityManager.AppTask task=new ActivityManager.AppTask();task.info.taskId=id;task.info.baseIntent=a.intent;
  c.tasks.tasks.add(task);check(ui.attach(a));return a;
 }
 public static void main(String[] args) throws Exception {
  Context c=new Context();RequestOwner o=owner(true,true);RequestUi.open(c,o,true);
  RequestUi ui=RequestUi.existing(o);ConfirmationActivity a=attach(c,ui,1);
  check(!c.tasks.tasks.get(0).excluded);ui.paused();check(Results.active(o.pending,SystemClock.now));
  RequestUi.cancel(o.nonce,"wrong");check(!o.pending.future.isDone());
  RequestUi.cancel("wrong",o.token);check(!o.pending.future.isDone());
  // A notification tap racing ahead of the swipe monitor may not rebind.
  c.tasks.tasks.get(0).alive=false;
  ConfirmationActivity replacement=new ConfirmationActivity();replacement.id=2;replacement.intent=c.launched;
  check(!ui.attach(replacement));check(o.pending.future.isDone());
  Handler.advance(0);check(c.notifications.active.isEmpty());check(replacement.ended==0);
  RequestOwner.close(o);
  // Success observer is queued, never consumes an unread ADB result.
  Context adb=new Context();RequestOwner old=owner(true,false);RequestUi.open(adb,old,true);
  RequestUi oldUi=RequestUi.existing(old);ConfirmationActivity oldWindow=attach(adb,oldUi,10);
  oldWindow.feedback=true;
  check(Results.complete(old.pending,"signed"));
  check(adb.notifications.active.contains(old.token)); // callback did not execute inline.
  check(Results.claim(old.nonce)==old.pending); // still readable before/after UI cleanup.
  Handler.advance(0);
  RequestOwner fresh=owner(true,true);RequestUi.open(adb,fresh,true);
  RequestUi freshUi=RequestUi.existing(fresh);ConfirmationActivity newWindow=attach(adb,freshUi,11);
  Handler.advance(1500);
  check(adb.tasks.tasks.get(0).removed==1 && adb.tasks.tasks.get(1).removed==0);
  check(adb.notifications.active.contains(fresh.token) && newWindow.ended==0);
  adb.notifications.allowed=false;Handler.advance(500);
  check(Results.active(fresh.pending,SystemClock.now)); // Recents is still a usable resume surface.
  adb.notifications.allowed=true;
  check(Results.await(old.pending).equals("signed"));
  RequestOwner.close(old);check(Results.active(fresh.pending,SystemClock.now));
  RequestOwner.close(fresh);Handler.advance(0);
  check(adb.tasks.tasks.get(1).removed==1);
  // No Recents and no notification must fail, never retain an inaccessible request.
  Context denied=new Context();denied.tasks.denied=true;denied.notifications.allowed=false;
  RequestOwner noSurface=owner(true,true);RequestUi.open(denied,noSurface,true);
  ConfirmationActivity hidden=new ConfirmationActivity();hidden.id=20;hidden.intent=denied.launched;
  check(!RequestUi.existing(noSurface).attach(hidden));check(noSurface.pending.future.isDone());
  Handler.advance(0);RequestOwner.close(noSurface);
  // Timed windows remain excluded; transport end removes their own task only.
  Context timed=new Context();RequestOwner normal=owner(false,true);RequestUi.open(timed,normal,true);
  RequestUi normalUi=RequestUi.existing(normal);attach(timed,normalUi,30);
  check(timed.tasks.tasks.get(0).excluded);
  RequestOwner.close(normal);Handler.advance(0);check(timed.tasks.tasks.get(0).removed==1);
  // A changed task root can never be destructively cleaned as this request.
  Context changed=new Context();RequestOwner guarded=owner(true,true);RequestUi.open(changed,guarded,true);
  RequestUi guardedUi=RequestUi.existing(guarded);attach(changed,guardedUi,40);
  changed.tasks.tasks.get(0).info.baseIntent=new android.content.Intent(changed,RequestActionReceiver.class);
  RequestOwner.close(guarded);Handler.advance(0);check(changed.tasks.tasks.get(0).removed==0);
  // Recents swipe cancels even when no network foreground service is running.
  Context swipe=new Context();RequestOwner pending=owner(true,false);RequestUi.open(swipe,pending,true);
  RequestUi pendingUi=RequestUi.existing(pending);attach(swipe,pendingUi,50);
  swipe.tasks.tasks.get(0).alive=false;Handler.advance(500);
  check(pending.pending.future.isDone() && swipe.notifications.active.isEmpty());RequestOwner.close(pending);
  // Revoking a notification-only resume surface must end even a renewed lease.
  for(boolean blockedChannel:new boolean[]{false,true}){
   Context revoked=new Context();RequestOwner lease=owner(true,true);RequestUi.open(revoked,lease,false);
   Handler.advance(0);check(!lease.pending.future.isDone());
   for(int i=0;i<3;i++){check(Results.touch(lease.pending,SystemClock.now));Handler.advance(2000);}
   if(blockedChannel)revoked.notifications.importance=0;else revoked.notifications.allowed=false;
   Handler.advance(500);check(lease.pending.future.isDone());RequestOwner.close(lease);
  }
  // startActivity returning is not an attachment acknowledgement.
  Context ignored=new Context();ignored.notifications.allowed=false;
  RequestOwner unattached=owner(true,true);RequestUi.open(ignored,unattached,true);
  Handler.advance(4999);check(!unattached.pending.future.isDone());
  Handler.advance(501);check(unattached.pending.future.isDone());RequestOwner.close(unattached);
  // Permission alone is not a resume surface: actual notify failure stays bounded.
  Context failed=new Context();failed.notifications.failNotify=true;
  RequestOwner invisible=owner(true,true);RequestUi.open(failed,invisible,true);
  Handler.advance(5500);check(invisible.pending.future.isDone());RequestOwner.close(invisible);
  // Dismissal or external removal of the sole notification ends the request.
  for(boolean deleteIntent:new boolean[]{false,true}){
   Context removed=new Context();RequestOwner orphan=owner(true,true);RequestUi.open(removed,orphan,false);
   Handler.advance(0);removed.notifications.active.clear();
   if(deleteIntent)RequestUi.dismissed(orphan.nonce,orphan.token);
   Handler.advance(500);check(orphan.pending.future.isDone());RequestOwner.close(orphan);
  }
  // Reopened post-process-death documents are removed only by exact private identity.
  ConfirmationActivity stale=new ConfirmationActivity();stale.id=70;
  String staleToken=String.format("%064x",999);
  stale.intent=new android.content.Intent(stale,ConfirmationActivity.class)
    .setData(android.net.Uri.parse("pam-confirm:"+staleToken)).putExtra("request_owner",staleToken);
  ActivityManager.AppTask staleTask=new ActivityManager.AppTask();
  staleTask.info.taskId=70;staleTask.info.baseIntent=stale.intent;stale.tasks.tasks.add(staleTask);
  RequestUi.closeStale(stale);check(staleTask.removed==1);
  staleTask.alive=true;staleTask.removed=0;
  staleTask.info.baseIntent=new android.content.Intent(stale,RequestActionReceiver.class)
    .setData(stale.intent.getData());
  RequestUi.closeStale(stale);check(staleTask.removed==0);
 }
}
"""
        with tempfile.TemporaryDirectory(prefix="pam-request-ui-") as temporary:
            base = Path(temporary)
            paths = []
            for relative, body in stubs.items():
                path = base / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
                paths.append(str(path))
            harness_path = base / "UiCheck.java"
            harness_path.write_text(harness)
            compiled = subprocess.run(["javac", "-d", temporary, *paths, *(str(SOURCE / name) for name in
                            ("Results.java", "RequestOwner.java", "UiTaskBinding.java", "RequestUi.java")),
                            str(harness_path)], capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run(["java", "-cp", temporary,
                                     "com.randiny_games.fingerprintauthenticator.UiCheck"],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
