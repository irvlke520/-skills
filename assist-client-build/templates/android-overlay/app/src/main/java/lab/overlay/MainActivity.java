package lab.overlay;

import android.content.Intent;
import android.graphics.Rect;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

/**
 * Entry point. Requests the overlay permission, then hands the offsets to the
 * native layer and starts both the collection thread and the render service.
 *
 * The offset block below is the only part you need to fill in for a new target.
 * Locate the values with tools/android_tools.py before starting:
 *   python tools/android_tools.py maps  --proc <pkg> --filter <so>
 *   python tools/android_tools.py scan  --proc <pkg> --module <so> --pattern "..."
 *   python tools/android_tools.py chain --proc <pkg> --base <so>+0x... --offsets "..."
 */
public class MainActivity extends AppCompatActivity {

    private static final int REQ_OVERLAY = 1001;

    /** Character device exposed by your kernel module. */
    private static final String DEVICE = "{{DEVICE}}";

    /** --- target layout, filled by scaffold.py from the offset table --- */
    private static final long MODULE_BASE = {{MODULE_BASE}}L;
    private static final long MATRIX_OFF = {{MATRIX_OFF}}L;
    private static final long ENTITY_BASE = {{ENTITY_BASE}}L;
    private static final int STRIDE = {{STRIDE}};
    private static final int COUNT = {{COUNT}};
    private static final int POS_OFF = {{POS_OFF}};
    private static final int HEALTH_OFF = {{HEALTH_OFF}};
    private static final int TEAM_OFF = {{TEAM_OFF}};

    /** box width = box height * BOX_RATIO ; entity height in world units */
    private static final float BOX_RATIO = {{BOX_RATIO}}f;
    private static final float HEIGHT = {{HEIGHT}}f;

    private EditText editPid;
    private EditText editDevice;
    private TextView textStatus;
    private boolean started = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        editPid = findViewById(R.id.editPid);
        editDevice = findViewById(R.id.editDevice);
        textStatus = findViewById(R.id.textStatus);
        Button btnStart = findViewById(R.id.btnStart);
        Button btnStop = findViewById(R.id.btnStop);

        editDevice.setText(DEVICE);

        btnStart.setOnClickListener(v -> start());
        btnStop.setOnClickListener(v -> stop());

        if (!Settings.canDrawOverlays(this)) {
            Intent intent = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    android.net.Uri.parse("package:" + getPackageName()));
            startActivityForResult(intent, REQ_OVERLAY);
        }
    }

    private int[] screenSize() {
        WindowManager wm = getSystemService(WindowManager.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Rect bounds = wm.getCurrentWindowMetrics().getBounds();
            return new int[]{bounds.width(), bounds.height()};
        }
        android.util.DisplayMetrics dm = new android.util.DisplayMetrics();
        wm.getDefaultDisplay().getMetrics(dm);
        return new int[]{dm.widthPixels, dm.heightPixels};
    }

    private void start() {
        if (!Settings.canDrawOverlays(this)) {
            status("overlay permission missing");
            return;
        }

        int pid;
        try {
            pid = Integer.parseInt(editPid.getText().toString().trim());
        } catch (NumberFormatException e) {
            status("invalid pid");
            return;
        }

        String device = editDevice.getText().toString().trim();
        int rc = KernelBridge.nativeOpen(device);
        if (rc != 0) {
            status("open " + device + " failed: " + rc);
            return;
        }

        int[] size = screenSize();
        long[] icfg = new long[]{
                MODULE_BASE, MATRIX_OFF, ENTITY_BASE, STRIDE, COUNT,
                POS_OFF, HEALTH_OFF, TEAM_OFF, size[0], size[1]
        };
        float[] fcfg = new float[]{BOX_RATIO, HEIGHT};

        KernelBridge.nativeSetConfig(icfg, fcfg);

        if (KernelBridge.nativeStart(pid, KernelBridge.DEFAULT_PORT) != 0) {
            status("native start failed");
            KernelBridge.nativeClose();
            return;
        }

        Intent svc = new Intent(this, OverlayService.class);
        svc.putExtra("port", KernelBridge.DEFAULT_PORT);
        startService(svc);

        started = true;
        status("running pid=" + pid + " port=" + KernelBridge.DEFAULT_PORT);
    }

    private void stop() {
        if (!started) {
            return;
        }
        KernelBridge.nativeStop();
        KernelBridge.nativeClose();
        stopService(new Intent(this, OverlayService.class));
        started = false;
        status("stopped");
    }

    private void status(String s) {
        runOnUiThread(() -> textStatus.setText(s));
    }

    @Override
    protected void onDestroy() {
        stop();
        super.onDestroy();
    }
}
