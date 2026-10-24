package lab.overlay;

import android.app.Service;
import android.content.Intent;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.PixelFormat;
import android.graphics.PorterDuff;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.view.Gravity;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.WindowManager;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Renders whatever the native layer publishes on the localhost socket.
 *
 * This service never touches the target process. It only draws rectangles from
 * coordinates that arrive over TCP, which keeps the render surface completely
 * decoupled from the data source.
 */
public class OverlayService extends Service implements SurfaceHolder.Callback {

    private static final int FRAME_MS = 8;

    private WindowManager windowManager;
    private SurfaceView surfaceView;
    private SurfaceHolder holder;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private volatile boolean running = true;
    private int port = KernelBridge.DEFAULT_PORT;

    private final List<float[]> entities = new CopyOnWriteArrayList<>();

    private final Paint boxPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint fillPaint = new Paint();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            port = intent.getIntExtra("port", KernelBridge.DEFAULT_PORT);
        }
        boxPaint.setStyle(Paint.Style.STROKE);
        boxPaint.setStrokeWidth(2.0f);
        textPaint.setColor(Color.WHITE);
        textPaint.setTextSize(20.0f);
        fillPaint.setStyle(Paint.Style.FILL);
        fillPaint.setAlpha(38);

        setupWindow();
        startClient();
        startRenderLoop();
        return START_STICKY;
    }

    private void setupWindow() {
        surfaceView = new SurfaceView(this);
        holder = surfaceView.getHolder();
        holder.setFormat(PixelFormat.TRANSLUCENT);
        holder.addCallback(this);

        WindowManager.LayoutParams params = new WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                        | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE
                        | WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL
                        | WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS
                        | WindowManager.LayoutParams.FLAG_HARDWARE_ACCELERATED,
                PixelFormat.TRANSLUCENT);
        params.gravity = Gravity.TOP | Gravity.START;

        windowManager = (WindowManager) getSystemService(WINDOW_SERVICE);
        if (windowManager != null) {
            windowManager.addView(surfaceView, params);
        }
    }

    private void startClient() {
        new Thread(() -> {
            while (running) {
                List<float[]> batch = new ArrayList<>();
                try (Socket socket = new Socket("127.0.0.1", port);
                     BufferedReader reader = new BufferedReader(
                             new InputStreamReader(socket.getInputStream()))) {
                    String line;
                    while (running && (line = reader.readLine()) != null) {
                        if (line.equals("CLEAR")) {
                            entities.clear();
                            entities.addAll(batch);
                            batch.clear();
                            continue;
                        }
                        float[] e = parseEntity(line);
                        if (e != null) {
                            batch.add(e);
                        }
                    }
                } catch (Exception ignored) {
                    try {
                        Thread.sleep(400);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
        }, "overlay-client").start();
    }

    /** wire format: x,y,w,h,distance,team */
    private float[] parseEntity(String line) {
        String[] p = line.split(",");
        if (p.length < 4) {
            return null;
        }
        try {
            float[] e = new float[6];
            for (int i = 0; i < 6; i++) {
                e[i] = i < p.length ? Float.parseFloat(p[i].trim()) : 0f;
            }
            return e;
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private void startRenderLoop() {
        handler.post(new Runnable() {
            @Override
            public void run() {
                if (!running) {
                    return;
                }
                drawFrame();
                handler.postDelayed(this, FRAME_MS);
            }
        });
    }

    private void drawFrame() {
        if (holder == null) {
            return;
        }
        Canvas canvas = holder.lockCanvas();
        if (canvas == null) {
            return;
        }
        try {
            canvas.drawColor(Color.TRANSPARENT, PorterDuff.Mode.CLEAR);
            for (float[] e : entities) {
                float x = e[0], y = e[1], w = e[2], h = e[3], dist = e[4], team = e[5];
                if (w <= 0 || h <= 0) {
                    continue;
                }
                int color = team > 0.5f ? Color.GREEN : Color.RED;
                boxPaint.setColor(color);
                fillPaint.setColor(color);
                canvas.drawRect(x, y, x + w, y + h, fillPaint);
                canvas.drawRect(x, y, x + w, y + h, boxPaint);
                canvas.drawText(String.format(java.util.Locale.US, "%.0f", dist), x, y - 6f, textPaint);
            }
        } finally {
            holder.unlockCanvasAndPost(canvas);
        }
    }

    @Override
    public void surfaceCreated(SurfaceHolder holder) {
        this.holder = holder;
    }

    @Override
    public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
        this.holder = holder;
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder holder) {
        this.holder = null;
    }

    @Override
    public void onDestroy() {
        running = false;
        if (surfaceView != null && windowManager != null) {
            try {
                windowManager.removeView(surfaceView);
            } catch (Exception ignored) {
            }
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
