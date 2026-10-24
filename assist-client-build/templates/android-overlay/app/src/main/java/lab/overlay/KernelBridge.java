package lab.overlay;

/** Thin wrapper over the native ioctl client. */
public final class KernelBridge {

    static {
        System.loadLibrary("kernel_bridge");
    }

    public static final int DEFAULT_PORT = 61234;

    private KernelBridge() {
    }

    /**
     * Open the character device exposed by the kernel module.
     * Returns 0 on success, or -errno on failure.
     */
    public static native int nativeOpen(String device);

    public static native void nativeClose();

    /**
     * @param icfg [moduleBase, matrixOff, entityBase, stride, count,
     *             posOff, healthOff, teamOff, screenW, screenH]
     * @param fcfg [boxRatio, height]
     */
    public static native void nativeSetConfig(long[] icfg, float[] fcfg);

    /** Spawn the collection thread and the localhost renderer socket. */
    public static native int nativeStart(int pid, int port);

    public static native void nativeStop();

    /** Read one int32 through the driver. Returns -1 if the ioctl failed. */
    public static native int nativeReadTest(long addr);
}
