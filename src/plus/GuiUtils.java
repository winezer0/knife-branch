package plus;

import javax.swing.*;

public class GuiUtils
{
    /**
     * 手动触发 JVM 内存清理，并向用户展示清理前后的内存占用量。
     */
    public static void SystemClear() {
        try {
            long beforeUsedMemory = getUsedMemoryBytes();
            System.gc();
            System.runFinalization();
            System.gc();
            long afterUsedMemory = getUsedMemoryBytes();
            String message = "BurpSuite JVM memory usage\n"
                    + "Before cleanup: " + formatMemoryUsage(beforeUsedMemory) + "\n"
                    + "After cleanup: " + formatMemoryUsage(afterUsedMemory);
            JOptionPane.showMessageDialog(null, message, "System Clear", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            JOptionPane.showMessageDialog(null,
                    "Failed to trigger system memory cleanup.\n" + e.getMessage(),
                    "System Clear",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * 获取当前 JVM 已使用的堆内存字节数，使用标准 Java API 以保证跨平台兼容。
     */
    public static long getUsedMemoryBytes() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    /**
     * 将字节数格式化为便于用户查看的 MB 文本。
     */
    public static String formatMemoryUsage(long memoryBytes) {
        double memoryInMb = memoryBytes / 1024.0 / 1024.0;
        return String.format("%.2f MB", memoryInMb);
    }

}

