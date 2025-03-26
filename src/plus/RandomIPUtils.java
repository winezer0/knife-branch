package plus;

import java.util.Random;
import java.util.regex.Pattern;
import java.util.Arrays;
import java.util.List;

public class RandomIPUtils {
    private static final Pattern IP_WITH_CIDR_PATTERN = Pattern.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[1-2][0-9]|3[0-2])$");
    private static final Random random = new Random();

    /**
     * 判断字符串是否是单个 IP/网段格式 10.0.0.0/24
     */
    public static boolean isCidrIpv4(String input) {
        return input != null && IP_WITH_CIDR_PATTERN.matcher(input.trim()).matches();
    }

    /**
     * 判断字符串是否是单个 IP/网段格式或多个IP网段格式
     * @param input 输入字符串
     * @return 如果是 IP/网段格式返回 true，否则返回 false
     */
    public static boolean isMultipleOrCidrIp(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false;
        }

        String[] ipRanges = input.split("\\|");
        for (String ipRange : ipRanges) {
            String trimmed = ipRange.trim();
            if (trimmed.isEmpty() || !isCidrIpv4(trimmed)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 从 IP/网段或多个网段中随机返回一个 IP 地址
     * @param ipRange IP/网段字符串，如 "192.168.0.1/30" 或 "192.168.0.1/24|10.0.0.1/24"
     * @return 随机生成的 IP 地址
     * @throws IllegalArgumentException 如果输入格式无效
     */
    public static String getRandomIpFromRanges(String ipRange) {
        String selectedRange = ipRange;
        if (ipRange.contains("|")) {
            // 拆分多个网段
            String[] ipRanges = ipRange.split("\\|");
            List<String> rangeList = Arrays.asList(ipRanges);
            // 随机选择一个网段
            selectedRange = rangeList.get(random.nextInt(rangeList.size())).trim();
        }
        // 从选中的网段中随机获取一个IP
        String randomIp = selectedRange;
        try {
            randomIp = getRandomIpFromRange(selectedRange);
        } catch (Exception exception){
            System.out.println(String.format("get Random Ip From Range [%s] Error:%s", selectedRange, exception));
        }
        return randomIp;
    }

    /**
     * 从单个 IP/网段中随机返回一个 IP 地址
     */
    public static String getRandomIpFromRange(String ipWithCidr) {
        String[] parts = ipWithCidr.split("/");
        String ip = parts[0].trim();
        int cidr = Integer.parseInt(parts[1].trim());

        // 特殊处理 /32 的情况
        if (cidr == 32) {
            return ip;
        }

        int ipInt = ipToInt(ip);
        int mask = cidr == 0 ? 0 : 0xFFFFFFFF << (32 - cidr);
        int network = ipInt & mask;
        int broadcast = network | ~mask;

        // 对于 /31 网络，没有广播地址，两个地址都是主机地址
        if (cidr == 31) {
            int randomIp = network + random.nextInt(2);
            return intToIp(randomIp);
        }

        // 随机生成网络地址和广播地址之间的一个 IP
        int randomIp = network + 1 + random.nextInt(broadcast - network - 1);
        return intToIp(randomIp);
    }

    private static int ipToInt(String ipAddress) {
        String[] octets = ipAddress.split("\\.");
        return (Integer.parseInt(octets[0]) << 24) |
                (Integer.parseInt(octets[1]) << 16) |
                (Integer.parseInt(octets[2]) << 8) |
                Integer.parseInt(octets[3]);
    }

    private static String intToIp(int ip) {
        return ((ip >> 24) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                (ip & 0xFF);
    }

    public static void main(String[] args) {
        String singleRange = "192.168.0.0/24";
        System.out.println("Single range test:");
        System.out.println(singleRange + " is valid: " + isMultipleOrCidrIp(singleRange));
        System.out.println("Random IP: " + getRandomIpFromRanges(singleRange));

        String multipleRanges = "192.168.10.1/24|172.16.10.1/24|10.10.10.1/24";
        System.out.println("\nMultiple ranges test:");
        System.out.println(multipleRanges + " is valid: " + isMultipleOrCidrIp(multipleRanges));
        for (int i = 0; i < 5; i++) {
            System.out.println("Random IP: " + getRandomIpFromRanges(multipleRanges));
        }


        String invalidInput = "192.168.0.1/33|invalid";
        System.out.println("\nInvalid input test:");
        System.out.println(invalidInput + " is valid: " + isMultipleOrCidrIp(invalidInput));
        try {
            System.out.println("Random IP: " + getRandomIpFromRanges(invalidInput));
        } catch (IllegalArgumentException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}