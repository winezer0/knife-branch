package plus;

import java.util.ArrayList;
import java.util.Random;
import java.util.regex.Pattern;
import java.util.List;

import static plus.UtilsPlus.splitStringToListWithGrammar;

public class RandomIPUtils {
    private static final Pattern IP_WITH_CIDR_PATTERN = Pattern.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[1-2][0-9]|3[0-2])$");
    private static final Random random = new Random();

    /**
     * 判断字符串是否是单个 IP/网段格式 10.0.0.0/24
     */
    private static boolean isCidrIpv4(String input) {
        return input != null && IP_WITH_CIDR_PATTERN.matcher(input.trim()).matches();
    }

    /**
     * 从单个 IP/网段中随机返回一个 IP 地址
     */
    private static String getRandomIpFromIPCidr(String ipWithCidr) {
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

    /**
     *
     * 对参数值进行语法切割,并且对切割后的结果进行CiDr格式化处理
     * @param ipString
     * @return
     */
    public static List<String> splitStrToListWithGrammarAndRender(String ipString){
        //直接对所有的值都进行切割语法支持 || && 应该默认不会有吧
        List<String> ipRangeList = splitStringToListWithGrammar(ipString);
        List<String> result = new ArrayList<>(ipRangeList.size());
        for (String ipRange : ipRangeList) {
            String ipRangeTrimmed = ipRange.trim();
            if (isCidrIpv4(ipRangeTrimmed)){
                ipRangeTrimmed = getRandomIpFromIPCidr(ipRangeTrimmed);
            }
            if (!ipRangeTrimmed.isEmpty()){
                result.add(ipRangeTrimmed);
            }
        }
        return result;
    }
}