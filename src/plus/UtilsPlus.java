package plus;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;
import java.util.Random;

public class UtilsPlus {
    /**
     * 将[.]替换为[\.],便于进行正则精确匹配
     * @param host
     * @return
     */
    public static String dotToEscapeDot(String host ) {
        return host.replace(".","\\.");
    }

    /**
     * 将域名变为转移的上级域名转义正则 www.xxx.com -> .*\.xxx\.com IP仅转义.号
     * @param host
     * @return
     */
    public static String hostToWildcardHostWithDotEscape(String host) {
        if(isIPFormat(host)){
            return dotToEscapeDot(domainToSuperiorDomain(host));
        }else {
            return ".*" + "\\." + dotToEscapeDot(domainToSuperiorDomain(host));
        }
    }

    /**
     * 判断Host不是IPv4或者IPv6格式
     * @param host
     * @return
     */
    public static boolean isIPFormat(String host) {
        boolean isIpv4 = IPAddressUtil.isIPv4LiteralAddress(host);
        boolean isIpv6 = IPAddressUtil.isIPv6LiteralAddress(host);
        return isIpv4||isIpv6;
    }

    /**
     * 域名转为上级域名格式 www.baidu.com -> baidu.com
     * @param domain
     * @return
     */
    public static String domainToSuperiorDomain(String domain){
        // 获取上级域名 3级域名获取2级域名|2级域名获取主域名|主域名不操作
        String[] hostParts = domain.split("\\.");
        if (hostParts.length > 2) {
            String[] slicedArr = Arrays.copyOfRange(hostParts, 1, hostParts.length);
            domain = String.join(".", slicedArr);
        }
        return domain;
    }

    /**
     * 去除JsonArray里面指定键 并且 值包含在hastset中的元素
     * @param jsonObjectJsonArray
     * @param jsonObjectKey
     * @param hashSet
     * @return
     */
    public static JsonArray RemoveJsonObjectJsonArray(JsonArray jsonObjectJsonArray , String jsonObjectKey, HashSet<String> hashSet){
        JsonArray resultJsonArray = new JsonArray();
        List<JsonObject> list = new ArrayList<>();
        for (int i = 0; i < jsonObjectJsonArray.size(); i++){
            JsonObject jsonObject = jsonObjectJsonArray.get(i).getAsJsonObject();
            String jsonElement = jsonObject.get(jsonObjectKey).getAsString();
            if (!hashSet.contains(jsonElement)){
                list.add(jsonObject);
            }
        }
        for (JsonObject jsonObject : list){
            resultJsonArray.add(jsonObject);
        }
        return resultJsonArray;
    }

    /**
     * 去除JsonArray里面指定键 并且 值的元素
     * @param jsonObjectJsonArray
     * @param jsonObjectKey
     * @param jsonObjectValue
     * @return
     */
    public static JsonArray RemoveJsonObjectJsonArray(JsonArray jsonObjectJsonArray , String jsonObjectKey, String jsonObjectValue){
        JsonArray resultJsonArray = new JsonArray();
        List<JsonObject> list = new ArrayList<>();
        for (int i = 0; i < jsonObjectJsonArray.size(); i++){
            JsonObject jsonObject = jsonObjectJsonArray.get(i).getAsJsonObject();
            String jsonElement = jsonObject.get(jsonObjectKey).getAsString();
            if (!jsonObjectValue.equals(jsonElement)){
                list.add(jsonObject);
            }
        }
        for (JsonObject jsonObject : list){
            resultJsonArray.add(jsonObject);
        }
        return resultJsonArray;
    }

    public static String JsonObjectToString(Object jsonObject) {
        return new Gson().toJson(jsonObject);
    }

    /**
     * 去重JsonArray,输入的Array里面时Json对象
     * @param jsonObjectJsonArray
     * @param jsonObjectKey
     * @return
     */
    public static JsonArray DeDuplicateJsonObjectJsonArray(JsonArray jsonObjectJsonArray , String jsonObjectKey){
        HashSet<String> hashSet = new HashSet<>();
        JsonArray resultJsonArray = new JsonArray();
        List<JsonObject> list = new ArrayList<>();
        for (int i = 0; i < jsonObjectJsonArray.size(); i++){
            JsonObject jsonObject = jsonObjectJsonArray.get(i).getAsJsonObject();
            String jsonElement = jsonObject.get(jsonObjectKey).getAsString();
            if (!hashSet.contains(jsonElement)){
                list.add(jsonObject);
                hashSet.add(jsonElement);
            }
        }
        for ( JsonObject jsonObject : list){
            resultJsonArray.add(jsonObject);
        }
        return resultJsonArray;
    }

    /**
     * 往列表中添加 多个 主机 元素
     * @param includeJsonArray
     * @param hostHashSet
     * @return
     */
    public static JsonArray JsonArrayAddElements(JsonArray includeJsonArray, HashSet<String> hostHashSet) {
        for(String host: hostHashSet){
            includeJsonArray = JsonArrayAddElement(includeJsonArray, host);
        }
        return includeJsonArray;
    }

    /**
     * 往列表中添加 单个 主机 元素
     * @param includeJsonArray
     * @param host
     * @return
     */
    public static JsonArray JsonArrayAddElement(JsonArray includeJsonArray, String host) {
        HashMap<String, Object> hostHashMap = genHostHashMap(host);
        String includeJsonString = JsonObjectToString(hostHashMap);
        JsonObject includeJsonObject = JsonParser.parseString(includeJsonString).getAsJsonObject();
        includeJsonArray.add(includeJsonObject);
        return includeJsonArray;
    }

    /**
     * 根据host生成主机元素 HashMap
     * @param host
     * @return
     */
    public static HashMap<String, Object> genHostHashMap(String host) {
        HashMap<String,Object> aIncludeHashMap = new HashMap();
        aIncludeHashMap.put("enabled",true);
        aIncludeHashMap.put("host", host);
        aIncludeHashMap.put("protocol","any");
        return aIncludeHashMap;
    }

    /**
     * 批量添加到 Ex Scope
     * @param callbacks
     * @param urlHashSet
     */
    public static void addHostToExScope(IBurpExtenderCallbacks callbacks, HashSet<String> urlHashSet) {
        if(urlHashSet.size()>0){
            for (String url : urlHashSet) {
                try {
                    URL shortUrl = new URL(url);
                    callbacks.excludeFromScope(shortUrl);
                } catch (MalformedURLException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     *  批量添加到 In Scope
     * @param callbacks
     * @param urlHashSet
     */
    public static void addHostToInScope(IBurpExtenderCallbacks callbacks, HashSet<String> urlHashSet) {
        if(urlHashSet.size()>0){
            for (String url : urlHashSet) {
                try {
                    URL shortUrl = new URL(url);
                    callbacks.includeInScope(shortUrl);
                } catch (MalformedURLException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * 获取所有选中的URL
     * @param messages
     * @return
     */
    public static HashSet<String> getUrlSetFromMessages(IHttpRequestResponse[] messages) {
        HashSet<String> urlHashSet = new HashSet<>();
        for (IHttpRequestResponse message : messages) {
            String url = message.getHttpService().toString();
            urlHashSet.add(url);
        }
        return urlHashSet;
    }

    /**
     * 获取所有选中的URL 的 HOSTS
     * @param messages
     * @return
     */
    public static HashSet<String> getHostSetFromMessages(IHttpRequestResponse[] messages) {
        HashSet<String> hostHashSet = new HashSet<>();
        for (IHttpRequestResponse message : messages) {
            String host = message.getHttpService().getHost();
            hostHashSet.add(host);
        }
        return hostHashSet;
    }

    /**
     * 转换Json字符串到hashMap,支持全小写处理
     * @param jsonConfig
     * @return
     */
    public static HashMap<String, String> parseJsonRule2HashMap(String jsonConfig, boolean lowerCase) {
        //忽略空字符串操作
        if (jsonConfig == null || "".equals(jsonConfig)) return null;

        //转换Json对象
        HashMap<String, String> ruleHashMap;
        try {
            ruleHashMap = new Gson().fromJson(jsonConfig, HashMap.class);
        } catch (Exception e) {
            BurpExtender.stderr.println(String.format("[!] converting Json rules Occur Error : %s", e.getMessage()));
            System.out.println(e.getMessage());
            return null;
        }

        if (ruleHashMap == null || ruleHashMap.isEmpty()) return null;

        if (lowerCase){
            //转换为全小写键值对
            HashMap<String, String> addRespHeaderMapLower = new HashMap();
            for (String rule : ruleHashMap.keySet()) {
                addRespHeaderMapLower.put(rule.toLowerCase(), ruleHashMap.get(rule));
            }
            return addRespHeaderMapLower;
        }

        return ruleHashMap;
    }

    /**
     * 从 规则动作 Map 中 取出符合当前 规则 的 动作
     * @param ruleMap
     * @param string
     * @param rule
     * @return
     */
    public static  String getActionFromRuleMap(HashMap<String, String> ruleMap, String rule, String string) {
        String addRespHeaderValue = null;

        //字符串过滤方案 关键字
        if (string.contains(rule)) {
            addRespHeaderValue = ruleMap.get(rule);
            return addRespHeaderValue;
        }

        //正则过滤方案 匹配 原始 key 匹配原始 URL
        try {
            Pattern pattern = Pattern.compile(rule, Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(string);
            if (matcher.find()) addRespHeaderValue = ruleMap.get(rule);
        } catch (Exception e) {
            // 处理正则表达式语法错误的情况
            BurpExtender.stderr.println(String.format("[!] Pattern Compile Rule Occur Error : %s", e.getMessage()));
            System.out.println(e.getMessage());
        }
        return addRespHeaderValue;
    }


    /**
     * 通用字符串分割方法
     * @param string 要分割的字符串
     * @param delimiter 分隔符（可以是正则特殊字符）
     * @return 分割后的列表
     */
    public static List<String> splitString(String string, String delimiter, boolean trim) {
        // 处理null或空输入字符串
        if (string == null || string.isEmpty()) {
            return Collections.emptyList();
        }

        // 处理null或空分隔符
        if (delimiter == null || delimiter.isEmpty()) {
            return Collections.singletonList(string);
        }

        // 执行分割
        String[] parts = string.split(Pattern.quote(delimiter));
        ArrayList<String> result = new ArrayList<>();
        for (String part:parts){
            if (trim){
                String trims = part.trim();
                if (!trims.isEmpty()) result.add(trims);
            } else {
                result.add(part);
            }
        }
        return result;
    }

    private static final Random random = new Random();
    public static <T> T getRandomElement(List<T> list) {
        if (list == null || list.isEmpty()) {
            return null;
        }
        return list.get(random.nextInt(list.size()));
    }

    /**
     * 切割 xxx||xxx 或者 XXX&&xxx的语法格式
     * @param string
     * @return
     */
    public static List<String> splitStringToListWithGrammar(String string) {
        if(string==null || string.isEmpty()){
            return Collections.emptyList();
        }
        List<String> headers = Collections.singletonList(string);
        if (string.contains("&&")){
            headers = splitString(string, "&&", true);
        } else if(string.contains("||")){
            headers = splitString(string, "||", true);
            //选择其中一个即可
            String randomStr = getRandomElement(headers);
            headers = randomStr!=null? Collections.singletonList(randomStr) : headers;
        }
        return headers;
    }
}
