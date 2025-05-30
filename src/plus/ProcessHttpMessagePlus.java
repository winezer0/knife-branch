package plus;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.bit4woo.utilbox.burp.HelperPlus;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;

import static plus.RandomIPUtils.splitStrToListWithGrammarAndRender;
import static plus.UtilsPlus.splitStringToListWithGrammar;

public class ProcessHttpMessagePlus {
    public static void messageRespHandleTraceless(IHttpRequestResponse messageInfo) {
        //删除指定响应头
        //获取对应的格式规则 "Last-Modified,If-Modified-Since,If-None-Match"
        String removeRespHeaderConfig = AdvScopeUtils.getGuiConfigValue(ConfigEntriesPlus.AUTO_REMOVE_RESP_HEADER);
        if (removeRespHeaderConfig != null) {
            removeRespHeader(messageInfo, removeRespHeaderConfig);
        }

        //给 Options 方法的响应 添加 Content-Type: application/octet-stream 用于过滤
        //获取对应的Json格式规则  {"OPTIONS":"Content-Type: application/octet-stream"}
        String modRespHeaderByReqMethodConfig = AdvScopeUtils.getGuiConfigValue(ConfigEntriesPlus.AUTO_MOD_RESP_HEADER_BY_REQ_METHOD);
        if (modRespHeaderByReqMethodConfig != null) {
            modRespHeaderByReqMethod(messageInfo, modRespHeaderByReqMethodConfig);
        }

        //给没有后缀的图片URL添加响应头,便于过滤筛选
        //获取对应的Json格式规则 // {"www.baidu.com":"Content-Type: application/octet-stream"}
        String modRespHeaderByReqUrlConfig = AdvScopeUtils.getGuiConfigValue(ConfigEntriesPlus.AUTO_MOD_RESP_HEADER_BY_REQ_URL);
        if (modRespHeaderByReqUrlConfig != null) {
            modRespHeaderByReqUrl(messageInfo, modRespHeaderByReqUrlConfig);
        }

        //给Json格式的请求的响应添加响应头,防止被Js过滤
        //获取对应的Json格式规则 // {"www.baidu.com":"Content-Type: application/octet-stream"}
        String modRespHeaderByRespHeaderConfig = AdvScopeUtils.getGuiConfigValue(ConfigEntriesPlus.AUTO_MOD_RESP_HEADER_BY_RESP_HEADER);
        if (modRespHeaderByRespHeaderConfig != null) {
            modRespHeaderByRespHeader(messageInfo, modRespHeaderByRespHeaderConfig);
        }

    }

    private static void modRespHeaderByReqMethod(IHttpRequestResponse messageInfo, String modRespHeaderByReqMethodConfig){
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        // 获取 请求方法
        String curMethod = helperPlus.getMethod(messageInfo).toLowerCase();
        //解析Json格式的规则
        HashMap<String, String> modRespHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(modRespHeaderByReqMethodConfig, false);

        if(modRespHeaderRuleMap != null && modRespHeaderRuleMap.containsKey(curMethod)) {
            //获取需要添加的响应头 每个方法只支持一种动作,更多的动作建议使用其他类型的修改方式
            String newRespHeaderLine = modRespHeaderRuleMap.get(curMethod);
            //修改响应内容
            byte[] resp = messageInfo.getResponse();
            if (resp.length > 0){
                //添加响应头
                if(newRespHeaderLine != null && newRespHeaderLine.contains(":")){
                    resp = helperPlus.addOrUpdateHeader(false, resp, newRespHeaderLine);
                }

                 // 修改响应体为空, 防止程序根据响应内容设置MIME类型
                if (AdvScopeUtils.getGuiConfigValue(ConfigEntriesPlus.WHEN_MOD_RESP_HEADER_SET_BODY_EMPTY) != null){
                    resp = helperPlus.UpdateBody(false, resp, "".getBytes(StandardCharsets.UTF_8));
                }

                //设置新的内容
                messageInfo.setResponse(resp);
                messageInfo.setComment("modRespHeaderByReqMethod");
            }
        }
    }

    private static void modRespHeaderByReqUrl(IHttpRequestResponse messageInfo, String modRespHeaderByReqUrlConfig){
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        // 获取 请求URL
        String curUrl = helperPlus.getFullURL(messageInfo).toString().toLowerCase();

        //解析Json格式的规则
        HashMap<String, String> modRespHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(modRespHeaderByReqUrlConfig, false);

        if (modRespHeaderRuleMap != null  && modRespHeaderRuleMap.size() > 0 ){
            //循环 获取需要添加的响应头 并 设置响应头信息
            byte[] resp = messageInfo.getResponse();
            if (resp.length > 0){
                //添加响应头
                for (String rule:modRespHeaderRuleMap.keySet()) {
                    //获取需要添加的响应头 每个URL支持多种动作规则
                    String newRespHeaderLine = UtilsPlus.getActionFromRuleMap(modRespHeaderRuleMap, rule, curUrl);
                    if(newRespHeaderLine != null && newRespHeaderLine.contains(":")){
                        resp = helperPlus.addOrUpdateHeader(false, resp, newRespHeaderLine);
                    }
                }

                // 修改响应体为空, 防止程序根据响应内容设置MIME类型
                if (AdvScopeUtils.getGuiConfigValue(ConfigEntriesPlus.WHEN_MOD_RESP_HEADER_SET_BODY_EMPTY) != null){
                    resp = helperPlus.UpdateBody(false, resp, "".getBytes(StandardCharsets.UTF_8));
                }

                //设置新的内容
                messageInfo.setResponse(resp);
                messageInfo.setComment("modRespHeaderByReqUrl");
            }
        }
    }

    private static void modRespHeaderByRespHeader(IHttpRequestResponse messageInfo, String modRespHeaderByRespHeaderConfig){
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        //解析Json格式的规则
        HashMap<String, String> modRespHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(modRespHeaderByRespHeaderConfig,false);
        //进行规则处理
        if (modRespHeaderRuleMap != null && modRespHeaderRuleMap.size() > 0){
            //获取响应头
            List<String> responseHeaders = helperPlus.getHeaderList(false, messageInfo);
            byte[] resp = messageInfo.getResponse();
            if (resp.length > 0){
                //添加响应头
                for (String rule:modRespHeaderRuleMap.keySet()) {
                    for (String responseHeader:responseHeaders){
                        //获取需要添加的响应头 每个规则只处理一种响应头，支持多种动作规则
                        String newRespHeaderLine = UtilsPlus.getActionFromRuleMap(modRespHeaderRuleMap, rule, responseHeader);
                        if(newRespHeaderLine != null && newRespHeaderLine.contains(":")){
                            resp = helperPlus.addOrUpdateHeader(false, resp, newRespHeaderLine);
                            break; 	//匹配成功后就进行下一条规则的匹配
                        }
                    }
                }

                // 修改响应体为空, 防止程序根据响应内容设置MIME类型
                if (AdvScopeUtils.getGuiConfigValue(ConfigEntriesPlus.WHEN_MOD_RESP_HEADER_SET_BODY_EMPTY) != null){
                    resp = helperPlus.UpdateBody(false, resp, "".getBytes(StandardCharsets.UTF_8));
                }
                
                //设置新的内容
                messageInfo.setResponse(resp);
                messageInfo.setComment("modRespHeaderByRespHeader");
            }
        }
    }

    private static void removeRespHeader(IHttpRequestResponse messageInfo, String removeRespHeaderConfig){
        // 删除无用的请求头信息
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());

        String[] headers = removeRespHeaderConfig.split(",");
        if (headers.length > 0){
            byte[] resp = messageInfo.getResponse();
            int rawLength = resp.length;
            if (rawLength > 0){
                //循环删除响应头
                for (String header : headers) {
                    if(!header.trim().isEmpty())
                        resp = helperPlus.removeHeader(false, resp, header.trim());
                }
                if (resp.length >0 && rawLength != resp.length){
                    messageInfo.setResponse(resp);
                    messageInfo.setComment("removeRespHeader");
                }
            }
        }
    }

    public static void messageReqHandleTraceless(IHttpRequestResponse messageInfo) {
        // 删除无用的请求头信息
        //获取对应的格式规则 "Last-Modified,If-Modified-Since,If-None-Match"
        String removeReqHeaderConfig = AdvScopeUtils.getGuiConfigValue(ConfigEntriesPlus.AUTO_REMOVE_REQ_HEADER);
        if (removeReqHeaderConfig != null) {
            removeReqHeader(messageInfo, removeReqHeaderConfig);
        }

        String addReqHeaderConfig = AdvScopeUtils.getGuiConfigValue(ConfigEntriesPlus.AUTO_ADD_REQ_HEADER);
        if (addReqHeaderConfig != null) {
            addReqHeader(messageInfo, addReqHeaderConfig);
        }
    }

    private static void removeReqHeader(IHttpRequestResponse messageInfo, String removeReqHeaderConfig){
        // 删除无用的请求头信息
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());

        String[] headers = removeReqHeaderConfig.split(",");
        if (headers.length > 0){
            byte[] req = messageInfo.getRequest();
            int rawLength = req.length;
            if(rawLength > 0){
                //循环删除请求头
                for (String header : headers) {
                    if(!header.trim().isEmpty())
                        req = helperPlus.removeHeader(true, req, header.trim());
                }
                if (req.length > 0 && rawLength != req.length){
                    messageInfo.setRequest(req);
                    messageInfo.setComment("removeReqHeader");
                }
            }
        }
    }

    private static void addReqHeader(IHttpRequestResponse messageInfo, String addReqHeaderConfig) {
        //添加自定义的请求头配置 要支持随机IP属性
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        //解析Json格式的规则
        HashMap<String, String> addReqHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(addReqHeaderConfig, false);
        if(addReqHeaderRuleMap != null && addReqHeaderRuleMap.size() > 0) {
            //循环添加修改请求头
            byte[] reqBytes = messageInfo.getRequest();
            if (reqBytes.length > 0){
                //添加响应头
                for (String headerName:addReqHeaderRuleMap.keySet()) {
                    //获取需要添加的请求头 每个请求支持多种动作规则
                    String headerValue = addReqHeaderRuleMap.get(headerName);
                    //转换请求头格式为列表,以支持 XFF|X-REAL IP 这种多个头但是要相同值的情况
                    List<String> headerList = splitStringToListWithGrammar(headerName);
                    //转换结果格式 以支持 多个IP随机的格式
                    List<String> valueList = splitStrToListWithGrammarAndRender(headerValue);
                    for (String header: headerList){
                        for (String value: valueList){
                            reqBytes = helperPlus.addOrUpdateHeader(true, reqBytes, header, value);
                        }
                    }
                }
                //设置新的内容
                messageInfo.setRequest(reqBytes);
                messageInfo.setComment("addReqHeader");
            }
        }
    }
}
