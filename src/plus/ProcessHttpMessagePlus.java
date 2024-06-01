package plus;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.bit4woo.utilbox.burp.HelperPlus;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;

public class ProcessHttpMessagePlus {
    public static void messageRespHandleTraceless(IHttpRequestResponse messageInfo) {
        //给 Options 方法的响应 添加 Content-Type: application/octet-stream 用于过滤
        if (AdvScopeUtils.getGuiConfigValue("ModRespHeaderByReqMethod") != null) {
            modRespHeaderByReqMethod(messageInfo);
        }
        //给没有后缀的图片URL添加响应头,便于过滤筛选
        if (AdvScopeUtils.getGuiConfigValue("ModRespHeaderByReqURL") != null) {
            modRespHeaderByReqUrl(messageInfo);
        }
        //给Json格式的请求的响应添加响应头,防止被Js过滤
        if (AdvScopeUtils.getGuiConfigValue("ModRespHeaderByRespHeader") != null) {
            modRespHeaderByRespHeader(messageInfo);
        }
    }

    private static void modRespHeaderByReqMethod(IHttpRequestResponse messageInfo){
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        // 获取 请求方法
        String curMethod = helperPlus.getMethod(messageInfo).toLowerCase();

        //获取对应的Json格式规则  {"OPTIONS":"Content-Type: application/octet-stream"}
        String ModRespHeaderConfig = AdvScopeUtils.getGuiConfigValue("ModRespHeaderByReqMethod");
        //解析Json格式的规则
        HashMap<String, String> modRespHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(ModRespHeaderConfig, true);

        if(modRespHeaderRuleMap != null && modRespHeaderRuleMap.containsKey(curMethod)) {
            //获取需要添加的响应头 每个方法只支持一种动作,更多的动作建议使用其他类型的修改方式
            String newRespHeaderLine = modRespHeaderRuleMap.get(curMethod);
            //修改响应内容
            byte[] resp = messageInfo.getResponse();
            //添加响应头
            if(newRespHeaderLine != null && newRespHeaderLine.contains(":")){
                resp = helperPlus.addOrUpdateHeader(false, resp, newRespHeaderLine);
            }

            // 修改响应体为空, 防止程序根据响应内容设置MIME类型
            if (AdvScopeUtils.getGuiConfigValue("ModRespHeaderSetBodyEmpty") != null){
                resp = helperPlus.UpdateBody(false, resp, "".getBytes(StandardCharsets.UTF_8));
            }

            //设置新的内容
            messageInfo.setResponse(resp);
            messageInfo.setComment("modRespHeaderByReqMethod"); //在logger中没有显示comment
        }
    }

    private static void modRespHeaderByReqUrl(IHttpRequestResponse messageInfo){
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        // 获取 请求URL
        String curUrl = helperPlus.getFullURL(messageInfo).toString().toLowerCase();

        //获取对应的Json格式规则 // {"www.baidu.com":"Content-Type: application/octet-stream"}
        String ModRespHeaderConfig = AdvScopeUtils.getGuiConfigValue("ModRespHeaderByReqURL");
        //解析Json格式的规则
        HashMap<String, String> modRespHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(ModRespHeaderConfig, true);

        if (modRespHeaderRuleMap != null  && modRespHeaderRuleMap.size() > 0 ){
            //循环 获取需要添加的响应头 并 设置响应头信息
            byte[] resp = messageInfo.getResponse();
            //添加响应头
            for (String rule:modRespHeaderRuleMap.keySet()) {
                //获取需要添加的响应头 每个URL支持多种动作规则
                String newRespHeaderLine = UtilsPlus.getActionFromRuleMap(modRespHeaderRuleMap, rule, curUrl);
                if(newRespHeaderLine != null && newRespHeaderLine.contains(":"))
                    resp = helperPlus.addOrUpdateHeader(false, resp, newRespHeaderLine);
            }
            //设置新的内容
            messageInfo.setResponse(resp);
            messageInfo.setComment("modRespHeaderByReqUrl"); //在logger中没有显示comment
        }
    }

    private static void modRespHeaderByRespHeader(IHttpRequestResponse messageInfo){
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        //获取对应的Json格式规则 // {"www.baidu.com":"Content-Type: application/octet-stream"}
        String ModRespHeaderConfig = AdvScopeUtils.getGuiConfigValue("ModRespHeaderByRespHeader");
        //解析Json格式的规则
        HashMap<String, String> modRespHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(ModRespHeaderConfig,false);
        //进行规则处理
        if (modRespHeaderRuleMap != null && modRespHeaderRuleMap.size() > 0){
            //获取响应头
            List<String> responseHeaders = helperPlus.getHeaderList(false, messageInfo);
            byte[] resp = messageInfo.getResponse();
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
            //设置新的内容
            messageInfo.setResponse(resp);
            messageInfo.setComment("modRespHeaderByRespHeader"); //在logger中没有显示comment
        }
    }

    public static void messageReqHandleTraceless(IHttpRequestResponse messageInfo) {
        // 删除无用的请求头信息
        if (AdvScopeUtils.getGuiConfigValue("RemoveReqHeader") != null) {
            removeReqHeader(messageInfo);
        }
    }

    private static void removeReqHeader(IHttpRequestResponse messageInfo){
        // 删除无用的请求头信息
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        //获取对应的格式规则 "Last-Modified,If-Modified-Since,If-None-Match"
        String removeReqHeaderConfig = AdvScopeUtils.getGuiConfigValue("RemoveReqHeader");

        if (removeReqHeaderConfig != null){
            String[] headers = removeReqHeaderConfig.split(",");
            if (headers.length > 0){
                byte[] req = messageInfo.getRequest();
                //循环删除请求头
                for (String header : headers) {
                    req = helperPlus.removeHeader(true, req, header.trim());
                }
                messageInfo.setRequest(req);
                messageInfo.setComment("remove req header"); //在logger中没有显示comment
            }
        }
    }

}
