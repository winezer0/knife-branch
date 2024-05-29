package plus;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.bit4woo.utilbox.burp.HelperPlus;

import java.util.HashMap;
import java.util.List;

public class ProcessHttpMessagePlus {
    public static void messageRespHandle(IHttpRequestResponse messageInfo) {
        //给 Options 方法的响应 添加 Content-Type: application/octet-stream 用于过滤
        if (AdvScopeUtils.getGuiConfigValue("AddRespHeaderByReqMethod") != null) {
            ProcessHttpMessagePlus.AddRespHeaderByReqMethod(messageInfo);
        }
        //给没有后缀的图片URL添加响应头,便于过滤筛选
        if (AdvScopeUtils.getGuiConfigValue("AddRespHeaderByReqURL") != null) {
            ProcessHttpMessagePlus.AddRespHeaderByReqUrl(messageInfo);
        }
        //给Json格式的请求的响应添加响应头,防止被Js过滤
        if (AdvScopeUtils.getGuiConfigValue("AddRespHeaderByRespHeader") != null) {
            ProcessHttpMessagePlus.AddRespHeaderByRespHeader(messageInfo);
        }
    }


    public static void msgInfoSetResponse(IHttpRequestResponse messageInfo, String addRespHeaderLine) {
        //进行实际处理
        if(addRespHeaderLine != null){
            IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
            HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
            String respHeaderName = "Content-Type";
            String respHeaderValue = "application/octet-stream";
            if (addRespHeaderLine.contains(":")) {
                respHeaderName = addRespHeaderLine.split(":", 2)[0].trim();
                respHeaderValue = addRespHeaderLine.split(":", 2)[1].trim();
            }
            byte[] resp = helperPlus.addOrUpdateHeader(false, messageInfo.getResponse(), respHeaderName, respHeaderValue);
            messageInfo.setResponse(resp);
            messageInfo.setComment("Resp Add Header By Knife"); //在logger中没有显示comment
        }
    }

    public static void AddRespHeaderByReqMethod(IHttpRequestResponse messageInfo){
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        // 获取 请求方法
        String curMethod = helperPlus.getMethod(messageInfo).toLowerCase();

        //获取对应的Json格式规则  {"OPTIONS":"Content-Type: application/octet-stream"}
        String addRespHeaderConfig = AdvScopeUtils.getGuiConfigValue("AddRespHeaderByReqMethod");
        //解析Json格式的规则
        HashMap<String, String> addRespHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(addRespHeaderConfig, true);

        if(addRespHeaderRuleMap != null && addRespHeaderRuleMap.containsKey(curMethod)) {
            //获取需要添加的响应头 每个方法只支持一种动作,更多的动作建议使用其他类型的修改方式
            String addRespHeaderLine = addRespHeaderRuleMap.get(curMethod);
            msgInfoSetResponse(messageInfo, addRespHeaderLine);
        }
    }

    public static void AddRespHeaderByReqUrl(IHttpRequestResponse messageInfo){
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        // 获取 请求URL
        String curUrl = helperPlus.getFullURL(messageInfo).toString().toLowerCase();

        //获取对应的Json格式规则 // {"www.baidu.com":"Content-Type: application/octet-stream"}
        String addRespHeaderConfig = AdvScopeUtils.getGuiConfigValue("AddRespHeaderByReqURL");
        //解析Json格式的规则
        HashMap<String, String> addRespHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(addRespHeaderConfig, true);

        if (addRespHeaderRuleMap == null) return;

        //循环 获取需要添加的响应头 并 设置响应头信息
        for (String rule:addRespHeaderRuleMap.keySet()) {
            //获取需要添加的响应头 每个URL支持多种动作规则
            String addRespHeaderLine = UtilsPlus.getActionFromRuleMap(addRespHeaderRuleMap, rule, curUrl);
            msgInfoSetResponse(messageInfo, addRespHeaderLine);
        }
    }

    public static void AddRespHeaderByRespHeader(IHttpRequestResponse messageInfo){
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        //获取对应的Json格式规则 // {"www.baidu.com":"Content-Type: application/octet-stream"}
        String addRespHeaderConfig = AdvScopeUtils.getGuiConfigValue("AddRespHeaderByRespHeader");
        //解析Json格式的规则
        HashMap<String, String> addRespHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(addRespHeaderConfig,false);
        if (addRespHeaderRuleMap == null) return;

        //获取响应头
        List<String> responseHeaders = helperPlus.getHeaderList(false, messageInfo);
        for (String rule:addRespHeaderRuleMap.keySet()) {
            for (String responseHeader:responseHeaders){
                //获取需要添加的响应头 每个规则只处理一种响应头，支持多种动作规则
                String addRespHeaderLine = UtilsPlus.getActionFromRuleMap(addRespHeaderRuleMap, rule, responseHeader);
                if(addRespHeaderLine!=null){
                    msgInfoSetResponse(messageInfo, addRespHeaderLine);
                    break; 	//匹配成功后就进行下一条规则的匹配
                }
            }
        }
    }
}
