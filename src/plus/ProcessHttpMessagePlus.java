package plus;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.bit4woo.utilbox.burp.HelperPlus;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;

public class ProcessHttpMessagePlus {
    public static void messageRespHandle(IHttpRequestResponse messageInfo) {
        //给 Options 方法的响应 添加 Content-Type: application/octet-stream 用于过滤
        if (AdvScopeUtils.getGuiConfigValue("ModRespHeaderByReqMethod") != null) {
            ModRespHeaderByReqMethod(messageInfo);
        }
        //给没有后缀的图片URL添加响应头,便于过滤筛选
        if (AdvScopeUtils.getGuiConfigValue("ModRespHeaderByReqURL") != null) {
            ModRespHeaderByReqUrl(messageInfo);
        }
        //给Json格式的请求的响应添加响应头,防止被Js过滤
        if (AdvScopeUtils.getGuiConfigValue("ModRespHeaderByRespHeader") != null) {
            ModRespHeaderByRespHeader(messageInfo);
        }
    }

    private static void msgInfoSetResponse(IHttpRequestResponse messageInfo, String ModRespHeaderLine) {
        //进行实际处理
        if(ModRespHeaderLine != null && ModRespHeaderLine.contains(":")) {
            IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
            HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());

            String respHeaderName = ModRespHeaderLine.split(":", 2)[0].trim();
            String respHeaderValue = ModRespHeaderLine.split(":", 2)[1].trim();

            byte[] resp = helperPlus.addOrUpdateHeader(false, messageInfo.getResponse(), respHeaderName, respHeaderValue);

            // 修改响应体为空, 防止程序根据响应内容设置MIME类型
            if (AdvScopeUtils.getGuiConfigValue("ModRespHeaderSetBodyEmpty") != null) {
                resp = helperPlus.UpdateBody(false, resp, "".getBytes(StandardCharsets.UTF_8));
            }

            messageInfo.setResponse(resp);
            messageInfo.setComment("add resp header"); //在logger中没有显示comment
        }
    }

    private static void ModRespHeaderByReqMethod(IHttpRequestResponse messageInfo){
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        // 获取 请求方法
        String curMethod = helperPlus.getMethod(messageInfo).toLowerCase();

        //获取对应的Json格式规则  {"OPTIONS":"Content-Type: application/octet-stream"}
        String ModRespHeaderConfig = AdvScopeUtils.getGuiConfigValue("ModRespHeaderByReqMethod");
        //解析Json格式的规则
        HashMap<String, String> ModRespHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(ModRespHeaderConfig, true);

        if(ModRespHeaderRuleMap != null && ModRespHeaderRuleMap.containsKey(curMethod)) {
            //获取需要添加的响应头 每个方法只支持一种动作,更多的动作建议使用其他类型的修改方式
            String ModRespHeaderLine = ModRespHeaderRuleMap.get(curMethod);
            msgInfoSetResponse(messageInfo, ModRespHeaderLine);
        }
    }

    private static void ModRespHeaderByReqUrl(IHttpRequestResponse messageInfo){
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        // 获取 请求URL
        String curUrl = helperPlus.getFullURL(messageInfo).toString().toLowerCase();

        //获取对应的Json格式规则 // {"www.baidu.com":"Content-Type: application/octet-stream"}
        String ModRespHeaderConfig = AdvScopeUtils.getGuiConfigValue("ModRespHeaderByReqURL");
        //解析Json格式的规则
        HashMap<String, String> ModRespHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(ModRespHeaderConfig, true);

        if (ModRespHeaderRuleMap == null) return;

        //循环 获取需要添加的响应头 并 设置响应头信息
        for (String rule:ModRespHeaderRuleMap.keySet()) {
            //获取需要添加的响应头 每个URL支持多种动作规则
            String ModRespHeaderLine = UtilsPlus.getActionFromRuleMap(ModRespHeaderRuleMap, rule, curUrl);
            msgInfoSetResponse(messageInfo, ModRespHeaderLine);
        }
    }

    private static void ModRespHeaderByRespHeader(IHttpRequestResponse messageInfo){
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
        HelperPlus helperPlus = new HelperPlus(callbacks.getHelpers());
        //获取对应的Json格式规则 // {"www.baidu.com":"Content-Type: application/octet-stream"}
        String ModRespHeaderConfig = AdvScopeUtils.getGuiConfigValue("ModRespHeaderByRespHeader");
        //解析Json格式的规则
        HashMap<String, String> ModRespHeaderRuleMap = UtilsPlus.parseJsonRule2HashMap(ModRespHeaderConfig,false);
        if (ModRespHeaderRuleMap == null) return;

        //获取响应头
        List<String> responseHeaders = helperPlus.getHeaderList(false, messageInfo);
        for (String rule:ModRespHeaderRuleMap.keySet()) {
            for (String responseHeader:responseHeaders){
                //获取需要添加的响应头 每个规则只处理一种响应头，支持多种动作规则
                String ModRespHeaderLine = UtilsPlus.getActionFromRuleMap(ModRespHeaderRuleMap, rule, responseHeader);
                if(ModRespHeaderLine!=null){
                    msgInfoSetResponse(messageInfo, ModRespHeaderLine);
                    break; 	//匹配成功后就进行下一条规则的匹配
                }
            }
        }
    }
}
