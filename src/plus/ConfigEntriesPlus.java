package plus;

import config.ConfigEntry;

import java.util.List;

public class ConfigEntriesPlus {
    public static void configEntriesAddSome(List<ConfigEntry> configEntries) {
        configEntries.add(new ConfigEntry("MsgChineseTab", "",ConfigEntry.Config_Basic_Variable,true,false,"消息窗口：添加中文转换面板"));
        configEntries.add(new ConfigEntry("MsgInfoTab", "",ConfigEntry.Config_Basic_Variable,false,false,"消息窗口：添加敏感信息面板"));

        //用于指示是否自动加载burp suite的项目配置文件,需要指示Json文件路径,需要支持相对路径,直接在knife下去寻找
        configEntries.add(new ConfigEntry("Auto_Load_Project_Config", "Project.Config.json",ConfigEntry.Config_Basic_Variable,true,false,"高级配置：启动时自动加载项目配置"));
        configEntries.add(new ConfigEntry("Scope_Base_On_SubDomain", "",ConfigEntry.Config_Basic_Variable,true,false,"高级配置：设置Scope时基于子域名操作"));
        configEntries.add(new ConfigEntry("Auto_Save_Scope_Update", "",ConfigEntry.Config_Basic_Variable,true,false,"高级配置：自动保存Scope更新到项目配置"));
        //默认不添加到scope的域名 //需要优化,不能每次都添加
        String defaultExcludeHosts = ".*\\.alicdn\\..*,.*\\.aliyun\\..*,.*\\.baidu\\..*,.*\\.bdstatic\\..*,.*\\.bing\\..*,.*\\.feishu\\..*,.*\\.firefox\\..*,.*\\.google\\..*,.*\\.gstatic\\..*,.*\\.microsoft\\..*,.*\\.mozilla\\..*,.*\\.msftconnecttest\\..*,.*\\.msn\\..*";
        configEntries.add(new ConfigEntry("Add_Exclude_Scope_Hosts",defaultExcludeHosts,ConfigEntry.Config_Basic_Variable,false,false,"高级配置：将目标正则追加到排除Scope"));

        //自动化处理一些常用的属性
        configEntries.add(new ConfigEntry("RemoveReqHeader", "Last-Modified,If-Modified-Since,If-None-Match",ConfigEntry.Config_Basic_Variable,true,false,"无痕修改请求：删除指定的请求头"));


        configEntries.add(new ConfigEntry("RemoveRespHeader", "Last-Modified,If-Modified-Since,If-None-Match",ConfigEntry.Config_Basic_Variable,false,false,"无痕修改响应：删除指定的请求头"));

        configEntries.add(new ConfigEntry("ModRespHeaderByReqMethod", "{\"OPTIONS\":\"Content-Type: application/octet-stream\"}",ConfigEntry.Config_Basic_Variable,true,false,"无痕修改响应：方法名 基于请求方法添加|修改响应头"));
        configEntries.add(new ConfigEntry("ModRespHeaderSetBodyEmpty", "",ConfigEntry.Config_Basic_Variable,false,false,"无痕修改响应：基于请求方法添加|修改响应头时设置响应体为空"));
        configEntries.add(new ConfigEntry("ModRespHeaderByReqURL", "{\"picture\":\"Content-Type: application/octet-stream\"}",ConfigEntry.Config_Basic_Variable,false,false,"无痕修改响应：关键字|正则 基于请求URL添加|修改响应头"));
        configEntries.add(new ConfigEntry("ModRespHeaderByRespHeader", "{\"application/json\":\"Content-Type: text/html;charset=utf-8\"}",ConfigEntry.Config_Basic_Variable,false,false,"无痕修改响应：关键字|正则 基于响应头添加|修改响应头"));
    }

}
