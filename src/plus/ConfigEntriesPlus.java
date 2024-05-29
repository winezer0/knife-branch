package plus;

import config.ConfigEntry;

import java.util.List;

public class ConfigEntriesPlus {
    public static void configEntriesAddSome(List<ConfigEntry> configEntries) {
        //用于指示是否自动加载burp suite的项目配置文件,需要指示Json文件路径,需要支持相对路径,直接在knife下去寻找
        configEntries.add(new ConfigEntry("Auto_Load_Project_Config", "Project.Config.json",ConfigEntry.Config_Basic_Variable,true,false,"高级配置：启动时自动加载项目配置"));
        configEntries.add(new ConfigEntry("Scope_Base_On_SubDomain", "",ConfigEntry.Config_Basic_Variable,true,false,"高级配置：设置Scope时基于子域名操作"));
        configEntries.add(new ConfigEntry("Auto_Save_Scope_Update", "",ConfigEntry.Config_Basic_Variable,true,false,"高级配置：自动保存Scope更新到项目配置"));
        //默认不添加到scope的域名 //需要优化,不能每次都添加
        String defaultExcludeHosts = ".*\\.baidu\\.com,.*\\.bdstatic\\.com,.*\\.msn\\.cn,.*\\.microsoft\\.com,.*\\.bing\\.com,.*\\.google\\.com,.*\\.firefox\\.com";
        configEntries.add(new ConfigEntry("Add_Exclude_Scope_Hosts",defaultExcludeHosts,ConfigEntry.Config_Basic_Variable,false,false,"高级配置：将目标正则追加到排除Scope"));

        //自动化处理一些常用的属性
        configEntries.add(new ConfigEntry("AddRespHeaderByReqMethod", "{\"OPTIONS\":\"Content-Type: application/octet-stream\"}",ConfigEntry.Config_Basic_Variable,true,false,"修改响应：方法名 基于请求方法添加响应头"));
        configEntries.add(new ConfigEntry("AddRespHeaderByReqURL", "{\"picture\":\"Content-Type: application/octet-stream\"}",ConfigEntry.Config_Basic_Variable,false,false,"修改响应：关键字|正则 基于请求URL添加响应头"));
        configEntries.add(new ConfigEntry("AddRespHeaderByRespHeader", "{\"application/json\":\"Content-Type: text/html;charset=utf-8\"}",ConfigEntry.Config_Basic_Variable,false,false,"修改响应：关键字|正则 基于响应头添加响应头"));
        configEntries.add(new ConfigEntry("AddRespHeaderSetBodyEmpty", "",ConfigEntry.Config_Basic_Variable,false,false,"修改响应：添加响应头时设置响应体为空"));
    }


}
