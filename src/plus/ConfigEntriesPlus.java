package plus;

import config.ConfigEntry;

import java.util.List;

public class ConfigEntriesPlus {
    public static String SHOW_MSG_CHINESE_TAB = "显示中文转换面板";
    public static String SHOW_MSG_INFO_TAB = "显示敏感信息面板";
    public static String LOAD_PROJECT_CONFIG_ON_STARTUP = "启动时自动加载项目配置";

    public static String SCOPE_ACTION_BASE_ON_SUBDOMAIN = "基于子域名操作Scope";
    public static String AUTO_SAVE_SCOPE_WHEN_UPDATE = "自动保存Scope更新";
    public static String AUTO_ADD_HOSTS_To_EXCLUDE_SCOPE = "自动添加到排除Scope";

    public static String AUTO_REMOVE_REQ_HEADER = "自动移除请求头";
    public static String AUTO_REMOVE_RESP_HEADER = "自动移除响应头";
    public static String AUTO_MOD_RESP_HEADER_BY_REQ_METHOD = "自动修改响应头_基于请求方法";
    public static String AUTO_MOD_RESP_HEADER_BY_REQ_URL = "自动修改响应头_基于请求URL";
    public static String AUTO_MOD_RESP_HEADER_BY_RESP_HEADER = "自动修改响应头_基于响应头";
    public static String WHEN_MOD_RESP_HEADER_SET_BODY_EMPTY = "修改响应头时自动清空响应体";

    public static String AUTO_ADD_REQ_HEADER = "自动添加请求头";

    public static void configEntriesAddSome(List<ConfigEntry> configEntries) {
        configEntries.add(new ConfigEntry(SHOW_MSG_CHINESE_TAB, "",ConfigEntry.Config_Basic_Variable,true,false,"显示窗口：添加中文转换面板"));
        configEntries.add(new ConfigEntry(SHOW_MSG_INFO_TAB, "",ConfigEntry.Config_Basic_Variable,false,false,"显示窗口：添加敏感信息面板"));
        //用于指示是否自动加载burp suite的项目配置文件,需要指示Json文件路径,需要支持相对路径,直接在knife下去寻找
        configEntries.add(new ConfigEntry(LOAD_PROJECT_CONFIG_ON_STARTUP, "Project.Config.json",ConfigEntry.Config_Basic_Variable,false,false,"高级配置：启动时自动加载项目配置"));
        configEntries.add(new ConfigEntry(SCOPE_ACTION_BASE_ON_SUBDOMAIN, "",ConfigEntry.Config_Basic_Variable,true,false,"高级配置：基于子域名操作Scope"));
        configEntries.add(new ConfigEntry(AUTO_SAVE_SCOPE_WHEN_UPDATE, "",ConfigEntry.Config_Basic_Variable,true,false,"高级配置：自动保存Scope更新"));
        //默认不添加到scope的域名 //需要优化,不能每次都添加
        String defaultExcludeHosts = ".*\\.alicdn\\..*,.*\\.aliyun\\..*,.*\\.baidu\\..*,.*\\.bdstatic\\..*,.*\\.bing\\..*,.*\\.feishu\\..*,.*\\.firefox\\..*,.*\\.google\\..*,.*\\.gstatic\\..*,.*\\.microsoft\\..*,.*\\.mozilla\\..*,.*\\.msftconnecttest\\..*,.*\\.msn\\..*";
        configEntries.add(new ConfigEntry(AUTO_ADD_HOSTS_To_EXCLUDE_SCOPE,defaultExcludeHosts,ConfigEntry.Config_Basic_Variable,false,false,"高级配置：将目标正则追加到排除Scope"));

        //自动化处理一些常用的属性
        configEntries.add(new ConfigEntry(AUTO_REMOVE_REQ_HEADER, "Last-Modified,If-Modified-Since,If-None-Match",ConfigEntry.Config_Basic_Variable,true,false,"无痕修改：自动删除请求头"));
        configEntries.add(new ConfigEntry(AUTO_REMOVE_RESP_HEADER, "Last-Modified,If-Modified-Since,If-None-Match",ConfigEntry.Config_Basic_Variable,false,false,"无痕修改：自动删除响应头"));
        configEntries.add(new ConfigEntry(AUTO_MOD_RESP_HEADER_BY_REQ_METHOD, "{\"OPTIONS\":\"Content-Type: application/octet-stream\"}",ConfigEntry.Config_Basic_Variable,true,false,"无痕修改：基于[请求方法]修改响应头"));
        configEntries.add(new ConfigEntry(AUTO_MOD_RESP_HEADER_BY_REQ_URL, "{\"picture\":\"Content-Type: application/octet-stream\"}",ConfigEntry.Config_Basic_Variable,false,false,"无痕修改：基于[请求URL正则]修改响应头"));
        configEntries.add(new ConfigEntry(AUTO_MOD_RESP_HEADER_BY_RESP_HEADER, "{\"application/json\":\"Content-Type: text/html;charset=utf-8\"}",ConfigEntry.Config_Basic_Variable,false,false,"无痕修改：基于[响应头正则]修改响应头"));
        configEntries.add(new ConfigEntry(WHEN_MOD_RESP_HEADER_SET_BODY_EMPTY, "",ConfigEntry.Config_Basic_Variable,false,false,"无痕修改：清空响应体 防止Burp根据响应内容设置MIME类型"));

        configEntries.add(new ConfigEntry(AUTO_ADD_REQ_HEADER, "{\"X-Forwarded-For&&X-Real-IP\":\"127.0.0.1/32||192.168.0.1/24\"}",ConfigEntry.Config_Basic_Variable,false,false,"无痕修改：自动添加请求头 支持解析CIDR获取随机IP"));
    }
}
