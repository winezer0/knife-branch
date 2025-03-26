package plus;

import burp.IBurpExtenderCallbacks;
import com.bit4woo.utilbox.utils.CharsetUtils;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import config.GUI;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

public class AdvScopeUtils {
    /**
     * 简化配置文件调用函数
     * @param key
     * @return
     */
    public static String getGuiConfigValue(String key) {
        return GUI.getConfigTableModel().getConfigValueByKey(key);
    }

    /**
     * 获取当前配置文件对象
     * @param callbacks
     * @return
     */
    public static JsonObject getConfigObject(IBurpExtenderCallbacks callbacks) {
        JsonObject jsonObject = JsonParser.parseString(callbacks.saveConfigAsJson()).getAsJsonObject();
        return jsonObject;
    }

    /**
     * 获取Scope配置对象
     * @param configObject
     * @return
     */
    public static JsonObject getScopeObject(JsonObject configObject) {
        return configObject.get("target").getAsJsonObject().get("scope").getAsJsonObject();
    }

    /**
     * 判断当前是否是高级scope设置模式
     * @param configObject
     */
    public static boolean isAdvScopeMode(JsonObject configObject){
        return getScopeObject(configObject).get("advanced_mode").getAsBoolean();
    }

    /**
     * 判断当前是否是高级scope设置模式
     * @param callbacks
     */
    public static boolean isAdvScopeMode(IBurpExtenderCallbacks callbacks){
        return isAdvScopeMode(getConfigObject(callbacks));
    }

    /**
     * 清空所有Scope内容
     * @param callbacks
     */
    public static void ClearAllScopeAdv(IBurpExtenderCallbacks callbacks) {
        // 1、读取当前的配置文件
        JsonObject jsonObject = getConfigObject(callbacks);

        //生成IncludeJson元素 清空元素
        getScopeObject(jsonObject).add("include",new JsonArray());
        getScopeObject(jsonObject).add("exclude",new JsonArray());

        //加载生成的Json配置到应用
        callbacks.loadConfigFromJson(UtilsPlus.JsonObjectToString(jsonObject));

        //根据用户设置,保存当前内存的配置到Json配置到文件
        autoSaveScopeUpdate(callbacks);
    }

    /**
     * 添加主机名到包含列表
     * @param callbacks
     * @param hostHashSet
     */
    public static void addHostToInScopeAdv(IBurpExtenderCallbacks callbacks, HashSet<String> hostHashSet) {
        //不处理没有获取到host的情况
        if(hostHashSet.size()>0) {
            // 1、读取当前的配置文件
            JsonObject projectConfigJsonObject = getConfigObject(callbacks);
            JsonObject scopeJsonObject = getScopeObject(projectConfigJsonObject);

            // 2、设置高级模式
            scopeJsonObject.addProperty("advanced_mode", true);

            //获取 include元素列表 JsonArray
            JsonArray includeJsonArray = scopeJsonObject.get("include").getAsJsonArray();

            //往 include元素列表 这中添加元素
            includeJsonArray = UtilsPlus.JsonArrayAddElements(includeJsonArray, hostHashSet);

            if (includeJsonArray.size() > 1){
                //删除包含列表里面.*的对象不然没有意义
                includeJsonArray = UtilsPlus.RemoveJsonObjectJsonArray(includeJsonArray, "host", ".*");
                //去重Json对象的包含列表
                includeJsonArray = UtilsPlus.DeDuplicateJsonObjectJsonArray(includeJsonArray, "host");
            }

            //将修改后的数据保存到json里面
            scopeJsonObject.add("include", includeJsonArray);

            //去除排除列表中和包含列表相同的数据
            JsonArray excludeJsonArray = scopeJsonObject.get("exclude").getAsJsonArray();
            if (excludeJsonArray.size() > 0) {
                JsonArray removeJsonObjectJsonArray = UtilsPlus.RemoveJsonObjectJsonArray(excludeJsonArray, "host", hostHashSet);
                scopeJsonObject.add("exclude", removeJsonObjectJsonArray);
            }

            //加载生成的Json配置到应用
            callbacks.loadConfigFromJson(UtilsPlus.JsonObjectToString(projectConfigJsonObject));

            //根据用户设置,保存当前内存的配置到Json配置到文件
            autoSaveScopeUpdate(callbacks);
        }
    }

    /**
     * 当 In scope 列表为空时，添加 .*
     * @param scopeJsonObject
     */
    public static void scopeJsonObjectAddDotHost(JsonObject scopeJsonObject) {
        //includeJsonArray 内存地址改变，需要重新获取,
        JsonArray includeJsonArray = scopeJsonObject.get("include").getAsJsonArray();
        if (includeJsonArray.size() < 1){
            //设置include Scope为.*
            includeJsonArray =  UtilsPlus.JsonArrayAddElement(includeJsonArray, ".*");
            //将修改后的数据保存到json里面
            scopeJsonObject.add("include", includeJsonArray);
        }
    }

    /**
     * 添加主机名到排除列表
     * @param callbacks
     * @param hostHashSet
     */
    public static void addHostToExScopeAdv(IBurpExtenderCallbacks callbacks, HashSet<String> hostHashSet) {
        //不处理没有获取到host的情况
        if(hostHashSet.size()>0){
            // 1、读取当前的配置文件
            JsonObject projectConfigJsonObject = getConfigObject(callbacks);
            JsonObject scopeJsonObject = getScopeObject(projectConfigJsonObject);
            //设置高级模式
            scopeJsonObject.addProperty("advanced_mode",true);

            //生成ExcludeJson元素 并循环添加到json对象中
            JsonArray excludeJsonArray = scopeJsonObject.get("exclude").getAsJsonArray();
            excludeJsonArray = UtilsPlus.JsonArrayAddElements(excludeJsonArray, hostHashSet);

            //去重Json对象的排除列表
            JsonArray removeDuplicateJsonArray = UtilsPlus.DeDuplicateJsonObjectJsonArray(excludeJsonArray,"host");
            scopeJsonObject.add("exclude",removeDuplicateJsonArray);

            //判断包含列表是否存在和排除列表相同的数据
            JsonArray includeJsonArray = scopeJsonObject.get("include").getAsJsonArray();
            if(includeJsonArray.size()>0){
                //去除包含列表中和排除列表相同的数据
                JsonArray removeJsonObjectJsonArray = UtilsPlus.RemoveJsonObjectJsonArray(includeJsonArray,"host",hostHashSet);
                scopeJsonObject.add("include",removeJsonObjectJsonArray);
            }

            //如果include Scope为空需要修改为.* //不然全部删除 //includeJsonArray 内存地址改变，需要重新获取,
            includeJsonArray = scopeJsonObject.get("include").getAsJsonArray();
            if (includeJsonArray.size() < 1){
                //设置include Scope为.*
                includeJsonArray =  UtilsPlus.JsonArrayAddElement(includeJsonArray, ".*");
                //将修改后的数据保存到json里面
                scopeJsonObject.add("include", includeJsonArray);
            }

            //加载Json文件
            String jsonObjectString = UtilsPlus.JsonObjectToString(projectConfigJsonObject);
            callbacks.loadConfigFromJson(jsonObjectString);

            //根据用户设置,保存当前内存的配置到Json配置到文件
            autoSaveScopeUpdate(callbacks);
        }
    }

    /**
     * 从Json文件中自动加载项目配置,可能会生成新文件,追加表单配置
     * @param callbacks
     */
    public static void autoLoadProjectConfig(IBurpExtenderCallbacks callbacks) {
        String configPath = getGuiConfigValue(ConfigEntriesPlus.LOAD_PROJECT_CONFIG_ON_STARTUP);
        if (configPath!=null){
            //自动加载burp项目Json的配置 // Project.Config.json 支持相对(BurpSuitePro)和绝对路径
            // 判断功能是否打开|功能打开后进行加载操作
            File file = new File(configPath);
            try{
                if (!file.exists() && !file.isDirectory()){
                    //配置文件不存在时,自动根据当前的配置生成
                    String configAsJson = callbacks.saveConfigAsJson();
                    FileUtils.write(file, configAsJson, CharsetUtils.getSystemCharSet());
                } else {
                    // 配置文件存在时,加载启动时加载项目配置文件
                    callbacks.loadConfigFromJson(FileUtils.readFileToString(file, CharsetUtils.getSystemCharSet()));
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 保存当前的项目配置Json文件中,会覆盖旧文件
     * @param callbacks
     */
    public static void autoSaveProjectConfig(IBurpExtenderCallbacks callbacks) {
        String configPath  = getGuiConfigValue(ConfigEntriesPlus.LOAD_PROJECT_CONFIG_ON_STARTUP);
        if(configPath != null){
            File file = new File(configPath);
            try{
                //将当前的配置存储到配置文件
                FileUtils.write(file, callbacks.saveConfigAsJson(), CharsetUtils.getSystemCharSet());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 当前的项目配置修改到Json文件中
     * @param callbacks
     */
    public static void autoSaveScopeUpdate(IBurpExtenderCallbacks callbacks){
        String autoSaveFlag  = getGuiConfigValue(ConfigEntriesPlus.AUTO_SAVE_SCOPE_WHEN_UPDATE);
        if(autoSaveFlag!=null){
            autoSaveProjectConfig(callbacks);
        }
    }

    /**
     * 追加Auto_Append_Hosts表单设置到配置文件的排除列表中
     * @param callbacks
     */
    public static void addDefaultExcludeHosts(IBurpExtenderCallbacks callbacks) {
        String defaultExcludeHosts  = getGuiConfigValue(ConfigEntriesPlus.AUTO_ADD_HOSTS_To_EXCLUDE_SCOPE);
        if (defaultExcludeHosts!=null && defaultExcludeHosts.trim().length()>0){
            HashSet<String> hashSet = new HashSet<>();
            //切割并整理输入
            List<String> defaultExcludeHostList = Arrays.asList(defaultExcludeHosts.split(","));
            for(String host:defaultExcludeHostList){
                hashSet.add(host.trim());
            }
            //添加主机名到排除列表
            addHostToExScopeAdv(callbacks, hashSet);
        }
    }
}
