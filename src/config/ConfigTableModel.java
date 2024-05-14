package config;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;

import com.bit4woo.utilbox.utils.SystemUtils;

import burp.BurpExtender;

public class ConfigTableModel extends AbstractTableModel{
	//https://stackoverflow.com/questions/11553426/error-in-getrowcount-on-defaulttablemodel
	//when use DefaultTableModel, getRowCount encounter NullPointerException. why?
	/**
	 * LineTableModel中数据如果类型不匹配，或者有其他问题，可能导致图形界面加载异常！
	 */
	private static final long serialVersionUID = 1L;
	private List<ConfigEntry> configEntries = new ArrayList<>();
	public static final String[] titles = new String[] {
			"#", "Key", "Value", "Type", "Enable", "Comment"
	};

	public static final String Firefox_Mac = "/Applications/Firefox.app/Contents/MacOS/firefox";
	
	// /usr/local/bin 本地默认可执行文件路径
	public static final String SQLMap_Command = "python /usr/local/bin/sqlmap-dev/sqlmap.py -r {RequestAsFile} --force-ssl --risk=3 --level=3";
	public static final String Nmap_Command = "nmap -Pn -sT -sV --min-rtt-timeout 1ms "
			+ "--max-rtt-timeout 1000ms --max-retries 0 --max-scan-delay 0 --min-rate 3000 {Host}";
	
	public ConfigTableModel(){
	
		configEntries.add(new ConfigEntry("Put_MenuItems_In_One_Menu", "",ConfigEntry.Config_Basic_Variable,false,false,"合并knife右键子菜单"));
	
		//用于指示是否自动加载burp suite的项目配置文件,需要指示Json文件路径,需要支持相对路径,直接在knife下去寻找
		configEntries.add(new ConfigEntry("Auto_Load_Project_Config", "Project.Config.json",ConfigEntry.Config_Basic_Variable,true,false,"高级配置：启动时自动加载项目配置"));
		configEntries.add(new ConfigEntry("Scope_Base_On_SubDomain", "",ConfigEntry.Config_Basic_Variable,true,false,"高级配置：设置Scope时基于子域名操作"));
		configEntries.add(new ConfigEntry("Auto_Save_Scope_Update", "",ConfigEntry.Config_Basic_Variable,true,false,"高级配置：自动保存Scope更新到项目配置"));
		//默认不添加到scope的域名 //需要优化,不能每次都添加
		String defaultExcludeHosts = ".*\\.baidu\\.com,.*\\.bdstatic\\.com,.*\\.msn\\.cn,.*\\.microsoft\\.com,.*\\.bing\\.com,.*\\.google\\.com,.*\\.firefox\\.com";
		configEntries.add(new ConfigEntry("Add_Exclude_Scope_Hosts",defaultExcludeHosts,ConfigEntry.Config_Basic_Variable,false,false,"高级配置：将目标正则追加到排除Scope"));
	
		if (SystemUtils.isMac()) {
			configEntries.add(new ConfigEntry("browserPath", Firefox_Mac,ConfigEntry.Config_Basic_Variable,true,false,"程序调用：指定浏览器路径"));
		}else {
			configEntries.add(new ConfigEntry("browserPath", Firefox_Windows,ConfigEntry.Config_Basic_Variable,true,false,"程序调用：指定浏览器路径"));}