package burp;

import base.FindUrlAction;
import base.Proxy;
import com.bit4woo.utilbox.burp.HelperPlus;
import com.google.gson.Gson;
import config.*;
import knife.*;
import messageTab.Info.InfoTabFactory;
import messageTab.U2C.ChineseTabFactory;
import org.apache.commons.lang3.StringUtils;
import plus.AdvScopeUtils;
import plus.MenuItemsPlus;
import plus.ProcessHttpMessagePlus;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class BurpExtender extends GUI implements IBurpExtender, IContextMenuFactory, ITab, IHttpListener, IProxyListener, IExtensionStateListener {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    private static HelperPlus helperPlus;


    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public IContextMenuInvocation invocation;


    public static String ExtensionName = "Knife";
    public static String Version = bsh.This.class.getPackage().getImplementationVersion();
    public static String Author = "by bit4woo";
    public static String github = "https://github.com/bit4woo/knife";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();
        BurpExtender.helperPlus = new HelperPlus(helpers);

        flushStd();
        BurpExtender.stdout.println(getFullExtensionName());
        BurpExtender.stdout.println(github);

        configTable = new ConfigTable(new ConfigTableModel());
        configPanel.setViewportView(configTable);

        String content = callbacks.loadExtensionSetting("knifeconfig");
        if (StringUtils.isEmpty(content)) {
            content = initConfig();
        }

        configManager = new Gson().fromJson(content, ConfigManager.class);
        showToUI(configManager);

        // [重要] 使用 SwingUtilities.invokeLater 解决操作过快 导致出现swing崩溃的问题
        SwingUtilities.invokeLater(new Runnable() { public void run() {
        ChineseTabFactory chntabFactory = new ChineseTabFactory(null, false, helpers, callbacks);
        InfoTabFactory infotabFactory = new InfoTabFactory(null, false, helpers, callbacks);

        //各项数据初始化完成后在进行这些注册操作，避免插件加载时的空指针异常
        callbacks.setExtensionName(getFullExtensionName());
        callbacks.registerContextMenuFactory(BurpExtender.this);// for menus
        callbacks.addSuiteTab(BurpExtender.this);
        callbacks.registerHttpListener(BurpExtender.this);
        callbacks.registerProxyListener(BurpExtender.this);
        callbacks.registerExtensionStateListener(BurpExtender.this);

        //自动加载用户指定的 Project Json文件,如果不存在会自动保存当前配置
        AdvScopeUtils.autoLoadProjectConfig(callbacks);
        //自动添加默认排除的域名列表
        AdvScopeUtils.addDefaultExcludeHosts(callbacks);

        //动态添加 编码转换 面板
        if (AdvScopeUtils.getGuiConfigValue("MsgChineseTab") != null) {
            callbacks.registerMessageEditorTabFactory(chntabFactory);// for Chinese
        }
        //动态添加 敏感信息 面板
        if (AdvScopeUtils.getGuiConfigValue("MsgInfoTab") != null) {
            callbacks.registerMessageEditorTabFactory(infotabFactory);// for Information
        }
        BurpExtender.stdout.println("Load Extension Success ...");
        }});
    }


    private static void flushStd() {
        try {
            stdout = new PrintWriter(callbacks.getStdout(), true);
            stderr = new PrintWriter(callbacks.getStderr(), true);
        } catch (Exception e) {
            stdout = new PrintWriter(System.out, true);
            stderr = new PrintWriter(System.out, true);
        }
    }

    public static PrintWriter getStdout() {
        flushStd();//不同的时候调用这个参数，可能得到不同的值
        return stdout;
    }

    public static PrintWriter getStderr() {
        flushStd();
        return stderr;
    }

    //name+version+author
    public static String getFullExtensionName() {
        return ExtensionName + " " + Version + " " + Author;
    }

    //JMenu 是可以有下级菜单的，而JMenuItem是不能有下级菜单的
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menu_item_list = new ArrayList<JMenuItem>();

        this.invocation = invocation;
        //常用
        menu_item_list.add(new OpenWithBrowserMenu(this));
        menu_item_list.add(new CustomPayloadMenu(this));
        menu_item_list.add(new CustomPayloadForAllInsertpointMenu(this));

        //cookie身份凭证相关
        menu_item_list.add(new UpdateCookieMenu(this));
        menu_item_list.add(new UpdateCookieWithHistoryMenu(this));
        menu_item_list.add(new ChangeToUploadRequest(this));

        menu_item_list.add(new SetCookieMenu(this));
        menu_item_list.add(new SetCookieWithHistoryMenu(this));

        UpdateHeaderMenu updateHeader = new UpdateHeaderMenu(this);//JMenuItem vs. JMenu
        if (updateHeader.getItemCount() > 0) {
            menu_item_list.add(updateHeader);
        }

        //添加自定义的菜单项
        MenuItemsPlus.addMenuItems(menu_item_list, this);

        //扫描攻击相关
        menu_item_list.add(new AddHostToScopeMenu(this));
        menu_item_list.add(new RunCmdMenu(this));
        menu_item_list.add(new DoActiveScanMenu(this));


        //不太常用的
        menu_item_list.add(new DismissMenu(this));
        menu_item_list.add(new DismissCancelMenu(this));

        menu_item_list.add(new ChunkedEncodingMenu(this));
        menu_item_list.add(new DownloadResponseMenu(this));
        //menu_item_list.add(new DownloadResponseMenu2(this));
        //menu_item_list.add(new ViewChineseMenu(this));
        //menu_item_list.add(new JMenuItem());
        //空的JMenuItem不会显示，所以将是否添加Item的逻辑都方法到类当中去了，以便调整菜单顺序。

        menu_item_list.add(new CopyJsOfThisSite(this));
        menu_item_list.add(new FindUrlAndRequest(this));

        Iterator<JMenuItem> it = menu_item_list.iterator();
        while (it.hasNext()) {
            JMenuItem item = it.next();
            if (StringUtils.isEmpty(item.getText())) {
                it.remove();
            }
        }

        String oneMenu = configTableModel.getConfigValueByKey("Put_MenuItems_In_One_Menu");
        if (oneMenu != null) {
            ArrayList<JMenuItem> Knife = new ArrayList<JMenuItem>();
            JMenu knifeMenu = new JMenu("^_^ Knife");
            Knife.add(knifeMenu);
            for (JMenuItem item : menu_item_list) {
                knifeMenu.add(item);
            }
            return Knife;
        } else {
            return menu_item_list;
        }
    }


    @Override
    public String getTabCaption() {
        return ("Knife");
    }


    @Override
    public Component getUiComponent() {
        return this.getContentPane();
    }

    @Override
    public void extensionUnloaded() {
        saveConfigToBurp();
    }

    @Override
    public String initConfig() {
        configManager = new ConfigManager("default");
        configTableModel = new ConfigTableModel();
        return getAllConfig();
    }

    //IProxyListener中的方法，修改的内容会在proxy中显示为edited
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        //processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY,true,message.getMessageInfo());
        //same action will be executed twice! if call processHttpMessage() here.
        if (FindUrlAction.CurrentProxy == null) {
            //为了知道burp当前监听的接口。供“find url and request”菜单使用
            FindUrlAction.CurrentProxy = new Proxy(message.getListenerInterface());
        }
        IHttpRequestResponse messageInfo = message.getMessageInfo();
        List<ConfigEntry> rules = ProcessManager.getAllActionRules();
        for (ConfigEntry rule : rules) {
            rule.takeProxyAction(messageIsRequest, message);
        }

        if (messageIsRequest) {
            if (isInCheckBoxScope(IBurpExtenderCallbacks.TOOL_PROXY, messageInfo)) {
                ProcessManager.doChunk(messageIsRequest, messageInfo);
            }
        }
    }

    //IHttpListener中的方法，修改的内容在Proxy中不可见
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        //stdout.println("processHttpMessage called when messageIsRequest="+messageIsRequest);
        try {
            if (messageIsRequest) {
                //add/update/append header
                if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
                    ProcessHttpMessagePlus.messageReqHandleTraceless(messageInfo);
                    //##############################//
                    //handle it in processProxyMessage(). so we can see the changes in the proxy view.
                    //##############################//
                } else {
                    List<ConfigEntry> rules = ProcessManager.getEditActionRules();
                    for (int index = rules.size() - 1; index >= 0; index--) {//按照时间倒叙引用规则

                        ConfigEntry rule = rules.get(index);
                        rule.takeEditAction(toolFlag, messageIsRequest, messageInfo);
                    }

                    if (isInCheckBoxScope(toolFlag, messageInfo)) {
                        ProcessManager.doChunk(messageIsRequest, messageInfo);
                    }
                }
            } else {
                // response 修改
                if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
                    ProcessHttpMessagePlus.messageRespHandleTraceless(messageInfo);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            e.printStackTrace(stderr);
        }
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }


    public static HelperPlus getHelperPlus() {
        return helperPlus;
    }


    public static boolean isInCheckBoxScope(int toolFlag, IHttpRequestResponse messageInfo) {
        if (toolFlag == (toolFlag & configManager.getEnableStatus())) {

            IExtensionHelpers helpers = getCallbacks().getHelpers();
            URL url = new HelperPlus(helpers).getFullURL(messageInfo);

            if (!configManager.isOnlyForScope() || callbacks.isInScope(url)) {
                return true;
            }
        }
        return false;
    }

}
