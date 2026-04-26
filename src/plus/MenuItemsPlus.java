package plus;

import burp.BurpExtender;

import javax.swing.*;
import java.util.ArrayList;

public class MenuItemsPlus {
    public static void addMenuItems(ArrayList<JMenuItem> menu_item_list, BurpExtender burpExtender) {
        //添加 配置文件相关 //手动更新用户指定的 Project Json 文件
        menu_item_list.add(new ProjectConfigLoadMenu(burpExtender));
        menu_item_list.add(new ProjectConfigSaveMenu(burpExtender));
        menu_item_list.add(new ProjectScopeClearMenu(burpExtender));
        menu_item_list.add(new AddHostToInScopeMenu(burpExtender));
        menu_item_list.add(new AddHostToInScopeAdvMenu(burpExtender));
        menu_item_list.add(new AddHostToExScopeMenu(burpExtender));
        menu_item_list.add(new AddHostToExScopeAdvMenu(burpExtender));
    }
}
