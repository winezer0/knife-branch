package knife;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;

import javax.swing.JMenuItem;

import com.bit4woo.utilbox.burp.HelperPlus;

import burp.*;
import config.CookieFinder;
import config.CookieRecorder;
import config.ProcessManager;

public class UpdateCookieMenu extends JMenuItem {
	//JMenuItem vs. JMenu
	public UpdateCookieMenu(BurpExtender burp){
		if (burp.invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
			|| burp.invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS) {
			this.setText("^_^ Update Cookie");
			this.addActionListener(new UpdateCookieAction(burp,burp.invocation));
		}
	}
}

class UpdateCookieAction implements ActionListener {
	private IContextMenuInvocation invocation;
	public IExtensionHelpers helpers;
	public PrintWriter stdout;
	public PrintWriter stderr;
	public IBurpExtenderCallbacks callbacks;
	public BurpExtender burp;

	public UpdateCookieAction(BurpExtender burp, IContextMenuInvocation invocation) {
		this.burp = burp;
		this.invocation = invocation;
		this.helpers = burp.helpers;
		this.callbacks = burp.callbacks;
		this.stderr = burp.stderr;
		this.stdout = burp.stdout;
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		try {
			//stdout.println("UpdateCookieAction called");
			IHttpRequestResponse[] selectedItems = invocation.getSelectedMessages();
			
			CookieRecorder recorder = CookieFinder.getLatestCookieFromHistory(selectedItems[0]);//自行查找一次
			
			if (recorder.isAllBlank()) {
				recorder = CookieFinder.getLatestHeaderFromSiteMap(selectedItems[0]);//自行查找一次
			}

			//通过弹窗交互 获取Cookie的方式很不简便，不再使用！
			String latestCookie = recorder.getValue();
			if (isVaildCookie(latestCookie)) {
				try{
					selectedItems[0] = ProcessManager.updateCookie(true,selectedItems[0], latestCookie);
					ProcessManager.setUsedCookieOfUpdate(latestCookie);
				}catch (Exception e){
					e.printStackTrace(stderr);
					//stderr.print(e.getMessage());
					//这是个bug，请求包实际还是被修改了，但是就是报这个错误！
					//当在proxy中拦截状态下更新请求包的时候，总是会报这个假错误！
					//"java.lang.UnsupportedOperationException: Request has already been issued"
				}
			}
		}catch (Exception e1){
			e1.printStackTrace(stderr);
		}
	}

	public boolean isVaildCookie(String cookieLine) {
		if (cookieLine == null) {
			return false;
		}
		String currentCookie = new HelperPlus(helpers).getHeaderLine(true,invocation.getSelectedMessages()[0],"Cookie");
		if (cookieLine.equalsIgnoreCase(currentCookie)) {
			return false;
		}
		return true;
	}
}