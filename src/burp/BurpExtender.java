package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;

public class BurpExtender extends GUI implements IBurpExtender, ITab, IExtensionStateListener,IContextMenuFactory,IHttpListener{
	private static IBurpExtenderCallbacks callbacks;
	private static IExtensionHelpers helpers;

	public static String ExtensionName = "Domain Hunter";
	public static String Version = bsh.This.class.getPackage().getImplementationVersion();
	public static String Author = "by bit4woo";	
	public static String github = "https://github.com/bit4woo/domain_hunter";

	public static PrintWriter stdout;
	public static PrintWriter stderr;

	//name+version+author
	public static String getFullExtensionName(){
		return ExtensionName+" "+Version+" "+Author;
	}

	public static PrintWriter getStdout() {
		try{
			stdout = new PrintWriter(BurpExtender.callbacks.getStdout(), true);
		}catch (Exception e){
			stdout = new PrintWriter(System.out, true);
		}
		return stdout;
	}

	public static PrintWriter getStderr() {
		try{
			stderr = new PrintWriter(BurpExtender.callbacks.getStderr(), true);
		}catch (Exception e){
			stderr = new PrintWriter(System.out, true);
		}
		return stderr;
	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		BurpExtender.callbacks = callbacks;
		BurpExtender.helpers = callbacks.getHelpers();

		stdout = getStdout();
		stderr = getStdout();
		stdout.println(getFullExtensionName());
		stdout.println(github);


		callbacks.setExtensionName(getFullExtensionName()); //插件名称
		callbacks.registerExtensionStateListener(this);
		callbacks.registerContextMenuFactory(this);
		callbacks.registerHttpListener(this);
		addMenuTab();

		//recovery save domain results from extensionSetting
		String content = callbacks.loadExtensionSetting("content");
		if (content!=null) {
			domainResult = domainResult.Open(content);
			showToUI(domainResult);
		}

	}

	public void extensionUnloaded() {
		//TODO to cancel SwingWorker in search and crawl function
		//this.getContentPane().removeAll();
	}

	@Override
	public Map<String, Set<String>> search(Set<String> rootdomains, Set<String> keywords){
		IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
		IHttpRequestResponse[] messages = callbacks.getSiteMap(null);
		new ThreadSearhDomain(Arrays.asList(messages)).Do();
		return null;
	}

	@Override
	public Map<String, Set<String>> crawl (Set<String> rootdomains, Set<String> keywords) {
		int i = 0;
		while(i<=2) {
			for (String rootdomain: rootdomains) {
				if (!rootdomain.contains(".")||rootdomain.endsWith(".")||rootdomain.equals("")){
					//如果域名为空，或者（不包含.号，或者点号在末尾的）
				}
				else {
					IHttpRequestResponse[] items = callbacks.getSiteMap(null); //null to return entire sitemap
					//int len = items.length;
					//stdout.println("item number: "+len);
					Set<URL> NeedToCrawl = new HashSet<URL>();
					for (IHttpRequestResponse x:items){// 经过验证每次都需要从头开始遍历，按一定offset获取的数据每次都可能不同

						IHttpService httpservice = x.getHttpService();
						String shortUrlString = httpservice.toString();
						String Host = httpservice.getHost();

						try {
							URL shortUrl = new URL(shortUrlString);

							if (Host.endsWith("."+rootdomain) && Commons.isResponseNull(x)) {
								// to reduce memory usage, use isResponseNull() method to adjust whether the item crawled.
								NeedToCrawl.add(shortUrl);
								// to reduce memory usage, use shortUrl. base on my test, spider will crawl entire site when send short URL to it.
								// this may miss some single page, but the single page often useless for domain collection
								// see spideralltest() function.
							}
						} catch (MalformedURLException e) {
							e.printStackTrace(stderr);
						}
					}


					for (URL shortUrl:NeedToCrawl) {
						if (!callbacks.isInScope(shortUrl)) { //reduce add scope action, to reduce the burp UI action.
							callbacks.includeInScope(shortUrl);//if not, will always show confirm message box.
						}
						callbacks.sendToSpider(shortUrl);
					}
				}
			}


			try {
				Thread.sleep(5*60*1000);//单位毫秒，60000毫秒=一分钟
				stdout.println("sleep 5 minutes to wait spider");
				//to wait spider
			} catch (InterruptedException e) {
				e.printStackTrace(stdout);
			}
			i++;
		}

		return search(rootdomains,keywords);
	}


	/*	public Map<String, Set<String>> spideralltest (String subdomainof, String domainlike) {

		int i = 0;
		while (i<=10) {
			try {
				callbacks.sendToSpider(new URL("http://www.baidu.com/"));
				Thread.sleep(1*60*1000);//单位毫秒，60000毫秒=一分钟
				stdout.println("sleep 1 min");
			} catch (Exception e) {
				e.printStackTrace();
			}
			i++;
			// to reduce memory usage, use isResponseNull() method to adjust whether the item crawled.
		}

		Map<String, Set<String>> result = new HashMap<String, Set<String>>();
		return result;
	}*/



	/**
	 * @return IHttpService set to void duplicate IHttpRequestResponse handling
	 * 
	 */
	Set<IHttpService> getHttpServiceFromSiteMap(){
		IHttpRequestResponse[] requestResponses = callbacks.getSiteMap(null);
		Set<IHttpService> HttpServiceSet = new HashSet<IHttpService>();
		for (IHttpRequestResponse x:requestResponses){

			IHttpService httpservice = x.getHttpService();
			HttpServiceSet.add(httpservice);
			/*	    	String shortURL = httpservice.toString();
	    	String protocol =  httpservice.getProtocol();
			String Host = httpservice.getHost();*/
		}
		return HttpServiceSet;

	}



	//以下是各种burp必须的方法 --start

	public void addMenuTab()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				BurpExtender.callbacks.addSuiteTab(BurpExtender.this); //这里的BurpExtender.this实质是指ITab对象，也就是getUiComponent()中的contentPane.这个参数由CGUI()函数初始化。
				//如果这里报java.lang.NullPointerException: Component cannot be null 错误，需要排查contentPane的初始化是否正确。
			}
		});
	}


	//ITab必须实现的两个方法
	@Override
	public String getTabCaption() {
		return ("Domain Hunter");
	}
	@Override
	public Component getUiComponent() {
		return this.getContentPane();
	}
	//ITab必须实现的两个方法
	//各种burp必须的方法 --end

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		List<JMenuItem> list = new ArrayList<JMenuItem>();

		byte context = invocation.getInvocationContext();
		if (context == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE) {
			JMenuItem addToDomainHunter = new JMenuItem("^_^ Add To Domain Hunter");
			addToDomainHunter.addActionListener(new addHostToRootDomain(invocation));	
			list.add(addToDomainHunter);
		}
		return list;
	}

	public class addHostToRootDomain implements ActionListener{
		private IContextMenuInvocation invocation;
		public addHostToRootDomain(IContextMenuInvocation invocation) {
			this.invocation  = invocation;
		}
		@Override
		public void actionPerformed(ActionEvent e)
		{
			try{
				IHttpRequestResponse[] messages = invocation.getSelectedMessages();
				Set<String> domains = new HashSet<String>();
				for(IHttpRequestResponse message:messages) {
					String host = message.getHttpService().getHost();
					domains.add(host);
				}

				domainResult.relatedDomainSet.addAll(domains);
				if (domainResult.autoAddRelatedToRoot == true) {
					domainResult.relatedToRoot();
					domainResult.subDomainSet.addAll(domains);
				}
				showToUI(domainResult);
			}
			catch (Exception e1)
			{
				e1.printStackTrace(stderr);
			}
		}
	}

	public static IBurpExtenderCallbacks getCallbacks() {
		// TODO Auto-generated method stub
		return callbacks;
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

		//		Date now = new Date();
		SwingWorker<Map, Map> worker = new SwingWorker<Map, Map>() {
			//using SwingWorker to void slow down proxy http response time.

			@Override
			protected Map doInBackground() throws Exception {
				findDomainInTraffic(toolFlag,messageIsRequest,messageInfo);
				return null;
			}
			@Override
			protected void done() {
			}
		};
		worker.execute();
		//findDomainInTraffic(toolFlag,messageIsRequest,messageInfo);
		//		Date now1 = new Date();
		//		stderr.println("takes time to finish find domain: "+(now1.getTime()-now.getTime()));

	}


	public void findDomainInTraffic(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
		boolean dataChanged =false;
		if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
			try {
				Getter getter = new Getter(helpers);
				if (messageIsRequest) {
					IHttpService httpservice = messageInfo.getHttpService();
					String Host = httpservice.getHost();

					int hostType = GUI.domainResult.domainType(Host);
					if (hostType == DomainObject.SUB_DOMAIN)
					{	
						if (!GUI.domainResult.getSubDomainSet().contains(Host)) {
							GUI.domainResult.getSubDomainSet().add(Host);
							stdout.println("new domain found: "+ Host);
							dataChanged = true;
						}
					}else if (hostType == DomainObject.SIMILAR_DOMAIN) {
						if (!GUI.domainResult.getSimilarDomainSet().contains(Host)) {
							GUI.domainResult.getSimilarDomainSet().add(Host);
							dataChanged = true;
						}
					}
				}else {//response

					IHttpService httpservice = messageInfo.getHttpService();
					String urlString = getter.getURL(messageInfo).getFile();

					String Host = httpservice.getHost();

					int hostType = GUI.domainResult.domainType(Host);
					if (hostType != DomainObject.USELESS) {//grep domains from response and classify
						if (urlString.endsWith(".gif") ||urlString.endsWith(".jpg")
								|| urlString.endsWith(".png") ||urlString.endsWith(".css")||urlString.endsWith(".woff")) {

						}else {
							dataChanged = classifyDomains(messageInfo);
						}
					}
				}
			} catch (Exception e) {
				e.printStackTrace(stderr);
			}
		}

		if (dataChanged) {
			showToUI(domainResult);
		}
	}

	public boolean classifyDomains(IHttpRequestResponse messageinfo) {
		boolean dataChanged = false;
		byte[] response = messageinfo.getResponse();
		if (response != null) {
			Set<String> domains = DomainProducer.grepDomain(new String(response));
			for (String domain:domains) {
				int type = GUI.domainResult.domainType(domain);
				if (type == DomainObject.SUB_DOMAIN)
				{
					if (!GUI.domainResult.getSubDomainSet().contains(domain)) {
						GUI.domainResult.getSubDomainSet().add(domain);
						stdout.println("new domain found: "+ domain);
						dataChanged = true;
					}
				}else if (type == DomainObject.SIMILAR_DOMAIN) {
					if (!GUI.domainResult.getSimilarDomainSet().contains(domain)){
						GUI.domainResult.getSimilarDomainSet().add(domain);
						dataChanged = true;
					}
				}
			}
		}
		return dataChanged;
	}

	/*	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					GUI frame = new GUI();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}*/
}