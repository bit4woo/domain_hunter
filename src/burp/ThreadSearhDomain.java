package burp;

import java.io.PrintWriter;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.text.StringEscapeUtils;

//////////////////ThreadGetTitle block/////////////
//no need to pass BurpExtender object to these class, IBurpExtenderCallbacks object is enough 
class ThreadSearhDomain{
	private List<IHttpRequestResponse> messages;
	private List<DomainProducer> plist;

	private static IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();//静态变量，burp插件的逻辑中，是可以保证它被初始化的。;
	public PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
	public PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
	public IExtensionHelpers helpers = callbacks.getHelpers();

	public ThreadSearhDomain(List<IHttpRequestResponse> messages) {
		this.messages = messages;
	}

	public void Do(){
		stdout.println("~~~~~~~~~~~~~Start Search Domain~~~~~~~~~~~~~");

		BlockingQueue<IHttpRequestResponse> inputQueue = new LinkedBlockingQueue<IHttpRequestResponse>();//use to store messageInfo
		BlockingQueue<String> subDomainQueue = new LinkedBlockingQueue<String>();
		BlockingQueue<String> similarDomainQueue = new LinkedBlockingQueue<String>();
		BlockingQueue<String> relatedDomainQueue = new LinkedBlockingQueue<String>();

		inputQueue.addAll(messages);

		plist = new ArrayList<DomainProducer>();

		for (int i=0;i<=10;i++) {
			DomainProducer p = new DomainProducer(inputQueue,subDomainQueue,
					similarDomainQueue,relatedDomainQueue,i);
			p.start();
			plist.add(p);
		}

		while(true) {//to wait all threads exit.
			if (inputQueue.isEmpty() && isAllProductorFinished()) {
				stdout.println("~~~~~~~~~~~~~Search Domain Done~~~~~~~~~~~~~");
				break;
			}else {
				try {
					Thread.sleep(1*1000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				continue;
			}
		}
		int oldnumber = GUI.getDomainResult().getSubDomainSet().size();

		GUI.getDomainResult().getSubDomainSet().addAll(subDomainQueue);
		GUI.getDomainResult().getSimilarDomainSet().addAll(similarDomainQueue);
		GUI.getDomainResult().getRelatedDomainSet().addAll(relatedDomainQueue);

		int newnumber = GUI.getDomainResult().getSubDomainSet().size();
		stdout.println(String.format("~~~~~~~~~~~~~%s subdomains added!~~~~~~~~~~~~~",newnumber-oldnumber));

		return;
	}

	boolean isAllProductorFinished(){
		for (DomainProducer p:plist) {
			if(p.isAlive()) {
				return false;
			}
		}
		return true;
	}

	public void stopThreads() {
		for (DomainProducer p:plist) {
			p.stopThread();
		}
		stdout.println("threads stopped!");
	}

	public static void main(String args[]) {//test
		System.out.println(DomainProducer.grepDomain("http://www.jd.com/usr/www.baidu.com/xss.jd.com"));
	}
}

/*
 * do request use method of burp
 * return IResponseInfo object Set
 *
 */

class DomainProducer extends Thread {//Producer do
	private final BlockingQueue<IHttpRequestResponse> inputQueue;//use to store messageInfo
	private final BlockingQueue<String> subDomainQueue;
	private final BlockingQueue<String> similarDomainQueue;
	private final BlockingQueue<String> relatedDomainQueue;
	private BlockingQueue<String> httpsQueue = new LinkedBlockingQueue<>();//temp variable to identify checked https

	private int threadNo;
	private boolean stopflag = false;

	private static IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();//静态变量，burp插件的逻辑中，是可以保证它被初始化的。;
	public PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
	public PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
	public IExtensionHelpers helpers = callbacks.getHelpers();

	public DomainProducer(BlockingQueue<IHttpRequestResponse> inputQueue, 
			BlockingQueue<String> subDomainQueue,
			BlockingQueue<String> similarDomainQueue,
			BlockingQueue<String> relatedDomainQueue,
			int threadNo) {
		this.threadNo = threadNo;
		this.inputQueue = inputQueue;
		this.subDomainQueue = subDomainQueue;
		this.similarDomainQueue = similarDomainQueue;
		this.relatedDomainQueue = relatedDomainQueue;
		stopflag= false;
	}

	public void stopThread() {
		stopflag = true;
	}

	@Override
	public void run() {
		while(true){
			Getter getter = new Getter(helpers);
			try {
				if (inputQueue.isEmpty() || stopflag) {
					//stdout.println("Producer break");
					break;
				}

				IHttpRequestResponse messageinfo = inputQueue.take();

				IHttpService httpservice = messageinfo.getHttpService();
				String urlString = helpers.analyzeRequest(messageinfo).getUrl().toString();

				String shortURL = httpservice.toString();
				String protocol =  httpservice.getProtocol();
				String Host = httpservice.getHost();

				//callbacks.printOutput(rootdomains.toString());
				//callbacks.printOutput(keywords.toString());
				int type = GUI.domainResult.domainType(Host);
				//callbacks.printOutput(Host+":"+type);
				if (type == DomainObject.SUB_DOMAIN)
				{	
					if (!subDomainQueue.contains(Host)) {
						subDomainQueue.add(Host);
					}
				}else if (type == DomainObject.SIMILAR_DOMAIN) {
					if (!similarDomainQueue.contains(Host)) {
						similarDomainQueue.add(Host);
					}
				}

				if (type !=DomainObject.USELESS && protocol.equalsIgnoreCase("https")){//get related domains
					if (!httpsQueue.contains(shortURL)) {//httpService checked or not
						Set<String> tmpDomains = CertInfo.getSANs(shortURL,GUI.domainResult.fetchKeywordSet());
						for (String domain:tmpDomains) {
							if (!relatedDomainQueue.contains(domain)) {
								relatedDomainQueue.add(domain);
							}
						}
						httpsQueue.add(shortURL);
					}
				}

				if (type != DomainObject.USELESS) {//grep domains from response and classify
					if (urlString.endsWith(".gif") ||urlString.endsWith(".jpg")
							|| urlString.endsWith(".png") ||urlString.endsWith(".css")) {

					}else {
						classifyDomains(messageinfo);
						//classifyEmails(messageinfo);
					}
				}
			} catch (Throwable error) {//java.lang.RuntimeException can't been catched, why?
			}
		}
	}

	public void classifyDomains(IHttpRequestResponse messageinfo) {
		byte[] response = messageinfo.getResponse();
		if (response != null) {
			Set<String> domains = DomainProducer.grepDomain(new String(response));
			for (String domain:domains) {
				int type = GUI.domainResult.domainType(domain);
				if (type == DomainObject.SUB_DOMAIN)
				{
					subDomainQueue.add(domain);

				}else if (type == DomainObject.SIMILAR_DOMAIN) {
					similarDomainQueue.add(domain);
				}
			}
		}
	}

	public static Set<String> grepDomain(String httpResponse) {
		httpResponse = httpResponse.toLowerCase();
		//httpResponse = cleanResponse(httpResponse);
		Set<String> domains = new HashSet<>();
		//"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"
		final String DOMAIN_NAME_PATTERN = "([A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}";

		String[] lines = httpResponse.split("\r\n");

		for (String line:lines) {//分行进行提取，似乎可以提高成功率？
			line = line.trim();
			int counter =0;

			while (needURLConvert(line) && counter<3) {// %对应的URL编码
				try {
					line = URLDecoder.decode(line);
					counter++;
				}catch(Exception e) {
					//e.printStackTrace(BurpExtender.getStderr());
					break;//即使出错，也要进行后续的查找
				}
			}
			//保险起见，再做一层处理
			if (line.toLowerCase().contains("%2f")) {
				line.replace("%2f"," ");
			}

			if (line.toLowerCase().contains("%3a")) {
				line.replace("%3a"," ");
			}

			counter = 0;
			while (needUnicodeConvert(line) && counter<3) {//unicode解码
				try {
					line = StringEscapeUtils.unescapeJava(line);
					counter++;
				}catch(Exception e) {
					//e.printStackTrace(BurpExtender.getStderr());
					break;//即使出错，也要进行后续的查找
				}
			}

			Pattern pDomainNameOnly = Pattern.compile(DOMAIN_NAME_PATTERN);
			Matcher matcher = pDomainNameOnly.matcher(line);
			while (matcher.find()) {//多次查找
				domains.add(matcher.group());
			}
		}
		return domains;
	}

	public static boolean needUnicodeConvert(String str) {
		Pattern pattern = Pattern.compile("(\\\\u(\\p{XDigit}{4}))");
		//Pattern pattern = Pattern.compile("(\\\\u([A-Fa-f0-9]{4}))");//和上面的效果一样
		Matcher matcher = pattern.matcher(str.toLowerCase());
		if (matcher.find() ){
			return true;
		}else {
			return false;
		}
	}

	public static boolean needURLConvert(String str) {
		Pattern pattern = Pattern.compile("(%(\\p{XDigit}{2}))");

		Matcher matcher = pattern.matcher(str.toLowerCase());
		if (matcher.find() ){
			return true;
		}else {
			return false;
		}
	}

	public static void main(String args[]){}

}
