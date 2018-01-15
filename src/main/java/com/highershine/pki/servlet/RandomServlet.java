package com.highershine.pki.servlet;

import java.io.IOException;
import java.util.Properties;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.highershine.gdna2.config.PKIConfiguration;

public class RandomServlet extends HttpServlet {

	private static final long serialVersionUID = 3923090461076418525L;
	static Logger log = LoggerFactory.getLogger(RandomServlet.class);
	private String tempURL = null;
	private String propertiesURL = null;	
	private Properties props = null;
	
	/** 认证地址 */
	private final String KEY_AUTHURL = "authURL";
	/** 应用标识 */
	private final String KEY_APP_ID = "appId";
	
	@Autowired
	private PKIConfiguration pkiConfiguration;

	public void init(ServletConfig cfg) throws ServletException {
		// 初始化程序跳转页�?
		tempURL = cfg.getInitParameter("url");
		propertiesURL = cfg.getInitParameter("propertiesURL");
	}
	 
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		// 设置页面不缓�?
		response.setHeader("Pragma", "No-cache");
		response.setHeader("Cache-Control", "no-cache");
		response.setDateHeader("Expires", 0);
	 
		try{
//			String parentPath = request.getSession().getServletContext()
//			.getRealPath("/WEB-INF");
//			InputStream in = new FileInputStream(parentPath + propertiesURL);
//			props = new Properties();
//			props.load(in);
//			this.setProperties(KEY_APP_ID,request.getSession());
//			this.setProperties(KEY_AUTHURL,request.getSession());
			
			request.getSession().setAttribute(KEY_APP_ID,pkiConfiguration.getAppId());
			request.getSession().setAttribute(KEY_AUTHURL,pkiConfiguration.getAuthURL());
			
			}catch(Exception e){	
				log.error("",e);
			}
			
			String randNum = generateRandomNum();
			if (randNum == null || randNum.trim().equals("")) {
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				return;
			}
			
			/**************************
			 * 第三�?服务端返回认证原�?  *
			 **************************/
			// 设置认证原文到session，用于程序向后传递，通讯报文中使�?
			request.getSession().setAttribute("original_data", randNum);

			// 设置认证原文到页面，给页面程序提供参数，用于产生认证请求数据�?
			request.setAttribute("original", randNum);

			// 设置跳转页面
			request.getRequestDispatcher(tempURL).forward(request, response);
			
		// 产生认证原文
	
		return;
	}

	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws IOException, ServletException {
		doGet(req, resp);
	}
	/**
	 * 产生认证原文
	 */
	public String generateRandomNum() {
		/**************************
		 * 第二�?服务端产生认证原�?  *
		 **************************/
		String num = "1234567890abcdefghijklmnopqrstopqrstuvwxyz";
		int size = 6;
		char[] charArray = num.toCharArray();
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < size; i++) {
			sb
					.append(charArray[((int) (Math.random() * 10000) % charArray.length)]);
		}
		return sb.toString();
	}
	 
	/**
	 * 获取文件中的属�?�?
	 * @param httpSession 
	 */
	private String   setProperties(String key, HttpSession httpSession) {
		
		httpSession.setAttribute(key,props.get(key) == null ? null : (String) props.get(key) );
		return props.get(key) == null ? null : (String) props.get(key);
	}
}
