/**
 * Copyright © 1999-2008 JIT Co，Ltd. 
 * All right reserved.
 */
package com.highershine.pki.servlet;

import java.io.IOException;
import java.util.Properties;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;

import com.highershine.gdna2.config.PKIConfiguration;

/**
 * 此Servlet为原来从PKI的Demo中拷出来的，暂时没使用，里面的代码已经拷贝至LIMS或MIS项目的LoginAction中了�?
 * @author jacky
 *
 */
public class PKIProcessServlet extends HttpServlet {

	private static final long serialVersionUID = 3923090461076418525L;
	
	private String tempURL = null;
	private String propertiesURL = null;
	
	private Properties props = null;
	
	/** pki认证方式  : 0中间�?  1 网关报文  */
	private final String PKI_FLAG = "pkiFlag";	
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
	 
//		String parentPath = request.getSession().getServletContext()
//		.getRealPath("/WEB-INF");
//		InputStream in = new FileInputStream(parentPath + propertiesURL);
//		props = new Properties();
//		props.load(in);
//		
//		String pkiFlag = props.getProperty(PKI_FLAG);
		
		String pkiFlag = pkiConfiguration.getPkiFlag();
		if("0".equals(pkiFlag)){
			//nothing
		}else if("1".equals(pkiFlag)){
//			this.setProperties(KEY_APP_ID,request.getSession());
//			this.setProperties(KEY_AUTHURL,request.getSession());
			
			request.getSession().setAttribute(KEY_APP_ID,pkiConfiguration.getAppId());
			request.getSession().setAttribute(KEY_AUTHURL,pkiConfiguration.getAuthURL());
			
			RandomServlet rs = new RandomServlet();
			String rand_str = rs.generateRandomNum();
			request.setAttribute("rand_str", rand_str);
			request.getSession().setAttribute("original_data", rand_str);
		}
		request.setAttribute("pkiFlag", pkiFlag);
		// 设置跳转页面
		request.getRequestDispatcher(tempURL).forward(request, response);
	}

	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws IOException, ServletException {
		doGet(req, resp);
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
