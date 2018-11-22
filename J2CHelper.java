package in.hp.java.was.utils;

import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.resource.spi.security.PasswordCredential;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import com.ibm.websphere.security.NotImplementedException;
import com.ibm.wsspi.security.auth.callback.Constants;
import com.ibm.wsspi.security.auth.callback.WSMappingCallbackHandlerFactory;

public class J2CHelper {
	
	private static Logger logger = Logger.getLogger(J2CHelper.class.getName());

	public static PasswordCredential lookUpCredentials(String j2cAuthAlias) {
		logger.log(Level.INFO, "LOADING CREDENTIALS FOR AUTH ALIAS :: " +j2cAuthAlias);
		PasswordCredential passwordCredential = null;
		CallbackHandler callbackHandler = null;
		Map<String, String> map = new HashMap<String, String>();
		map.put(Constants.MAPPING_ALIAS, null);
		try {
			callbackHandler = WSMappingCallbackHandlerFactory.getInstance().getCallbackHandler(map, null);
			LoginContext loginContext = new LoginContext("DefaultPrincipalMapping", callbackHandler);
			loginContext.login();
			Subject subject = loginContext.getSubject();
			Set<Object> credentials = subject.getPrivateCredentials();
			passwordCredential = (PasswordCredential) credentials.iterator().next();
			logger.log(Level.INFO, "LOADED CREDENTIALS FOR AUTH ALIAS :: " +j2cAuthAlias);
			logger.log(Level.INFO, "USERNAME :: " +passwordCredential.getUserName());
			logger.log(Level.INFO, "PASSWORD :: " +passwordCredential.getPassword().toString());
		} catch (NotImplementedException e) {
			String errorMsg = "ERROR WHILE LOADING CREDENTIALS FOR AUTH ALIAS :: " +j2cAuthAlias;
			logger.log(Level.SEVERE, errorMsg, e);
			e.printStackTrace();
		} catch (LoginException e) {
			String errorMsg = "ERROR WHILE LOADING CREDENTIALS FOR AUTH ALIAS :: " +j2cAuthAlias;
			logger.log(Level.SEVERE, errorMsg, e);
			e.printStackTrace();
		}
		return passwordCredential;
	}
}
