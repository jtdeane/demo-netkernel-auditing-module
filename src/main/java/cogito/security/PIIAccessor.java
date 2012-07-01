package cogito.security;

import org.netkernel.layer0.nkf.INKFRequestContext;
import org.netkernel.module.standard.endpoint.StandardAccessorImpl;

import cogito.infrastructure.AccessorUtility;


/**
 * Handles requests for Mock PII Audit
 */
public class PIIAccessor extends StandardAccessorImpl {
	
	/**
     * Default constructor
     */
	public PIIAccessor() {
		
		this.declareThreadSafe();
	}
	
	/**
	 * 
	 * Handles requests for Mock PII Audit
	 * @param context
	 * @throws Exception
	 */
	public void onSource(INKFRequestContext context) throws Exception {
		
		//get the text to audit
        String text = context.getThisRequest().getArgumentValue("text");
        
        String auditResult = null;
        
        if (text.length() > 21) {
        	
        	auditResult = "FOUND PII";
        	
        } else {
        	
        	auditResult = "NO PII";
        }
        
        context.logRaw(INKFRequestContext.LEVEL_DEBUG, auditResult);
        
        AccessorUtility.returnMessage(context, auditResult);
	}
}