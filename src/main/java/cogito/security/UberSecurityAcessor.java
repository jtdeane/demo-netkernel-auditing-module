package cogito.security;

import org.netkernel.layer0.nkf.INKFRequest;
import org.netkernel.layer0.nkf.INKFRequestContext;
import org.netkernel.layer0.representation.impl.HDSBuilder;
import org.netkernel.module.standard.endpoint.StandardAccessorImpl;
import org.netkernel.xml.xda.DOMXDA;

import cogito.infrastructure.AccessorUtility;

/**
 * Handles processing of audit events. In addition, it checks for PII
 * and maps external application names to internal application names
 * @author jeremydeane
 *
 */
public class UberSecurityAcessor extends StandardAccessorImpl {
	
	/**
     * Default constructor
     */
	public UberSecurityAcessor() {	
		this.declareThreadSafe();
	}

	@Override
	public void onSource(INKFRequestContext context) throws Exception {
		
		//1. Get the audit event xml
		DOMXDA auditEventDOMXDA = AccessorUtility.
				extractDocumentFromHTTPBody(context);
		
		//2. PII Audit
		personallyIdentifiableInformationAudit(auditEventDOMXDA, context);
		
		//3. Map the application name (service mediation)
		mapToInternalApplicationName(auditEventDOMXDA, context);
		
		//4. Submit Audit Event to Provider returning reponse to Consumer
		context.createResponseFrom(submitAuditEvent
				(auditEventDOMXDA.toString(), context));
	}
	
	/**
	 * Mock check for PII
	 * @param auditEventDOMXDA
	 * @param context
	 * @throws Exception
	 */
	private void personallyIdentifiableInformationAudit(DOMXDA auditEventDOMXDA, 
			INKFRequestContext context) throws Exception {
		
		INKFRequest subRequest=context.createRequest
				("res:/cogito/security/pii/audit");		
		
		//extract message using xpath expression
		String message = auditEventDOMXDA.getText("/audit-event/message", true);
		
		//add the text as an argument
		subRequest.addArgumentAsAbsolute("text", message);
		
		//issue the sub-request asynchronously (fire and forget)
		context.issueAsyncRequest(subRequest);			
	}
	
	/**
	 * Maps external to internal application name
	 * @param auditEventDOMXDA
	 * @param context
	 * @throws Exception
	 */
	private void mapToInternalApplicationName(DOMXDA auditEventDOMXDA, 
			INKFRequestContext context) throws Exception {
		
		//extract external application name using xpath expression
		String externalName = auditEventDOMXDA.getText
				("/audit-event/application", true);
		
		//create the sub-request to get the internal name
		INKFRequest subRequest=context.createRequest
				("res:/cogito/security/internal/" + externalName);
		
		//issue the sub-request to get the external name
		String internalName = (String )context.issueRequest(subRequest);
		
		//set the internal name
		auditEventDOMXDA.setText("/audit-event/application", internalName);
	}

	/**
	 * Submit the Audit Event
	 * @param xml
	 * @param context
	 * @return Object
	 * @throws Exception
	 */
	private Object submitAuditEvent (String xml, INKFRequestContext context) 
			throws Exception {
		
		//get the audit event id
        String eventID = context.getThisRequest().getArgumentValue("eventID");
        
        //create the sub-request
		INKFRequest subRequest=context.createRequest("active:httpPut");
		
		//specifiy the request URL
		subRequest.addArgument("url", 
				"http://localhost:8080/spring-auditor/audit/event/" + eventID);
		
		//add the body to the request
		subRequest.addArgumentByValue("body", xml);
		
		//specify the body content type
		HDSBuilder builder = new HDSBuilder();
		builder.addNode("Content-Type", "application/xml");
		builder.addNode("Accept", "application/xml");
		
		//issue the sub-request
		subRequest.addArgumentByValue("headers", builder.getRoot());
		
		//return the reponse from the sub-request
        return context.issueRequest(subRequest);
	}	
}