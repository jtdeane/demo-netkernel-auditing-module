package cogito.security;

import org.netkernel.layer0.nkf.INKFRequest;
import org.netkernel.layer0.nkf.INKFRequestContext;
import org.netkernel.layer0.representation.impl.HDSBuilder;
import org.netkernel.module.standard.endpoint.StandardAccessorImpl;

/**
 * Handles processing of audit events
 */
public class SecurityAccessor extends StandardAccessorImpl {
	
	/**
     * Default constructor
     */
	public SecurityAccessor() {	
		this.declareThreadSafe();
	}
	
	@Override
	public void onSource(INKFRequestContext context) throws Exception {
		
        //get the audit event xml
		String xml = (String)context.source("httpRequest:/body", String.class);
		
		//submit the audit event to the Provider
		Object response = submitAuditEvent(xml, context);
        
		//return a response to the Consumer
		context.createResponseFrom(response);
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