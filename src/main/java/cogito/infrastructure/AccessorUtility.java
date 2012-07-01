package cogito.infrastructure;

import java.io.CharArrayReader;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.netkernel.layer0.nkf.INKFRequestContext;
import org.netkernel.layer0.nkf.INKFResponse;
import org.netkernel.layer0.representation.impl.HDSBuilder;
import org.netkernel.xml.xda.DOMXDA;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

/**
 * <code>AccessorUtility</code> provides utility methods for the personnel
 * resource accessors
 * @author jdeane
 * @version 1.0
 */
public class AccessorUtility {
	
	/**
	 * Extract document from the context
	 * @param context
	 * @return DOMXDA
	 * @throws Exception
	 */
	public static DOMXDA extractDocumentFromHTTPBody(INKFRequestContext context) 
		throws Exception {

		return new DOMXDA(createDocumentFromString
				((String)context.source("httpRequest:/body", String.class)));
	}
	
	/**
	 * Return a simple error message
	 * @param context
	 * @param errorMessage
	 * @throws Exception
	 */
	public static void handleError(INKFRequestContext context, String errorMessage) 
		throws Exception {
        
		HDSBuilder builder = new HDSBuilder();
		builder.pushNode("error", errorMessage);
		
        INKFResponse response = context.createResponseFrom(builder.getRoot());
        response.setExpiry(INKFResponse.EXPIRY_ALWAYS);
        response.setMimeType("application/xml");
	}
	
	/**
	 * Return a message
	 * @param context
	 * @param message
	 */
	public static void returnMessage(INKFRequestContext context, String message) {
		
	    //4. RETURN A RESPONSE            
		HDSBuilder builder = new HDSBuilder();
		builder.pushNode("message", message);
		
	    INKFResponse response = context.createResponseFrom(builder.getRoot());
	    response.setExpiry(INKFResponse.EXPIRY_ALWAYS);
	    response.setMimeType("application/xml");
	}
    
    /**
     * This method creates a Document object from an XML String.
     * @param xml - strings
     * @return Document
     * @throws Exception
     */
    public static Document createDocumentFromString(String xml) 
        throws Exception {
        
        //method variables
        InputSource in = null;
        DocumentBuilder builder = null;
        
        //create a document builders
        builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        
        //create the input source
        in = new InputSource(new CharArrayReader(xml.toCharArray()));
        
        return builder.parse(in);
    }
}