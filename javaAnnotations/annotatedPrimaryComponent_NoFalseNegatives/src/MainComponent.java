import com.fortify.samples.thirdparty.component.Utility;
import com.fortify.annotations.*;

public class MainComponent {

	/**
	 * @param args
	 */
	private static Utility thirdPartyLibrary = new Utility();
	private class EventType
	{
		final static int INFO = 0;
		final static int WARNING = 1;
		final static int FAIL = 2;
		final static int CRITICAL = 3;
		final static int UNKNOWN = 4;
		final static int DEBUG = 5;
	}
	
	private class EventTargetDatabase
	{
		final static int APPLICATION = 0;
		final static int SECURITY = 1;
		final static int REPORTS = 2;
		final static int ACTION = 3;
		final static int UNKNOWN = 4;
		final static int AUDIT = 5;
	}
	
	public static class ApplicationException extends Exception {

		public ApplicationException(String string) {
			super(string);
		}

		/**
		 * 
		 */
		private static final long serialVersionUID = 1L; };
	
	// Fortify SCA will now arrive at the right conclusion here
	// sendEmergencyBroad might send sensitive information that it shouldn't be, resulting in information leakage
	// It will now conclude that this function transmits system information
	
	private
	@FortifySystemInfoSink("message")
	int sendEmergencyBroadcast(String message)
	{
		int result = 0;
		// Validate the contents of the message
		if ((message == null) || (message.length() == 0))
			return 0;
		
		result = thirdPartyLibrary.activateEmergencyResponse(message);
		return result;
	}
	
	// Fortify SCA will now arrive at the right conclusion here
	// removeSensitiveInformation is a function that removes sensitive information
	// It will now conclude that the returned String is cleansed for privacy-related data
	// It will also now conclude that the incoming data is connected to the outgoing return value
	
	private 
	@FortifyPassthrough(in="data", out="return") 
	@FortifyPrivacyValidate("return") 
	String removeSensitiveInformation(String data)
	{
		String result = "";
		result = thirdPartyLibrary.removePrivacyData(data);
		return result;
		
	}
	
	// Fortify SCA will now arrive at the right conclusion here
	// removeSensitiveInformationFromException is a function that removes sensitive information from an Exception object
	// It will now conclude that the returned Exception message no longer contains sensitive information
	// It will also now conclude that the incoming data is connected to the outgoing return value
	
	private 
	@FortifyPrivacyValidate("return")
	@FortifySystemInfoValidate("return")
	String removeSensitiveInformationFromException(Exception e)
	{
		Exception sanitizedException = thirdPartyLibrary.sanitizeException(e);
		return sanitizedException.getMessage();
	}
	
	private
	@FortifySystemInfoSink("e")
	int logApplicationException(int eventType, int category, Exception e)
	{
		int result = 0;
		result = thirdPartyLibrary.logEventToDisk(eventType, category, e.getMessage(), e.toString());
		
		if ((category == EventType.CRITICAL) && (result != 0))
			{
			// TODO: Fortify SCA will now correctly report a 'System Information Leak' below
			
			// The function sendEmergencyBroadcast sends information to users
			// Fortify SCA now recognizes that the broadcast function acts like a final sink for data
			
			String exceptionMessage = e.getMessage();
			result = sendEmergencyBroadcast(exceptionMessage);
			}
		
		// TODO: Fortify SCA no longer reports a 'System Information Leak' below
				
		// The function removeSensitiveInformationFromException cleanses an Exception object
		// Fortify SCA now recognizes this because of the cleanse annotation on the sanitization function
		
		String sanitizedExceptionMessage = removeSensitiveInformationFromException(e);
		System.err.println(sanitizedExceptionMessage);
		return result;
		
	}
	
	private int logProgrammerNote(String message)
	{
		int result = 0;
		result = logApplicationException(EventType.DEBUG, EventTargetDatabase.APPLICATION, new Exception(message));
		return result;
	}
	
	private int logAuditEvent(String message)
	{
		int result = 0;
		result = logApplicationException(EventType.INFO, EventTargetDatabase.AUDIT, new Exception(message));
		return result;
	}
	
	private int logSecurityEvent(String message)
	{
		int result = 0;
		result = logApplicationException(EventType.WARNING, EventTargetDatabase.SECURITY, new Exception(message));
		return result;
	}
	
	// Fortify SCA will now arrive at the right conclusion here
	// loadConfiguration is a function that returns sensitive system information
	// Fortify SCA will now conclude that this function acts as a filesystem source of data
	
	private 
	@FortifyFileSystemSource("return")
	String[] loadConfiguration()
	{
		String[] serverConfigData = null;
		try
		{
			serverConfigData = thirdPartyLibrary.loadServerConnectProperties();
			
			// Validate the contents of the configuration file
			String serverHostname = serverConfigData[0];

			if ((serverHostname == null) || (serverHostname.length() == 0))
				throw new ApplicationException("Configuration file corrupt");
			
			String internalAccessCode = serverConfigData[1];
			if ((internalAccessCode == null) || (internalAccessCode.length() == 0))
				throw new ApplicationException("Configuration file corrupt");
			
			String databaseTable = serverConfigData[2];
			if ((databaseTable == null) || (databaseTable.length() == 0))
				throw new ApplicationException("Configuration file corrupt");
			
			// Fortify SCA will now recognize the transaction key as sensitive data
			
			@FortifyPassword String sensitiveTransactionKey = serverConfigData[3];
			if ((sensitiveTransactionKey == null) || (sensitiveTransactionKey.length() == 0))
				throw new ApplicationException("Configuration file corrupt");
			
			// The variable is not actually an authentication credential
			// Fortify SCA will now assume it is no longer a sensitive piece of information
			
			@FortifyNotPassword String passwordLabel = serverConfigData[4];
			if ((passwordLabel == null) || (passwordLabel.length() == 0))
				throw new ApplicationException("Configuration file corrupt");
			
			// TODO: an original false positive of 'Privacy Violation' should no longer be reported
			
			// Fortify SCA will no longer produce a false positive here
			// This variable has now been assumed to contain no sensitive information
			// Fortify SCA will no longer see sensitive information being dumped to a console
			
			System.err.println("Password label is " + passwordLabel);
			
			String debugNote = "Server configuration data loaded: parameters = " +
								"host = " + serverHostname + " " +
								"sensitive access code = " + internalAccessCode + " " +
								"database table = " + databaseTable + " " + 
								"sensitive transaction key = " + sensitiveTransactionKey;
		
			// TODO: an original false negative will now be correctly reported as a privacy violation
			// Fortify SCA will now recognize the sensitiveTransactionKey as a password
			
			logProgrammerNote(debugNote);
			
		}
		catch (ApplicationException e)
		{
			logApplicationException(EventType.CRITICAL, EventTargetDatabase.APPLICATION, e);
		}
		return serverConfigData;
	}
	
	private
	@FortifyPrivateSource("return")
	String getSocialSecurityNumber(String userID)
	{
		// Sample internal function that returns privacy-related data
		return "123-45-6789";
	}
	
	// Fortify SCA will now arrive at the right conclusion here
	// sanitizedCreditCardData is a function that makes credit card data safe to display on a screen
	// Fortify SCA will now recognize that returned data is no longer dangerous
	
	private 
	@FortifyPCIValidate("return")
	String sanitizeCreditData(String ccData) throws ApplicationException
	{
		if ((ccData == null) || (ccData.length() == 0))
			throw new ApplicationException("Invalid ccData");
		
		String result = thirdPartyLibrary.sanitizeCreditCardDataDisplay(ccData);
		return result;
	}
	
	// Fortify SCA will now arrive at the right conclusion here
	// retrieveCreditCardData is a function that returns sensitive data from an external source
	// Fortify SCA will now conclude that the returned data is sensitive
	// Fortify SCA will also conclude that the function is a source of data
	
	private 
	@FortifyPCISource("return")
	String retrieveCreditCardData(String userID)
	{
		// Fortify SCA should now arrive at the right conclusion here
		// The key variable is an authentication credential and is sensitive information
		// Fortify SCA will now assume it is
		
		@FortifyPassword String privateSymmetricKey = "WQEQWEQWESDFGHK%YLHGBDFG:#@${$RT{GR4;@";
		@FortifyPassword String userCreditCardInfoSecurityToken = "";
		try
		{
			if ((userID == null) || (userID.length() == 0))
				throw new ApplicationException("userID invalid");
			
			userCreditCardInfoSecurityToken = thirdPartyLibrary.loadCreditCardInfo(userID, privateSymmetricKey);
			
			// TODO: Fortify SCA should now correctly report this as a 'Privacy Violation'
			
			// Sensitive data is being written to a database in a non-secure manner
			// Fortify SCA will now recognize that the logAuditEvent function represents a database
			// Fortify SCA will now recognize that the token is a sensitive variable
			
			logAuditEvent("Credit card data retrieved for user " + userID + " (CC: " + userCreditCardInfoSecurityToken + " )");
			
			// TODO: Fortify SCA will now recognize the sanitize function as cleaning the 
			// newly declared sensitive variable
			
			String safeCreditCardDisplayString = sanitizeCreditData(userCreditCardInfoSecurityToken);
			System.err.println("Safe credit card data displayed for user: " + safeCreditCardDisplayString);
			
		}
		catch (ApplicationException e)
		{
			logApplicationException(EventType.FAIL, EventTargetDatabase.APPLICATION, e);
		}
		return userCreditCardInfoSecurityToken;
	}
	
	// Fortify SCA will now arrive at the right conclusion here
	// This function returns sensitive information from a data source
	// Fortify SCA will now conclude that the function is a source of data
	
	private 
	@FortifyDatabaseSource("return") 
	String[] loadUserProfile(String userID)
	{
		String[] userProfileData = null;
		try
		{
			// Perform validation on incoming userID parameter
			if ((userID == null) || (userID.length() == 0))
				throw new ApplicationException("userID invalid");
			
			userProfileData = thirdPartyLibrary.loadUserDataFromDatabase(userID);
			@FortifyPassword String userAuthenticationCredential = userProfileData[1];
			
			// Make programmer note of user pulled from database
			// Bad Security Practice: sensitive data is not sanitized or written to disc securely
			String debugNote = "user " + userID + " loaded from database; password = " + userAuthenticationCredential;
			logProgrammerNote(debugNote);
			logAuditEvent("user " + userID + " processed.");
		}
		catch (ApplicationException e)
		{
			logApplicationException(EventType.FAIL, EventTargetDatabase.APPLICATION, e);
		}
		return userProfileData;
	}
	
	public static void main(String[] args) {
		MainComponent mainObject = new MainComponent();
		try
		{
			String userID = args[0];
			if ((userID == null) || (userID.length() == 0) || args.length != 1)
			{
				mainObject.logSecurityEvent("unexpected execution of middleware application with invalid parameters");
				throw new ApplicationException("invalid command line argument passed to application");
			}
			
			mainObject.logAuditEvent("user processing iniated");
			
			// Step 1: Load configuration data
			String[] configurationData = mainObject.loadConfiguration();
			
			// Step 2: Load credit card data of user from another source
			String userCreditCardData = mainObject.retrieveCreditCardData(userID);
			
			// Step 3: Load corresponding user data from database for subsequent processing
			String[] userProfileData = mainObject.loadUserProfile(userID);
			
			// Step 4: Load financial instruments belonging to user
			String rawFinancialInstruments[] = mainObject.loadFinancialInstruments(userID);
			
			// Step 5: Sanitize all data entered by user for safe display
			String[] sanitizedUserProfileData = mainObject.sanitizeUserDataForDisplay(userProfileData);
			
			// Step 6: Transform data to user's own culture
			String[] cultureFriendlyFinancialInstruemnts = mainObject.localizeFinancialInstruments(rawFinancialInstruments);
			
			// Step 7: Formulate and submit HTML page with provided data 
			int result = mainObject.postInformation(configurationData, userID, sanitizedUserProfileData, userCreditCardData, cultureFriendlyFinancialInstruemnts);
			if (result != 0)
			{
				if (result == 2)
				{
					// Security violation
					mainObject.logSecurityEvent("user processing failed due to security issue");	
				}
				
				// Unexpected submission failure
				throw new ApplicationException("Unexpected post failure, error code: " + result);
			}
			mainObject.logAuditEvent("user processing terminated with no problems");
		}
		catch( ApplicationException e )
		{
			mainObject.logProgrammerNote(e.getMessage());
			mainObject.logAuditEvent("user processing failed unexpectedly");
		}
	}

	// Fortify SCA will now arrive at the the right conclusion here
	// This function takes incoming data and posts it to an external data repository for subsequent processing
	// Fortify SCA will now conclude that this function not act as a repository for data
	// Fortify SCA will now recognize that the userID function contains HTML data that poses a XSS risk
	
	private 
	@FortifyXSSSink("userData")
	@FortifyPrivacySink("userCreditCardData")
	int postInformation(String[] hostInformation, String userID, String[] userData, String userCreditCardData, String[] financialInstrumentInformation)
	{
		int result = 0;
		try
		{
			if ((hostInformation == null) || (hostInformation.length != 4))
				{
				logProgrammerNote("hostInformation not included in submission");
				throw new ApplicationException("host information for submission invalid");
				}
			
			// Validate the hostname
			String hostname = hostInformation[0];
			if (!hostname.matches("internal[A-Z]{2}"))
			{
				logSecurityEvent("Attempt to submit to unexpected host " + hostname);
				throw new ApplicationException("unexpected host");
			}
			
			// Validate the userID
			if ((userID == null) || (userID.length() == 0))
			{
				logProgrammerNote("userID not included in submission");
				throw new ApplicationException("userid not included in submission");
			}
			
			// Validate the user authentication credential
			@FortifyPassword String userAuthenticationCredential = userData[1];
			if ((userAuthenticationCredential == null) || (userAuthenticationCredential.length() == 0))
			{
				logProgrammerNote("user password not included in submission");
				throw new ApplicationException("user password not included in submission");
			}
			
			if ((userAuthenticationCredential.length() != 10) || (!userAuthenticationCredential.matches("[A-Za-z]{7}[0-9]{3}")))
			{
				// TODO: Fortify SCA should now recognize that the authentication credential is a password
				
				// Fortify SCA will now report a privacy violation
				// logSecurityEvent writes data to a repository; Fortify SCA now knows this
				// userAuthenticationCredential is a piece of sensitive information; Fortify SCA now knows this
				// Fortify SCA will now recognize that sensitive information is being written to disc non-securely
				
				logSecurityEvent("invalid user credential supplied: userid = " + userID + "; credential = "+userAuthenticationCredential);
				throw new ApplicationException("user password does not conform to policy");
			}
			
			// Validate the credit card data
			if (userCreditCardData == null)
			{
				logProgrammerNote("credit card data not included in submission");
				throw new ApplicationException("credit card data not included in submission");
			}
			
			if ((userCreditCardData.length() != 16) || (userCreditCardData.matches("[0-9]{16}")))
			{
				// TODO: Fortify SCA should now correctly report a privacy violation
				
				// Fortify SCA will now produce a privacy violation
				// logSecurityEvent writes data to a repository; Fortify SCA should now know this
				// userCreditCardData is a piece of sensitive information; Fortify SCA should now know this
				// Fortify SCA will now recognize that sensitive information is being written to disc non-securely
				
				logSecurityEvent("suspicious credit card format: " + userCreditCardData);
			}
			
			// Optional data elements
			String userEmailAddress = userData[2];
			String userCustomNotes = userData[3];
			
			logAuditEvent("Posting user information to host: "+hostInformation[0]);
			
			result = thirdPartyLibrary.postHTMLResponse(userID, userAuthenticationCredential, userEmailAddress, userCustomNotes, financialInstrumentInformation);
		}
		catch (ApplicationException e)
		{
			logAuditEvent("submission for processing failed: internal message" + e.getMessage());
		}
		return result;
		
	}
	
	// Fortify SCA will now arrive at the right conclusion here
	// This function transforms incoming data and returns it
	// Fortify SCA will conclude that data is flowing from an incoming to outgoing parameter, possibly spreading dangerous data
	
	private 
	@FortifyPassthrough(in="rawFinancialInstruments", out="return") 
	String[] localizeFinancialInstruments(String[] rawFinancialInstruments) {
		int index = 0;
		String[] returnData = null;
		
		try
		{
			if ((rawFinancialInstruments == null) || (rawFinancialInstruments.length == 0))
			{
				throw new ApplicationException("rawFinancialInstrument data invalid");
			}
			
			returnData = new String[rawFinancialInstruments.length];
			
			for (index = 0; index < rawFinancialInstruments.length; index++)
			{
				String incomingStringElement = rawFinancialInstruments[index];
				if (incomingStringElement != null)
				{
					// Convert any incoming financial stock information to local culture
					thirdPartyLibrary.reformatStockData(rawFinancialInstruments[index], returnData[index]);
				}
				else
					throw new ApplicationException("rawFinancialInstrument [" + index + "] null");
			}
		}
		catch (ApplicationException e)
		{
			logProgrammerNote(e.getMessage());
		}
		return returnData;
	}


	// This function takes incoming data, transforms it into safe data, and returns it
	
	private 
	@FortifyXSSValidate("return")
	String[] sanitizeUserDataForDisplay(String[] userProfileData) {
		int index = 0;
		String[] returnData = null;
		
		try
		{
			if ((userProfileData == null) || (userProfileData.length == 0))
			{
				throw new ApplicationException("userProfileData invalid");
			}
			
			returnData = new String[userProfileData.length];
			
			for (index = 0; index < userProfileData.length; index++)
			{
				String incomingStringElement = userProfileData[index];
				if (incomingStringElement != null)
				{
					
					// Convert any incoming data element to HTML entity equivalents
					incomingStringElement.replaceAll("<", "&lt");
					incomingStringElement.replaceAll(">", "&gt");
					incomingStringElement.replaceAll("&", "&amp;");
					incomingStringElement.replaceAll("\"", "&quot;");
					incomingStringElement.replaceAll("'", "&apos;");
					returnData[index] = incomingStringElement;
					
					if (returnData[index].compareTo(userProfileData[index]) != 0)
					{
						// Suspicious data has been found, report it
						logSecurityEvent("Suspcious data found for user: "+returnData[index]);
					}
				}
				else
					throw new ApplicationException("userProfileData[" + index + "] invalid");
			}
		}
		catch (ApplicationException e)
		{
			logProgrammerNote(e.getMessage());
		}
		
		return returnData;
	}

	// Fortify SCA will now arrive at the right conclusion here
	// This function returns sensitive financial information about a user
	// Fortify SCA will now conclude that returned data is sensitive
	// Fortify SCA will also now conclude that the returned data is coming from an external source
	
	private 
	@FortifyPrivateSource("return") 
	String[] loadFinancialInstruments(String userID) {
		String rawFinancialInstruments[] = null;
		try
		{
			if ((userID == null) || (userID.length() == 0))
				throw new ApplicationException("userid invalid");
			
			rawFinancialInstruments = thirdPartyLibrary.retrieveStockDataFromWebSource("ExternalGateway", 8100);
			logAuditEvent("financial instruments retrieved for user " + userID);
			
			// Fortify SCA will now arrive at the right conclusion here
			// A piece of sensitive information is being sanitized and them dumped to a data source in a secure manner
			// This is the secure and desirable behavior
			
			// Fortify SCA now recognizes what the sanitizing function does
			// It also now recognizes that data flows from the incoming sanitizing parameter to outgoing parameter
			// It also concludes that data is now flowing directly to the console
			// Hence, it conclude this is now a security issue
			
			// It now arrives at the right answer based on the right conclusions 
			
			String data = getSocialSecurityNumber(userID);
			String sanitizedData = removeSensitiveInformation(data);
			System.err.println("Dumping a sanitized SSN to a console should now be safe: "+sanitizedData);
		}
		catch (ApplicationException e)
		{
			logProgrammerNote(e.getMessage());
		}
		
		return rawFinancialInstruments;
	}

}
