import com.fortify.samples.thirdparty.component.Utility;

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
	
	// Fortify SCA will arrive at the wrong conclusion here
	// sendEmergencyBroad might send sensitive information that it shouldn't be, resulting in information leakage
	// Fortify SCA does not recognize this because we use an unrecognized third-party library with no source code
	// It will conclude that this function does not transmit or store data
		
	private int sendEmergencyBroadcast(String message)
	{
		int result = 0;
		// Validate the contents of the message
		if ((message == null) || (message.length() == 0))
			return 0;
		
		result = thirdPartyLibrary.activateEmergencyResponse(message);
		return result;
	}
	
	// Fortify SCA will arrive at the wrong conclusion here
	// removeSensitiveInformation is a function that removes sensitive information
	// Fortify SCA will not recognize this because we use an unrecognized third party-library with no source code
	// It will conclude that the returned String is not cleansed
	// It will also conclude that the incoming data is not connected to the outgoing return value
	
	private String removeSensitiveInformation(String data)
	{
		String result = "";
		result = thirdPartyLibrary.removePrivacyData(data);
		return result;
		
	}
	
	// Fortify SCA will arrive at the wrong conclusion here
	// removeSensitiveInformationFromException is a function that removes sensitive information from an Exception object
	// Fortify SCA will not recognize this because we use an unrecognized third party-library with no source code
	// It will conclude that the returned Exception still contains sensitive information
	// It will also conclude that the incoming data is not connected to the outgoing return value
	
	private String removeSensitiveInformationFromException(Exception e)
	{
		Exception sanitizedException = thirdPartyLibrary.sanitizeException(e);
		return sanitizedException.getMessage();
	}
	
	private int logApplicationException(int eventType, int category, Exception e)
	{
		int result = 0;
		result = thirdPartyLibrary.logEventToDisk(eventType, category, e.getMessage(), e.toString());
		
		if ((category == EventType.CRITICAL) && (result != 0))
			{
			// TODO: eliminate false negative
			
			// Fortify SCA will produce a false negative here
			// The function sendEmergencyBroadcast sends information to users
			// Fortify SCA does not recognize this because we use an unrecognized third-party library with no source code
			// As a result, no warnings will be reported that system information may be leaked through this broadcast
			
			String exceptionMessage = e.getMessage();
			result = sendEmergencyBroadcast(exceptionMessage);
			}
		
		// TODO: eliminate false positive
		
		// Fortify SCA will produce a false positive here
		// The function removeSensitiveInformationFromException cleanses an Exception object
		// Fortify SCA does not recognize this because we use an unrecognized third-party library with no source code
		// As a result, a warning will be reported that sensitive information may have leaked 
		
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
	
	// Fortify SCA will arrive at the wrong conclusion here
	// loadConfiguration is a function that returns sensitive system information
	// Fortify SCA does not recognize this because we use an unrecognized third-party library with no source code
	// It will conclude that no sensitive information is returned from this function
	
	private String[] loadConfiguration()
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
			
			// Fortify SCA will be misled here
			// It will not recognize the transaction key as sensitive data
			// It normally looks for more obvious keywords when trying to identify a variable holding sensitive data
			
			String sensitiveTransactionKey = serverConfigData[3];
			if ((sensitiveTransactionKey == null) || (sensitiveTransactionKey.length() == 0))
				throw new ApplicationException("Configuration file corrupt");
			
			// Fortify SCA will arrive at the wrong conclusion here
			// The variable is not actually an authentication credential
			// Fortify SCA will assume it is by default due to its naming convention
			
			String passwordLabel = serverConfigData[4];
			if ((passwordLabel == null) || (passwordLabel.length() == 0))
				throw new ApplicationException("Configuration file corrupt");
			
			// TODO: eliminate false positive
			
			// Fortify SCA will produce a false positive here
			// This variable has now been assumed to contain sensitive information due to the previous false conclusion
			// Fortify SCA will see sensitive information being dumped to a console and report it as informtion leakage
			
			System.err.println("Password label is " + passwordLabel);
			
			String debugNote = "Server configuration data loaded: parameters = " +
								"host = " + serverHostname + " " +
								"sensitive access code = " + internalAccessCode + " " +
								"database table = " + databaseTable + " " + 
								"sensitive transaction key = " + sensitiveTransactionKey;
		
			// TODO: eliminate false negative
			
			// Fortify SCA will produce a false negative here
			// It will not recognize that the information being dumped is sensitive (sensitiveTransactionKey)
			// It is bad practice to dump sensitive information in a non-secure way
			// It should always be sanitized and written to disc securely
			
			logProgrammerNote(debugNote);
			
		}
		catch (ApplicationException e)
		{
			logApplicationException(EventType.CRITICAL, EventTargetDatabase.APPLICATION, e);
		}
		return serverConfigData;
	}
	
	private String getSocialSecurityNumber(String userID)
	{
		// Sample internal function that returns privacy-related data
		return "123-45-6789";
	}
	
	// Fortify SCA will arrive at the wrong conclusion here
	// sanitizedCreditCardData is a function that makes credit card data safe to display on a screen
	// Fortify SCA does not recognize this because we use an unrecognized third-party library with no source code
	// It will conclude that any returned data is still dangerous
	
	private String sanitizeCreditData(String ccData) throws ApplicationException
	{
		if ((ccData == null) || (ccData.length() == 0))
			throw new ApplicationException("Invalid ccData");
		
		String result = thirdPartyLibrary.sanitizeCreditCardDataDisplay(ccData);
		return result;
	}
	
	// Fortify SCA will arrive at the wrong conclusion here
	// retrieveCreditCardData is a function that returns sensitive data from an external source
	// Fortify SCA does not recognize this because we use an unrecognized third-party library with no source code
	// It will conclude that the returned data is not sensitive
	// It will also conclude that the function is not a source of data
	
	private String retrieveCreditCardData(String userID)
	{
		// Fortify SCA will arrive at the wrong conclusion here
		// The key variable is an authentication credential and is sensitive information
		// Fortify SCA will assume it is not based on its unconventional name
		
		String privateSymmetricKey = "WQEQWEQWESDFGHK%YLHGBDFG:#@${$RT{GR4;@";
		String userCreditCardInfoSecurityToken = "";
		try
		{
			if ((userID == null) || (userID.length() == 0))
				throw new ApplicationException("userID invalid");
			
			userCreditCardInfoSecurityToken = thirdPartyLibrary.loadCreditCardInfo(userID, privateSymmetricKey);
			
			// TODO: eliminate false negative
			
			// Fortify SCA will produce a false negative here
			// Sensitive data is being written to a database in a non-secure manner
			// Fortify SCA will not recognize that the logAuditEvent function represents a database
			
			logAuditEvent("Credit card data retrieved for user " + userID + " (CC: " + userCreditCardInfoSecurityToken + " )");
			
			// TODO: eliminate false negative
			
			// Fortify SCA will produce a false negative here
			// Sensitive data is being removed before it is being sent to the error console
			// Fortify SCA does not know this however because of a previously wrong conclusion (see function declaration)
			
			String safeCreditCardDisplayString = sanitizeCreditData(userCreditCardInfoSecurityToken);
			System.err.println("Safe credit card data displayed for user: " + safeCreditCardDisplayString);
			
		}
		catch (ApplicationException e)
		{
			logApplicationException(EventType.FAIL, EventTargetDatabase.APPLICATION, e);
		}
		return userCreditCardInfoSecurityToken;
	}
	
	// Fortify SCA will arrive at the wrong conclusion here
	// This function returns sensitive information from a data source
	// Fortify SCA does not recognize this because we use an unrecognized third-party library with no source code
	// It will conclude that the returned data is not sensitive
	// It will also conclude that the function is not a source of data
	
	private String[] loadUserProfile(String userID)
	{
		String[] userProfileData = null;
		try
		{
			// Perform validation on incoming userID parameter
			if ((userID == null) || (userID.length() == 0))
				throw new ApplicationException("userID invalid");
			
			userProfileData = thirdPartyLibrary.loadUserDataFromDatabase(userID);
			String userAuthenticationCredential = userProfileData[1];
			
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

	// Fortify SCA will arrive the the wrong conclusion here
	// This function takes incoming data and posts it an external data repository for subsequent processing
	// Fortify SCA will not recognize this because we use an unrecognized third-party library with no available source code
	// It will conclude that this function does not act as a repository for data
	// It will not recognize that the userID function contains HTML data that poses a XSS risk
	
	private int postInformation(String[] hostInformation, String userID, String[] userData, String userCreditCardData, String[] financialInstrumentInformation)
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
			String userAuthenticationCredential = userData[1];
			if ((userAuthenticationCredential == null) || (userAuthenticationCredential.length() == 0))
			{
				logProgrammerNote("user password not included in submission");
				throw new ApplicationException("user password not included in submission");
			}
			
			if ((userAuthenticationCredential.length() != 10) || (!userAuthenticationCredential.matches("[A-Za-z]{7}[0-9]{3}")))
			{
				// TODO: eliminate false negative
				
				// Fortify SCA will produce a false negative here
				// logSecurityEvent writes data to a repository; Fortify SCA does not know this
				// userAuthenticationCredential is a piece of sensitive information; Fortify SCA does not know this
				// Fortify SCA will not recognize that sensitive information is being written to disc non-securely
				
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
				// TODO: eliminate false negative
				
				// Fortify SCA will produce a false negative here
				// logSecurityEvent writes data to a repository; Fortify SCA does not know this
				// userCreditCardData is a piece of sensitive information; Fortify SCA does not know this
				// Fortify SCA will not recognize that sensitive information is being written to disc non-securely
				
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
	
	// Fortify SCA will arrive at the wrong conclusion here
	// This function transforms incoming data and returns it
	// Fortify SCA will not recognize this because we use an unrecognized third-party library with no available source code
	// It will conclude that data is not flowing from an incoming to outgoing parameter, possibly spreading dangerous data
	
	private String[] localizeFinancialInstruments(String[] rawFinancialInstruments) {
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
	
	private String[] sanitizeUserDataForDisplay(String[] userProfileData) {
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

	// Fortify SCA will arrive at the wrong conclusion here
	// This function returns sensitive financial information about a user
	// Fortify SCA will not recognize this because we use an unrecognized third-party library with no available source code
	// It will conclude that returned data is not sensitive
	// It will also conclude that the returned data is not coming from an external source
	
	private String[] loadFinancialInstruments(String userID) {
		String rawFinancialInstruments[] = null;
		try
		{
			if ((userID == null) || (userID.length() == 0))
				throw new ApplicationException("userid invalid");
			
			rawFinancialInstruments = thirdPartyLibrary.retrieveStockDataFromWebSource("ExternalGateway", 8100);
			logAuditEvent("financial instruments retrieved for user " + userID);
			
			// Fortify SCA will arrive at the wrong conclusion here
			// A piece of sensitive information is being sanitized and them dumped to a data source in a secure manner
			// This is the secure and desirable behavior
			
			// Fortify SCA does not recognize what the sanitizing function does
			// It also does not recognize that data flows from the incoming sanitizing parameter to outgoing parameter
			// It concludes that data is not flowing directly to the console
			// Hence, it conclude this is not a security issue
			
			// Although it arrived at the right answer, it did so based on wrong conclusions 
			
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
