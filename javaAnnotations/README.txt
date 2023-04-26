============
Introduction
============

For detailed information about all of the Fortify Java Annotations, please use the Fortify Static Code Analyzer User Guide for reference. 

The goal of this example is to illustrate how the use of Fortify Annotations can result in increased accuracy in the reported vulnerabilities.  The following sections illustrate the potential problems and solutions associated with vulnerability results.

==================
Sample Description
==================

The application acts as a middleware component within a larger project.  This component is executed after a user has already logged into the solution.  Upon startup, this component grabs many different types of information about the give user and packages it together for subsequent processing in a front-end user interface.  Credit-card data is presented to the user along with other personal information in a sidebar of the main front-end interface.  The application relies upon third-party libraries to retrieve, transform, and post information relevant to the user.  Logging and auditing requirements dictate that this component uses a third-party library responsible for processing relevant security events.

In this example application, none of the third party libraries include source code.  Fortunately, Fortify SCA recognizes some of the libraries and is able to observe any security vulnerabilities based on this previous knowledge.  However, other less popular libraries are unknown.  As such, there is a risk that false negatives or false positives may result due to a lack of understanding of these third-party libraries.

Developers can include Java annotations to describe the underlying libraries and give Fortify SCA enough information to discover the security vulnerabilities that may result from the use of these libraries.  In the Java example provided, annotations have been added to the appropriate wrapper that is used to call the corresponding third-party method.

----------------------------------
Potential Security Vulnerabilities
----------------------------------

This application mainly handles and processes lots of sensitive data.  There are many vulnerabilities that result from processing dangerous ("tainted") data.  Particularly popular vulnerabilities within this class include the following: Cross Site scripting (XSS), SQL Injection, and Information Leakage.

In order to detect these types of vulnerabilities, Fortify SCA traces data as it flows through an application.  Data flows from a source such as a database, web service, or user interface.  Data flows towards a sink for subsequent processing.  An example is a SQL database.  Fortify SCA detects this class of data vulnerabilities by recognizing sources and sinks.  It must trace the flow of data (pass-through functions) from the source to the sink.  If tainted data leaves a source and reaches a sink without being cleansed (through a cleanse function), a vulnerability has occurred.

It is critical that the engine recognizes all forms of sources, sinks, pass-through functions, and cleanse functions within the application in order to find serious vulnerabilities.  Unrecognized third-party libraries pose problems for the engine.  It may not recognize some sources, sinks, pass-through functions, or cleanse functions.  As a result, vulnerabilities may go undetected or be falsely reported.

----------------------------
Unidentified Sources of Data
----------------------------

One should expect Fortify SCA to detect all sources and sinks of information.  However, these sources are disguised in this example through the thirdPartyLibrary component.  Source code is not available for these components.  Hence, Fortify SCA will not be able to detect any data validation issues that relate to the information flowing from these sources of data.

loadConfiguration()
This is a data source that returns information about the application's environment through the filesystem.

loadFinancialInstruments(...)
This is a data source that returns privacy-related financial information.

loadUserProfile(...)
This is a data source that returns user information from an application database.

retrieveCreditCardData(...)
This is a data source that returns sensitive credit-card data about the user from a PCI-related source.

--------------------------
Unidentified Sinks of Data
--------------------------

Data flows from a source to a sync.  Many different types of security vulnerabilities cannot be discovered without recognizing the sync of a data flow.  In this example, there are several syncs of data that are hidden as a result of using a third party library.  Java annotations assist aid Fortify SCA in identifying the data syncs within an application.

logApplicationException(...)
This function allows data to be logged to a repository.  Data flows from the system towards the repository through this function.  Many vulnerabilities may result from not properly handling the data before it enters this sync.

logAuditEvent(...)
Events are logged to an auditing database through this function.  Essentially, an event is described and enters this function to be submitted to some backend for subsequent processing.  Special security precautions must be considered when submitting data to this table as sensitive information may be leaked by accident.

logProgrammerNote(...)
Programmers may need to try debugging part of an application in runtime.  This function allows the programmer to submit notes to a repository where it is eventually written to disc.  The programmer must be very careful in what they write to disc.  They may disclose the internal architecture of their application to an adversary through this sync.

logSecurityNote(...)
This function allows a developer to submit special application security events to a repository for subsequent repository.  The developer may accidentally submit notes that are unencrypted or could easily be intercepted by an adversary.

postInformation(...)
This function processes a given set of data and posts a response that is eventually sent to the user through their web browser.  Data flows from the middleware application to a backend for processing.  Many different types of vulnerabilities may occur through incorrect handling of this data sync.

sendEmergencyBroadcast(...)
This function allows the system to page a staff member when a particularly critical event has occurred that requires immediate attention.  This is a sync of data because data is flowing from the system towards this function and out to the user.  There are many vulnerabilities that result from the use of this sync such as accidental sensitive information disclosure.

-----------------------------------
Unidentified Pass-Through Functions
-----------------------------------

A pass-through function is a function that transfers data from one parameter to another within a given function call.  Data flows from one parameter to another.  Pass-through functions aid in the detection of data validation vulnerabilities.  If functions are not recognized as pass-through functions correctly, entire classes of security vulnerabilities may not be discovered.

Unrecognized third-party libraries are particularly problematic with respect to unrecognized pass-through functions.  The inability to trace data through these libraries may result in false negatives.  It is very important to use Java Annotations or rules to accurately describe the flow of data through these unrecognized components.

removeSensitiveInformation(String)
removeSesntivieInformationFromException(...)

This function accepts a piece of data that is deemed sensitive.  It calls the mysterious third-party library and returns a string that is a variant of the original incoming data.  If incoming data is dangerous, outgoing data may also become dangerous as a result of executing this method.  This is a third-party library function that Fortify SCA does not know about.  Hence, the engine cannot recognize that this is a pass-through function and known vulnerabilities may otherwise go undetected.

localizeFinancialInstruments(...)
This function accepts an incoming array of strings and returns an array of strings that are localized versions of the passed-strings.  If incoming data is dangerous, outgoing data may also become dangerous as a result of executing this method.  This is a third-party library function that Fortify SCA does not know about.  Hence, the engine cannot recognize that this is a pass-through function and known vulnerabilities may otherwise go undetected.

sanitizedCreditCardData(...)
This function accepts incoming credit-card data, removes just enough information to make it safe for display, and returns it to the application.  A modified form of the incoming data is returned as an outgoing parameter.

sanitizeUserDataForDisplay(...)
This function passes incoming user profile data, manipulates it within the unrecognized third-party library, and returns it as another array.  Data that is dangerous may enter through one parameter and pass out through the returned parameter.  Fortify SCA needs to know this in order to accurately track the flow of any dangerous data.

-----------------------------------
Unidentified Sanitization Functions
-----------------------------------

Functions that sanitize data aid in eliminating a whole host of common security vulnerabilities related to data validation.  If data is sanitized as it flows from a source to a sink, many different types of vulnerabilities are eliminated.  It is critical that Fortify SCA recognizes sanitization functions in order to correctly eliminate false positives.

removeSensitiveInformationFromException(...)
This function scrubs any sensitive information from an exception before it is written to disc.  It aids in eliminating risks associated with accidental information disclosure, privacy violations, or other types of information leaks.  In this example, the engine does not recognize what this function does because the scrubbing is done by a third-party component that does not include source code that can be examined by Fortify SCA.

removePrivacyData(...)
This function is responsible for removing any data from a given string that is deemed sensitive.  This function is used within the getFinancialInstruments(...) function to retrieve social security numbers.  Before this data is sent to the console (during a debugging session), this function is called to prevent any privacy violations that would be reported by Fortify SCA.  In this case, Fortify SCA does not have access to the underlying source code to the sanitization function.  As such, this gets reported as a false positive.

-------------------------
Incorrect Password Fields
-------------------------

Fortify SCA attempts to find sensitive passwords or variables containing passwords within the source code provided.  It does this based on the variable name.  A variable name may be misleading and not actually contain a password or other sensitive information.

--------
Solution
--------

The goal of this example is to illustrate how the use of Fortify Annotations can result in increased accuracy in the reported vulnerabilities.  Each section below explains how to address the class of problems found.

Step 1 - Annotate All Sources of Data
=====================================
Data is being pulled through an external JAR file that does not contain source code.  Furthermore, Fortify SCA does not have any pre-existing set of rules for this particular third-party JAR.  As such, it is necessary that the user provides useful information to Fortify SCA in order to identify sources of data and find all vulnerabilities.  The list below shows all sources of data in this application that are exposed through the third-party library:

loadUserConfiguration : Source of user configuration information
getSocialSecurityNumber : Source of privacy-related data (Social Security Numbers in this case)
retrieveCreditCardData : Source of PCI-related data;
loadUserProfile : Source of user data being pulled from a database; and
loadFinancialInstruments : Source of financial information about user

If possible, it is best use the annotation that most accurately describes the source of the data.  For instance, loadUserConfiguration is a filesystem source.  If possible, it is also best to use the annotation that most accurately describes the nature of the data.  In this example, getSocialSecurityNumber is a source of privacy-related data while retrieveCreditCardData is a source of PCI-compliant data.  Multiple Java Annotations can be used to describe both the source of the data and the nature of the data.


Step 2 : Annotate All Sinks of Data
===================================


Data is being written to many different targets for subsequent processing.  The actual repository details are abstracted through the use of the third-party JAR.  Fortify SCA does not recognize this particular third-party JAR.  As such, Fortify SCA cannot recognize that data is being written to a target.  It is necessary that the user provides useful information to Fortify SCA in order to identify these targets of data.  The list below shows all the sinks that are being written to through the use of the external JAR:

sendEmergencyBroadcast : data is dumped to a gateway to alert administrators of problems;
logApplicationException : data is dumped to an exception database; and
postInformation : data is dumped to a processing database for HTML processing by the front-end

If possible, it is best to use the annotation that most accurately describes the nature of the data that is being written to the sink.  For instance, a "PCI Sink" is a function that writes PCI-compliant data to a sink.  An "XSS Sink" is a function that writes data that may contain HTML or JavaScript.

Step 3 : Annotate Pass-Through Functions
========================================

Data is being transformed in many different ways throughout this application.  For instance, the function reformatStockData takes an incoming String array of financial information and translates it from a culture-neutral string to a culture-specific string.  This function is hidden within the external JAR.  Its source code is not accessible to Fortify SCA.  As such, Fortify SCA would never be able to know that data is flowing from the incoming parameter to the outgoing parameter.  The user must provide annotations to help Fortify SCA build an accurate model of how data is flowing through the application.  The list below shows all the pass-through functions that need to be modeled in this application:

localizeFinancialInstruments : incoming data passes to an outgoing parameter in an altered format
removeSensitiveInformation : data passes from an incoming to outgoing parameter through the library
removeSensitiveInformationFromException : same as above

It is important to note that this information is only necessary for third-party libraries that are not recognized by Fortify SCA.

Step 4 : Recognize Cleansing Functions
======================================

Functions that are hidden within a third-party library may sanitize information and render it safe for storage or display.  In this case, there are several functions that allow for proper display of credit-card information and storage of privacy-related data.  Below is a list of the functions that would normally go undetected as cleanse functions due to the abstraction through the JAR:

removeSensitiveInformation : returns data that no longer contains privacy-related data;
removeSensitiveInformationFromException : returns an Exception object that with no privacy data
sanitizeCreditCardData : returns credit-card data with all data except last 4 digits crossed out

-----------------------------------------------------
Special Considerations (Beyond Third-Party Libraries)
-----------------------------------------------------

Fortify Annotations can be used on available source code too.  In the example provided, Fortify Annotations are used to describe the behavior of a third-party library.  However, Annotations can also be used to force a particular description of behavior for included source code as well.  This is ideal for situations where there is a false positive or the code is considered "good enough" and will never be fixed.

-------------------------
Eliminate False Positives
-------------------------

The variable PasswordLabel has been mistaken as a source of sensitive data by Fortify SCA.  Clearly, it only contains the display name of the field corresponding to the password input description.  Fortify SCA may report false positives as a result.  Fortify Annotations can be used to force Fortify SCA to recognize that this is not a password.  The FortifyNotPassword annotation does just this and eliminates the corresponding false positive.

-----------------------------
Code That Will Never Be Fixed
-----------------------------

In the example provided, the SanitizeUserDataForDisplay function performs basic HTML escaping and renders HTML harmless when shown on a user's web browser.  It has been decided (within this example) that the associated business risk from the exposed XSS attack is considered small.  As such, this issue never needs to be fixed.  Fortify Annotations can be used on this code to force Fortify SCA to recognize this as a cleanse function that is accurate and complete.  The "FortifyXSSValidate" annotation forces Fortify SCA to pretend that the function completely eliminates this threat.

--------
Glossary
--------

The terms below are used through this document.

False Negatives
---------------

False negatives are vulnerabilities that exist within code that go undetected by the scanner.  Most false negatives result from the use of unrecognized third-party libraries.  Normally, these libraries do not include source-code.  Some may not have been examined previously by Fortify for known security vulnerabilities.  As such, it is reasonable to expect that any security vulnerabilities within these unknown third-party components will go undetected by Fortify without special knowledge.  There are some false negatives that result from the use of a third-party library that does not include source code.


False Positives
---------------

False positives are vulnerabilities that are reported that do not exist.  Due to a bug in Fortify SCA or incomplete source code, the engine reports something that is not a problem.

Third-Party Libraries
---------------------

Third-party libraries are pieces of code that do not expose source code.  Normally, these are proprietary and expose some useful functionality that is reused by the original application.

Data Source
-----------

A data source is a function that is used by an application to retrieve data.  For example, Fortify SCA recognizes .NET's StreamReader.ReadLine(...) function as a source of data because it is used to retrieve data from a Stream object.

Data Sink
---------

A data sink is a function that is used by an application to save or expose data.  For example, Fortify SCA recognizes Java's System.out.println(...) function as a sink of data.  This function accepts a String that is a piece of data.  It eventually exposes this data to the user through a console.

Cleanse Function
----------------

A cleanse function is a function that sanitizes data.  It scrubs the data and renders it safe for processing.  A sample cleanse function removes credit-card data from an incoming String object and returns a "clean" version.  The clean version no longer contains sensitive information and is considered "safe".

Pass-Through Function
---------------------

A pass-through function is a function that has multiple parameters.  One parameter is an incoming parameter that represents data.  An outgoing parameter contains some manipulated version of the incoming parameter.
