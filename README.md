<h1 align="center">
  <br>
  <a href="https://github.com/gauravnarwani97/Trishul"><img src="https://i.ibb.co/XtMBbBv/logo.png" alt="Trishul" width="200" height="171"></a>
</h1>

<h4 align="center">Burp Extension for Automated Vulnerability Discovery</h4>

![alt text](https://raw.githubusercontent.com/gauravnarwani97/Trishul/master/trishul_main_picture.png "Trishul Main")

# Trishul
Trishul is an automated vulnerability finding Burp Extension. Built with Jython supports real-time vulnerability detection in multiple requests with user-friendly output. This tool was made to supplement testing where results have to be found in a limited amount of time. Currently, the tool supports finding of Cross-Site Scripting, SQL Injections and Server-Side Template Injections. More vulnerabilities would be added in the later versions.

## Installation
1. Download and Install Burp Suite: http://portswigger.net/burp/download.html
2. Download Jython standalone JAR: http://www.jython.org/download.html
3. Open Extender Tab in Burp. Go to Options. Under Python Environment, you have to update the location of Jython Standalone JAR you just downloaded. Click on Select File and Choose the downloaded Jython jar file.
4. Download the trishul.py file from this repository.
5. Open Extender Tab under Extender and Click on Add under Burp Extensions. Choose Extension Type as Python and give the location of trishul.py file. Click on Next.
6. Once the Extension is done installing, you will see a Tab added to your Burp with the Name “Trishul”. Click on the Tab and enjoy automatic vulnerability detection.

Note: All demonstration shown on this tool has been done on the website http://testphp.vulnweb.com.

## Usage
To detect vulnerabilities in requests, the requests are provided via the two ways:
1. Send each request manually to Trishul
2. Automatically test for all requests in a scope added Website
Each of the following ways will be explained in more detail in the following paragraphs.

### Usage #1:
While Installing Trishul, we add another item in our drop-down menu while using Right-Click on various requests. Once you Right-Click any request in Proxy/Target/Repeater, you will find an option “Send a request to Trishul”. With this option, you can send any request to Trishul that you want to test.
![alt text](https://raw.githubusercontent.com/gauravnarwani97/Trishul/master/trishul_send_req.png "send_req_to_trishul")

### Usage #2:
Add the website to be tested in scope and Turn Intercept on in Trishul to test all requests flowing to the website in scope.
![alt text](https://raw.githubusercontent.com/gauravnarwani97/Trishul/master/trishul_add_website_scope.png "show_scope")

Once the website is added to Scope. Head over to Trishul and Turn Intercept On to capture all the requests flowing to the inscoped Website.

![alt text](https://raw.githubusercontent.com/gauravnarwani97/Trishul/master/Trishul_intercept_working_gif.gif "intercept_video")

## Configurations
There are a couple of configurations available for a user to use Trishul. To view these configurations, head over to Trishul and view the config tab in the bottom left of the pane. Here is the List of Options Available:
1. Intercept Button: With Intercept Button set to On, the tool will perform a test on all requests flowing to the website added in Scope. This button is restricted to scope as it is not feasible to test all the requests flowing to Burp from multiple domains. This would affect the performance.
2. Auto-Scroll: With Auto-Scroll checked, the tool will scroll automatically to the last tested request. This option is feasible when testing a huge domain with Intercept turned on such that scrolling shouldn’t be a tough job.
3. Detect XSS, SQLi, SSTI – These checkboxes are added if any user wants to only test for a specific vulnerability and want to omit other test cases. Used to obtain much faster results for a specific request.
4. Blind XSS: This textbox is added for users who want to append their Blind XSS Payload for every parameter in a request. To use this, enter your Blind XSS payload (singular) in the text box and click on the Blind XSS Checkbox. Now, for every request passing through Trishul, the value of all parameters in the request would be replaced with the Blind XSS payload.

## Interpreting Results
For every result, Trishul displays one of the three options for each of the vulnerability tested:
+	Found: The vulnerability was successfully detected for the Request parameters.
+	Not Found: The vulnerability was not present in the Request parameters.
+	Possible! Check Manually: The vulnerability maybe present. The tester has to reconfirm the finding.

The test for these vulnerabilities depends on the parameters in the request. If the request has no parameters, Trishul would not process this request and would show Not Found in all of the vulnerabilities.

If any of the Found/Possible! Check Manually is been seen under the vulnerability class for the specific request, the user has to click the result to see the vulnerable parameter displayed under the Vulnerability class in Issues Tab in the bottom left.

The user then has to select the parameter displayed under the Vulnerability class and the description for that parameter would be shown to him. The user can then view the Request and Response which was sent from Trishul to determine the vulnerability.

On Clicking the Highlighted Response Tab, you will be shown the highlighted text for some of the vulnerability class. For Example: Payload reflection for Cross-Site Scripting or Error Based SQLi text shown in response. The Highlighted Response tab was added as there was no option in Burp API to highlight the response text in Burp’s MessageEditor Tab.

![alt text](https://raw.githubusercontent.com/gauravnarwani97/Trishul/master/trishul_usage.gif "Trishul Usage Video")


## Authors
Gaurav Narwani @gauravnarwani97
