#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from burp import ITab
from burp import IBurpExtender
from burp import IHttpListener
from burp import IContextMenuFactory
from burp import IMessageEditorController
from burp import IHttpRequestResponse
from burp import IHttpRequestResponseWithMarkers
from burp import IHttpService
from burp import ITextEditor
from javax.swing import JList
from javax.swing import JTable
from javax.swing import JFrame
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JToggleButton
from javax.swing import JCheckBox
from javax.swing import JMenuItem
from javax.swing import JTextArea
from javax.swing import JTree
from javax.swing.tree import TreePath
from javax.swing import JPopupMenu
from javax.swing import JSplitPane
from javax.swing import JEditorPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import SwingUtilities
from javax.swing.table import TableRowSorter
from javax.swing.table import AbstractTableModel
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing.tree import DefaultTreeCellRenderer
from javax.swing.tree import DefaultTreeModel
from javax.swing.text.html import HTMLEditorKit
from threading import Lock
from java.io import File
from java.net import URL
from java.net import URLEncoder
from java.awt import Color
from java.awt import Dimension
from java.awt import BorderLayout
from java.awt.event import MouseAdapter
from java.awt.event import ActionListener
from java.awt.event import AdjustmentListener
from java.util import LinkedList
from java.util import ArrayList
from java.lang import Runnable
from java.lang import Integer
from java.lang import String
from java.lang import Math
from thread import start_new_thread
from array import array
import datetime
import re

#
#Initialize BurpExtender API to use Extender features
#

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, IContextMenuFactory, IHttpRequestResponseWithMarkers, ITextEditor):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		#Initialize callbacks to be used later

		self._helpers = callbacks.getHelpers()
		callbacks.setExtensionName("Trishul")
		
		self._log = ArrayList()
		#_log used to store our outputs for a URL, which is retrieved later by the tool

		self._lock = Lock()
		#Lock is used for locking threads while updating logs in order such that no multiple updates happen at once
		
		self.intercept = 0

		self.FOUND = "Found"
		self.CHECK = "Possible! Check Manually"
		self.NOT_FOUND = "Not Found"
		#Static Values for output


		#Initialize GUI
		self.issuesTab()

		self.advisoryReqResp()

		self.configTab()

		self.tabsInit()

		self.definecallbacks()


		print("Thank You for Installing Trishul")

		return

	#
	#Initialize Issues Tab displaying the JTree
	#

	def issuesTab(self):
		self.root = DefaultMutableTreeNode('Issues')

		frame = JFrame("Issues Tree")

		self.tree = JTree(self.root)
		self.rowSelected = ''
		self.tree.addMouseListener(mouseclick(self))
		self.issuepanel = JScrollPane()
		self.issuepanel.setPreferredSize(Dimension(300,450))
		self.issuepanel.getViewport().setView((self.tree))
		frame.add(self.issuepanel,BorderLayout.CENTER)

	#
	#Adding Issues to Issues TreePath
	#
	def addIssues(self, branch, branchData=None):
		if branchData == None:
			branch.add(DefaultMutableTreeNode('No valid data'))
		else:
			for item in branchData:
				branch.add(DefaultMutableTreeNode(item))

	#
	#Initialize the Config Tab to modify tool settings
	#
	def configTab(self):
		Config = JLabel("Config")
		self.startButton = JToggleButton("Intercept Off", actionPerformed=self.startOrStop)
		self.startButton.setBounds(40, 30, 200, 30)

		self.autoScroll = JCheckBox("Auto Scroll")
		self.autoScroll.setBounds(40, 80, 200, 30)

		self.xsscheck = JCheckBox("Detect XSS")
		self.xsscheck.setSelected(True)
		self.xsscheck.setBounds(40, 110, 200, 30)
		
		self.sqlicheck = JCheckBox("Detect SQLi")
		self.sqlicheck.setSelected(True)
		self.sqlicheck.setBounds(40, 140, 200, 30)
		
		self.ssticheck = JCheckBox("Detect SSTI")
		self.ssticheck.setSelected(True)
		self.ssticheck.setBounds(40, 170, 200, 30)

		self.blindxss = JCheckBox("Blind XSS")
		self.blindxss.setBounds(40, 200, 200, 30)

		self.BlindXSSText = JTextArea("", 5, 30)

		scrollbxssText = JScrollPane(self.BlindXSSText)
		scrollbxssText.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
		scrollbxssText.setBounds(40, 250, 400, 110) 

		self.configtab = JPanel()
		self.configtab.setLayout(None)
		self.configtab.setBounds(0, 0, 300, 300)
		self.configtab.add(Config)
		self.configtab.add(self.startButton)
		self.configtab.add(self.autoScroll)
		self.configtab.add(self.xsscheck)
		self.configtab.add(self.sqlicheck)
		self.configtab.add(self.ssticheck)
		self.configtab.add(self.blindxss)
		self.configtab.add(scrollbxssText)

	#
	#Turn Intercept from Proxy on or off
	#
	def startOrStop(self, event):
		if self.startButton.getText() == "Intercept Off":
			self.startButton.setText("Intercept On")
			self.startButton.setSelected(True)
			self.intercept = 1
		else:
			self.startButton.setText("Intercept Off")
			self.startButton.setSelected(False)
			self.intercept = 0

	#
	#Intialize the Advisory, Request and Response Tabs
	#
	def advisoryReqResp(self):
		self.textfield = JEditorPane("text/html", "")
		self.kit = HTMLEditorKit()
		self.textfield.setEditorKit(self.kit)
		self.doc = self.textfield.getDocument()
		self.textfield.setEditable(0)
		self.advisorypanel = JScrollPane()
		self.advisorypanel.getVerticalScrollBar()
		self.advisorypanel.setPreferredSize(Dimension(300,450))
		self.advisorypanel.getViewport().setView((self.textfield))

		self.selectedreq = []

		self._requestViewer = self._callbacks.createMessageEditor(self, False)
		self._responseViewer = self._callbacks.createMessageEditor(self, False)
		self._texteditor = self._callbacks.createTextEditor()
		self._texteditor.setEditable(False)

	#
	#Initialize Trishul Tabs
	#
	def tabsInit(self):
		self.logTable = Table(self)
		tableWidth = self.logTable.getPreferredSize().width
		self.logTable.getColumn("#").setPreferredWidth(Math.round(tableWidth / 50 * 0.1))
		self.logTable.getColumn("Method").setPreferredWidth(Math.round(tableWidth / 50 * 3))
		self.logTable.getColumn("URL").setPreferredWidth(Math.round(tableWidth / 50 * 40))
		self.logTable.getColumn("Parameters").setPreferredWidth(Math.round(tableWidth / 50 * 1))
		self.logTable.getColumn("XSS").setPreferredWidth(Math.round(tableWidth / 50 * 4))
		self.logTable.getColumn("SQLi").setPreferredWidth(Math.round(tableWidth / 50 * 4))
		self.logTable.getColumn("SSTI").setPreferredWidth(Math.round(tableWidth / 50 * 4))
		self.logTable.getColumn("Request Time").setPreferredWidth(Math.round(tableWidth / 50 * 4))

		self.tableSorter = TableRowSorter(self)
		self.logTable.setRowSorter(self.tableSorter)

		self._bottomsplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
		self._bottomsplit.setDividerLocation(500)
		
		self.issuetab = JTabbedPane()
		self.issuetab.addTab("Config",self.configtab)
		self.issuetab.addTab("Issues",self.issuepanel)
		self._bottomsplit.setLeftComponent(self.issuetab)

		self.tabs = JTabbedPane()
		self.tabs.addTab("Advisory",self.advisorypanel)
		self.tabs.addTab("Request", self._requestViewer.getComponent())
		self.tabs.addTab("Response", self._responseViewer.getComponent())
		self.tabs.addTab("Highlighted Response", self._texteditor.getComponent())
		self._bottomsplit.setRightComponent(self.tabs)
		
		self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
		self._splitpane.setDividerLocation(450)
		self._splitpane.setResizeWeight(1)
		self.scrollPane = JScrollPane(self.logTable)
		self._splitpane.setLeftComponent(self.scrollPane)
		self.scrollPane.getVerticalScrollBar().addAdjustmentListener(autoScrollListener(self))
		self._splitpane.setRightComponent(self._bottomsplit)

	#
	#Initialize burp callbacks
	#
	def definecallbacks(self):
		self._callbacks.registerHttpListener(self)
		self._callbacks.customizeUiComponent(self._splitpane)
		self._callbacks.customizeUiComponent(self.logTable)
		self._callbacks.customizeUiComponent(self.scrollPane)
		self._callbacks.customizeUiComponent(self._bottomsplit)
		self._callbacks.registerContextMenuFactory(self)
		self._callbacks.addSuiteTab(self)

	#
	#Menu Item to send Request to Trishul 
	#
	def createMenuItems(self, invocation):
		responses = invocation.getSelectedMessages()
		if responses > 0:
			ret = LinkedList()
			requestMenuItem = JMenuItem("Send request to Trishul")

			for response in responses:
				requestMenuItem.addActionListener(handleMenuItems(self,response, "request")) 
			ret.add(requestMenuItem)
			return ret
		return None

	#
	#Highlighting Response
	#
	def markHttpMessage( self, requestResponse, responseMarkString ):
		responseMarkers = None
		if responseMarkString:
			response = requestResponse.getResponse()
			responseMarkBytes = self._helpers.stringToBytes( responseMarkString )
			start = self._helpers.indexOf( response, responseMarkBytes, False, 0, len( response ) )
			if -1 < start:
				responseMarkers = [ array( 'i',[ start, start + len( responseMarkBytes ) ] ) ]

		requestHighlights = [array( 'i',[ 0, 5 ] )]
		return self._callbacks.applyMarkers( requestResponse, requestHighlights, responseMarkers )
	
	def getTabCaption(self):
		return "Trishul"

	def getUiComponent(self):
		return self._splitpane

	#
	#Table Model to display URL's and results based on the log size
	#
	def getRowCount(self):
		try:
			return self._log.size()
		except:
			return 0

	def getColumnCount(self):
		return 8

	def getColumnName(self, columnIndex):
		data = ['#','Method', 'URL', 'Parameters', 'XSS', 'SQLi', "SSTI", "Request Time"]
		try:
			return data[columnIndex]
		except IndexError:
			return ""

	def getColumnClass(self, columnIndex):
		data = [Integer, String, String, Integer, String, String, String, String]
		try:
			return data[columnIndex]
 		except IndexError:
			return ""

	#Get Data stored in log and display in the respective columns
	def getValueAt(self, rowIndex, columnIndex):
		logEntry = self._log.get(rowIndex)
		if columnIndex == 0:
			return rowIndex+1
		if columnIndex == 1:
			return logEntry._method
		if columnIndex == 2:
			return logEntry._url.toString()
		if columnIndex == 3:
			return len(logEntry._parameter)
		if columnIndex == 4:
			return logEntry._XSSStatus
		if columnIndex == 5:
			return logEntry._SQLiStatus
		if columnIndex == 6:
			return logEntry._SSTIStatus
		if columnIndex == 7:
			return logEntry._req_time
		return ""

	def getHttpService(self):
		return self._currentlyDisplayedItem.getHttpService()

	def getRequest(self):
		return self._currentlyDisplayedItem.getRequest()

	def getResponse(self):
		return self._currentlyDisplayedItem.getResponse()
	
	#For Intercepted requests perform tests in scope
	def processHttpMessage(self, toolFlag, messageIsRequest, messageInf):
		if self.intercept == 1:
			if toolFlag == self._callbacks.TOOL_PROXY:
				if not messageIsRequest:
					requestInfo = self._helpers.analyzeRequest(messageInf)
					requeststr = requestInfo.getUrl()
					parameters = requestInfo.getParameters()
					param_new = [p for p in parameters if p.getType() != 2]
					if len(param_new) != 0:
						if self._callbacks.isInScope(URL(str(requeststr))):
							start_new_thread(self.sendRequestToTrishul,(messageInf,))
		return

	#
	#Main processing of Trishul
	#
	def sendRequestToTrishul(self,messageInfo):
		request = messageInfo.getRequest()
		req_time = datetime.datetime.today()
		requestURL = self._helpers.analyzeRequest(messageInfo).getUrl()
		messageInfo = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(requestURL.getHost()), int(requestURL.getPort()), requestURL.getProtocol() == "https"), request)
		resp_time = datetime.datetime.today()
		time_taken = (resp_time - req_time).total_seconds()
		response = messageInfo.getResponse()
		#initialozations of default value
		SQLiimp = self.NOT_FOUND
		SSTIimp = self.NOT_FOUND
		XSSimp = self.NOT_FOUND
		Comp_req = messageInfo
		requestInfo = self._helpers.analyzeRequest(messageInfo)
		self.content_resp = self._helpers.analyzeResponse(response)
		requestURL = requestInfo.getUrl()
		parameters = requestInfo.getParameters()
		requeststring = self._helpers.bytesToString(request)
		headers = requestInfo.getHeaders()
		#Used to obtain GET, POST and JSON parameters from burp api
		param_new = [p for p in parameters if p.getType() == 0 or p.getType() == 1 or p.getType() == 6]
		i = 0
		xssflag=0
		sqliflag=0
		sstiflag=0
		resultxss = []
		resultsqli = []
		resultssti = []
		xssreqresp = []
		sqlireqresp = []
		sstireqresp = []
		ssti_description = []
		sqli_description = []
		xss_description = []
		for i in range(len(param_new)):
			name =  param_new[i].getName()
			ptype =  param_new[i].getType()
			param_value = param_new[i].getValue()
			#check XSS if ticked
			if self.xsscheck.isSelected():
				score = 0
				flag1 = 0
				XSSimp = self.NOT_FOUND
				payload_array = ["<", ">", "\\\\'asd", "\\\\\"asd", "\\", "'\""]
				json_payload_array = ["<", ">", "\\\\'asd", "\\\"asd", "\\", "\'\\\""]
				payload_all = ""
				json_payload = ""
				rand_str = "testtest"
				for payload in payload_array:
					payload_all = payload_all+rand_str+payload
				payload_all = URLEncoder.encode(payload_all, "UTF-8")
				for payload in json_payload_array:
					json_payload = json_payload+rand_str+payload
				json_payload = URLEncoder.encode(json_payload, "UTF-8")
				if ptype == 0 or ptype == 1:
					new_paramters_value = self._helpers.buildParameter(name, payload_all, ptype)
					updated_request = self._helpers.updateParameter(request, new_paramters_value)
				else:
					jsonreq = re.search(r"\s([{\[].*?[}\]])$", requeststring).group(1)
					new = jsonreq.split(name+"\":",1)[1]
					if new.startswith('\"'):
						newjsonreq = jsonreq.replace(name+"\":\""+param_value,name+"\":\""+json_payload)
					else:
						newjsonreq = jsonreq.replace(name+"\":"+param_value,name+"\":\""+json_payload+"\"")
					updated_request = self._helpers.buildHttpMessage(headers, newjsonreq)

				attack = self.makeRequest(Comp_req, updated_request)
				response = attack.getResponse()
				response_str = self._helpers.bytesToString(response)
				xssreqresp.append(attack)
				if_found_payload = ""
				non_encoded_symbols = ""
				for check_payload in payload_array:
					if_found_payload = rand_str+check_payload
					if if_found_payload in response_str:
						non_encoded_symbols = non_encoded_symbols+"<br>"+check_payload.replace('<', '&lt;')
						score = score+1
						flag1 = 1
				if score > 2: XSSimp = self.CHECK
				if score > 3: XSSimp = self.FOUND
				xssflag = self.checkBetterScore(score,xssflag)
				if non_encoded_symbols == "   \\\\'asd":
					XSSimp = self.NOT_FOUND
				
				if non_encoded_symbols != '':
					xss_description.append("The Payload <b>" + payload_all.replace('<', '&lt;') + "</b> was passed in the request for the paramater <b>" + self._helpers.urlDecode(name) + "</b>. Some Tags were observed in the output unfiltered. A payload can be generated with the observed tags.<br>Symbols not encoded for parameter <b>" + name + "</b>: " + non_encoded_symbols)
				else:
					xss_description.append("")
			else:
				XSSimp = "Disabled"
			resultxss.append(XSSimp)

			if self.sqlicheck.isSelected():
				SQLiimp = self.NOT_FOUND
				score = 0
				value = "%27and%28select%2afrom%28select%28sleep%285%29%29%29a%29--"
				orig_time = datetime.datetime.today()
				if ptype == 0 or ptype == 1:
					new_paramters_value = self._helpers.buildParameter(name, value, ptype)
					updated_request = self._helpers.updateParameter(request, new_paramters_value)
				else:
					jsonreq = re.search(r"\s([{\[].*?[}\]])$", requeststring).group(1)
					new = jsonreq.split(name+"\":",1)[1]
					if new.startswith('\"'):
						newjsonreq = jsonreq.replace(name+"\":\""+param_value,name+"\":\""+value)
					else:
						newjsonreq = jsonreq.replace(name+"\":"+param_value,name+"\":\""+value+"\"")
					updated_request = self._helpers.buildHttpMessage(headers, newjsonreq)
				attack1 = self.makeRequest(Comp_req, updated_request)
				response1 = attack1.getResponse()
				new_time = datetime.datetime.today()
				response_str1 = self._helpers.bytesToString(response1)
				sqlireqresp.append(attack1)
				diff = (new_time - orig_time).total_seconds()
				if (diff - time_taken) > 3:
					score = 4
				
				self.error_array = ["check the manual that corresponds to your", "You have an error", "syntax error", "SQL syntax", "SQL statement", "ERROR:", "Error:", "MySQL","Warning:","mysql_fetch_array()"]
				found_text = ""
				for error in self.error_array:
					if error in response_str1:
						found_text = found_text + error
						score = score + 1
				if score > 1: SQLiimp = self.CHECK
				if score > 2: SQLiimp = self.FOUND
				sqliflag = self.checkBetterScore(score,sqliflag)

				if found_text != '':
					sqli_description.append("The payload <b>"+self._helpers.urlDecode(value)+"</b> was passed in the request for parameter <b>"+self._helpers.urlDecode(name)+"</b>. Some errors were generated in the response which confirms that there is an Error based SQLi. Please check the request and response for this parameter")
				elif (diff - time_taken) > 3:
					sqli_description.append("The payload <b>"+self._helpers.urlDecode(value)+"</b> was passed in the request for parameter <b>"+self._helpers.urlDecode(name)+"</b>. The response was in a delay of <b>"+str(diff)+"</b> seconds as compared to original <b>"+str(time_taken)+"</b> seconds. This indicates that there is a time based SQLi. Please check the request and response for this parameter")
				else:
					sqli_description.append("")
			else:
				SQLiimp = "Disabled"

			resultsqli.append(SQLiimp)

			if self.ssticheck.isSelected():
				score = 0
				SSTIimp = self.NOT_FOUND
				payload_array = ["${123*456}", "<%=123*567%>", "{{123*678}}"]
				json_payload_array = ["$\{123*456\}", "<%=123*567%>", "\{\{123*678\}\}"]
				payload_all = ""
				rand_str = "jjjjjjj"
				json_payload = ""
				for payload in payload_array:
					payload_all = payload_all+rand_str+payload
				for payload in json_payload_array:
					json_payload = json_payload+rand_str+payload
				payload_all = URLEncoder.encode(payload_all, "UTF-8")
				json_payload = URLEncoder.encode(json_payload, "UTF-8")
				if ptype == 0 or ptype == 1:
					new_paramters_value = self._helpers.buildParameter(name, payload_all, ptype)
					updated_request = self._helpers.updateParameter(request, new_paramters_value)
				else:
					jsonreq = re.search(r"\s([{\[].*?[}\]])$", requeststring).group(1)
					new = jsonreq.split(name+"\":",1)[1]
					if new.startswith('\"'):
						newjsonreq = jsonreq.replace(name+"\":\""+param_value,name+"\":\""+json_payload)
					else:
						newjsonreq = jsonreq.replace(name+"\":"+param_value,name+"\":\""+json_payload+"\"")
					updated_request = self._helpers.buildHttpMessage(headers, newjsonreq)
				
				attack = self.makeRequest(Comp_req, updated_request)
				response = attack.getResponse()
				response_str = self._helpers.bytesToString(response)
				self.expected_output = ["56088","69741","83394","3885","777777777777777"]
				for output in self.expected_output:
					if_found_payload = rand_str+output
					if if_found_payload in response_str:
						if output == self.expected_output[0]:
							sstireqresp.append(attack)
							ssti_description.append("Parameter <b>" + self._helpers.urlDecode(name) + "</b> is using <b>Java</b> Template<br>The value <b>" + payload_new + "</b> was passed which gave result as <b>56088</b>")
							score = 2
						if output == self.expected_output[1]:
							sstireqresp.append(attack)
							ssti_description.append("Parameter <b>" + self._helpers.urlDecode(name) + "</b> is using <b>Ruby</b> Template<br>The value <b>" + payload_new + "</b> was passed which gave result as <b>69741</b>")
							score = 2
						if output == self.expected_output[2]:
							payload_new = "{{5*'777'}}"
							json_payload_ssti = "\{\{5*'777'\}\}"
							payload = URLEncoder.encode("{{5*'777'}}", "UTF-8")
							json_ssti = URLEncoder.encode("\{\{5*'777'\}\}", "UTF-8")
							if ptype == 0 or ptype == 1:
								new_paramters = self._helpers.buildParameter(name, payload, ptype)
								ssti_updated_request = self._helpers.updateParameter(request, new_paramters)
							else:
								jsonreq = re.search(r"\s([{\[].*?[}\]])$", requeststring).group(1)
								new = jsonreq.split(name+"\":",1)[1]
								if new.startswith('\"'):
									newjsonreq = jsonreq.replace(name+"\":\""+param_value,name+"\":\""+json_ssti)
								else:
									newjsonreq = jsonreq.replace(name+"\":"+param_value,name+"\":\""+json_ssti+"\"")
								ssti_updated_request = self._helpers.buildHttpMessage(headers, newjsonreq)
							self.ssti_attack = self.makeRequest(Comp_req, ssti_updated_request)
							ssti_response = self.ssti_attack.getResponse()
							ssti_response_str = self._helpers.bytesToString(ssti_response)
							if self.expected_output[3] in ssti_response_str:
								sstireqresp.append(self.ssti_attack)
								ssti_description.append("Parameter <b>" + self._helpers.urlDecode(name) + "</b> is using <b>Twig</b> Template<br>The value <b>" + payload_new + "</b> was passed which gave result as <b>3885</b>")
								score = 2
							elif self.expected_output[4] in ssti_response_str:
								sstireqresp.append(self.ssti_attack)
								self.responseMarkString = "777777777777777"
								ssti_description.append("Parameter <b>" + self._helpers.urlDecode(name) + "</b> is using <b>Jinja2</b> Template<br>The value <b>" + payload_new + "</b> was passed which gave result as <b>777777777777777</b>")
								score = 2
						if score > 0: SSTIimp = self.CHECK
						if score > 1: SSTIimp = self.FOUND
						sstiflag = self.checkBetterScore(score,sstiflag)
			else:
				SSTIimp = "Disabled"

			resultssti.append(SSTIimp)

			if self.blindxss.isSelected():
				blindxss_value = self.BlindXSSText.getText()
				if ptype == 0 or ptype == 1:
					new_paramters_value = self._helpers.buildParameter(name, blindxss_value, ptype)
					updated_request = self._helpers.updateParameter(request, new_paramters_value)
				else:
					jsonreq = re.search(r"\s([{\[].*?[}\]])$", requeststring).group(1)
					new = jsonreq.split(name+"\":",1)[1]
					if new.startswith('\"'):
						newjsonreq = jsonreq.replace(name+"\":\""+param_value,name+"\":\""+blindxss_value)
					else:
						newjsonreq = jsonreq.replace(name+"\":"+param_value,name+"\":\""+blindxss_value+"\"")
					updated_request = self._helpers.buildHttpMessage(headers, newjsonreq)
				attack = self.makeRequest(Comp_req, updated_request)

		if XSSimp != "Disabled":
			if xssflag > 3: XSSimp = self.FOUND
			elif xssflag > 2: XSSimp = self.CHECK
			else: XSSimp = self.NOT_FOUND

		if SSTIimp != "Disabled":
			if sstiflag > 1: SSTIimp = self.FOUND
			elif sstiflag > 0: SSTIimp = self.CHECK
			else: SSTIimp = self.NOT_FOUND

		if SQLiimp != "Disabled":
			if sqliflag > 3: SQLiimp = self.FOUND
			elif sqliflag > 2: SQLiimp = self.CHECK
			else: SQLiimp = self.NOT_FOUND

		self.addToLog(messageInfo, XSSimp, SQLiimp, SSTIimp, param_new, resultxss, resultsqli, resultssti, xssreqresp, sqlireqresp, sstireqresp , xss_description, sqli_description, ssti_description, req_time.strftime('%H:%M:%S %m/%d/%y'))


	#
	#Function used to check if the score originally and mentioned is better
	#
	def checkBetterScore(self, score, ogscore):
		if score > ogscore:
			ogscore = score
		return ogscore


	def makeRequest(self, messageInfo, message):
		request = messageInfo.getRequest()
		requestURL = self._helpers.analyzeRequest(messageInfo).getUrl()
		return self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(requestURL.getHost()), int(requestURL.getPort()), requestURL.getProtocol() == "https"), message)

	
	def addToLog(self, messageInfo, XSSimp, SQLiimp, SSTIimp, parameters, resultxss, resultsqli, resultssti, xssreqresp, sqlireqresp, sstireqresp, xss_description, sqli_description, ssti_description, req_time):
		requestInfo = self._helpers.analyzeRequest(messageInfo)
		method = requestInfo.getMethod()
		self._lock.acquire()
		row = self._log.size()
		self._log.add(LogEntry(self._callbacks.saveBuffersToTempFiles(messageInfo), requestInfo.getUrl(),method,XSSimp,SQLiimp,SSTIimp,req_time, parameters,resultxss, resultsqli, resultssti, xssreqresp, sqlireqresp, sstireqresp, xss_description, sqli_description, ssti_description)) # same requests not include again.
		SwingUtilities.invokeLater(UpdateTableEDT(self,"insert",row,row))
		self._lock.release()

#
# extend JTable to handle cell selection
#
class Table(JTable):

	def __init__(self, extender):
		self._extender = extender
		self.setModel(extender)
		self.addMouseListener(mouseclick(self._extender))
		self.getColumnModel().getColumn(0).setPreferredWidth(0)
		self.setRowSelectionAllowed(True)
		LogEntry = []
		return

	#Set color for cells in tables
	def prepareRenderer(self, renderer, row, col):
		comp = JTable.prepareRenderer(self, renderer, row, col)
		value = self._extender.getValueAt(self._extender.logTable.convertRowIndexToModel(row), col)

		if col == 4 or col == 5 or col == 6:
			if value == self._extender.FOUND:
				comp.setBackground(Color(179, 0, 0))
				comp.setForeground(Color.WHITE)
			elif value == self._extender.CHECK:
				comp.setBackground(Color(255, 153, 51))
				comp.setForeground(Color.BLACK)
			elif value == self._extender.NOT_FOUND:
				comp.setBackground(Color.LIGHT_GRAY)
				comp.setForeground(Color.BLACK)
			elif value == "Disabled":
				comp.setBackground(Color.LIGHT_GRAY)
				comp.setForeground(Color.BLACK)
		else:
			comp.setForeground(Color.BLACK)
			comp.setBackground(Color.LIGHT_GRAY)

		selectedRow = self._extender.logTable.getSelectedRow()
		if selectedRow == row:
			comp.setBackground(Color.WHITE)
			comp.setForeground(Color.BLACK)
		return comp


	#open Issue tab to display vulnerable parameters
	def changeSelection(self, row, col, toggle, extend):
		
		if col >= 0:
			self.performAction(row)
			self._extender.issuetab.setSelectedIndex(1)
			self._extender.tree.expandRow(0)

		if col == 4:
			self._extender.tree.collapseRow(2)
			self._extender.tree.collapseRow(3)
			self._extender.tree.expandRow(1)
	
		if col == 5:
			self._extender.tree.collapseRow(1)
			self._extender.tree.collapseRow(3)
			self._extender.tree.expandRow(2)

		if col == 6:
			self._extender.tree.collapseRow(1)
			self._extender.tree.collapseRow(2)
			self._extender.tree.expandRow(3)

		JTable.changeSelection(self, row, col, toggle, extend)
		return

	#Add parameters to array for every issue found for a particular request
	def performAction(self, row):
		model = self._extender.tree.getModel()
		root = model.getRoot()
		root.removeAllChildren()
		model.reload()
		self.xssroot = DefaultMutableTreeNode('Cross-Site-Scripting')
		root.add(self.xssroot)
		

		self.sqliroot = DefaultMutableTreeNode('SQL Injection')
		root.add(self.sqliroot)

		self.sstiroot = DefaultMutableTreeNode('Server Side Template Injection')
		root.add(self.sstiroot)
		resultxss = []
		resultsqli = []
		resultssti = []
		logEntry = self._extender._log.get(self._extender.logTable.convertRowIndexToModel(row))
		
		resultxss = logEntry._resultxss
		resultsqli = logEntry._resultsqli
		resultssti = logEntry._resultssti
		parameter = logEntry._parameter
		
		for i in range(len(parameter)):
			if resultxss[i] == self._extender.CHECK or resultxss[i] == self._extender.FOUND:
				array = []
				array.append(parameter[i].getName())
				self._extender.addIssues(self.xssroot, array)
			if resultsqli[i] == self._extender.CHECK or resultsqli[i] == self._extender.FOUND:
				array = []
				array.append(parameter[i].getName())
				self._extender.addIssues(self.sqliroot, array)
			if resultssti[i] == self._extender.CHECK or resultssti[i] == self._extender.FOUND:
				array = []
				array.append(parameter[i].getName())
				self._extender.addIssues(self.sstiroot, array)

		self._extender.rowSelected = row

		return

#
#Log to Store Data of Requests
#
class LogEntry:

	def __init__(self, requestResponse, url, method, XSSimp, SQLiimp, SSTIimp, req_time, parameter, resultxss, resultsqli, resultssti, xssreqresp, sqlireqresp, sstireqresp, xss_description, sqli_description, ssti_description):
		self._requestResponse = requestResponse
		self._url = url
		self._method = method
		self._XSSStatus = XSSimp
		self._SQLiStatus = SQLiimp
		self._SSTIStatus = SSTIimp
		self._req_time = req_time
		self._parameter = parameter
		self._resultxss = resultxss
		self._resultsqli = resultsqli
		self._resultssti = resultssti
		self._xssreqresp = xssreqresp
		self._sqlireqresp = sqlireqresp
		self._sstireqresp = sstireqresp
		self._ssti_description = ssti_description
		self._xss_description = xss_description
		self._sqli_description = sqli_description
		return

#
#Mouse Adapter to click on Table and Tree to display data
#
class mouseclick(MouseAdapter):

	def __init__(self, extender):
		self._extender = extender

	def mouseReleased(self, evt):
		if evt.button == 3:
			self._extender.menu.show(evt.getComponent(), evt.getX(), evt.getY())
		self.path = self._extender.tree.getLastSelectedPathComponent()
		if self.path != None:
			row = self._extender.rowSelected
			logEntry = self._extender._log.get(self._extender.logTable.convertRowIndexToModel(row))
			parameter = logEntry._parameter
			xssreqresp = logEntry._xssreqresp
			sqlireqresp = logEntry._sqlireqresp
			sstireqresp = logEntry._sstireqresp
			xss_description = logEntry._xss_description
			sqli_description = logEntry._sqli_description
			ssti_description = logEntry._ssti_description
			url = logEntry._url.toString()
			for i in range(len(parameter)):
				if str(self.path.getParent()) == "Server Side Template Injection":
					if str(self.path) == parameter[i].getName():
						self._extender.textfield.setText("")
						response = sstireqresp[i].getResponse()
						confidence = self.checkConfidence(logEntry._resultssti[i])
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<h1>"+str(self.path.getParent())+"</h1>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><table cellspacing=\"1\" cellpadding=\"0\"><tr><td>Issue:</td> <td><b>"+str(self.path.getParent())+"<b></td></tr><tr><td>Severity:</td> <td><b>High<b></td></tr><tr><td>Confidence:</td> <td>"+confidence+"</td></tr><tr><td>URL:</td> <td><b>"+url+"</b><td></tr></table>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br style=\"margin:0px\"><h3>Description</h3>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "The Parameter <b>" + self._extender._helpers.urlDecode(str(self.path)) + "</b> is Vulnerable to <b>" + str(self.path.getParent()) + "</b>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), ssti_description[i], 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "Usually Mass Emailers use common templated like Smarty, Mako, Twig, and Jinja2 to send emails because it makes it easy to replace values when sending multiple mails. Also, Web applications commonly use these template engines to present dynamic data on web pages and emails. Examples include wikis, blogs, content management systems, and marketing applications. This feature allows embedding user input into the web application, and if not sanitized properly, could make it vulnerable to Server-Side Template Injection and potentially give remote code execution (RCE) capability to intruders.", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><h3>Remediation</h3>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "Remediations are different for different types of Templates, but the following concepts could help remediate all template engines.<br> 1.<b>Sanitization:</b> Always pass user inputs into templates as parameters. Always Sanitize the input before passing it into the template removing various malicious characters before parsing the data. Thus without specific characters inserted on the page, the malicious code will not execute.<br> 2.<b>Sandboxing:</b> If your business restricts sanitizing characters, it is advisable to put the template in a sandboxeed environment like a docker container. So with the help of docker security you can craft a secure environment for these malicious activities.", 0, 0, None)
						self._extender.textfield.setCaretPosition(0)
						self._extender.selectedreq = sstireqresp[i]
						self._extender._requestViewer.setMessage(sstireqresp[i].getRequest(), True)
 						self._extender._responseViewer.setMessage(sstireqresp[i].getResponse(), False)
 						self._extender._currentlyDisplayedItem = sstireqresp[i]
 						self._extender._texteditor.setText(sstireqresp[i].getResponse())
 						response_str = self._extender._helpers.bytesToString(response)
						for ssti_out in self._extender.expected_output:
							if ssti_out in response_str:
								self._extender._texteditor.setSearchExpression(ssti_out)
								break
 						
 				elif str(self.path.getParent()) == "Cross-Site-Scripting":
 					if str(self.path) == parameter[i].getName():
 						self._extender.textfield.setText("")
 						response = xssreqresp[i].getResponse()
 						content_resp = self._extender._helpers.analyzeResponse(response)
						if content_resp.getStatedMimeType() == "HTML":
							confidence = self.checkConfidence(logEntry._resultxss[i])
						else:
							confidence = "<b style=\"color: orange;\">Tentative (Non HTML Output)</b>"
 						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<h1>"+str(self.path.getParent())+"</h1>", 0, 0, None)
 						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><table cellspacing=\"1\" cellpadding=\"0\"><tr><td>Issue:</td> <td><b>"+str(self.path.getParent())+"<b></td></tr><tr><td>Severity:</td> <td><b>High<b></td></tr><tr><td>Confidence:</td> <td>"+confidence+"</td></tr><tr><td>URL:</td> <td><b>"+url+"</b><td></tr></table>", 0, 0, None)
 						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br style=\"margin:0px\"><h3>Description</h3>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "The Parameter <b>" + self._extender._helpers.urlDecode(str(self.path)) + "</b> is Vulnerable to <b>" + str(self.path.getParent()) + "</b>", 0, 0, None)
 						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), xss_description[i], 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "Cross-site scripting vulnerabilities arise when data is copied from a request and echoed into the application's response in an unsafe way. An attacker can use the vulnerability to construct a request that, if issued by another application user, will cause JavaScript code supplied by the attacker to execute within the user's browser in the context of that user's session with the application.<br><br>The attacker-supplied code can perform a wide variety of actions, such as stealing the victim's session token or login credentials, performing arbitrary actions on the victim's behalf, and logging their keystrokes.<br><br>Users can be induced to issue the attacker's crafted request in various ways. For example, the attacker can send a victim a link containing a malicious URL in an email or instant message. They can submit the link to popular web sites that allow content authoring, for example in blog comments. And they can create an innocuous looking web site that causes anyone viewing it to make arbitrary cross-domain requests to the vulnerable application (using either the GET or the POST method).<br><br>The security impact of cross-site scripting vulnerabilities is dependent upon the nature of the vulnerable application, the kinds of data and functionality that it contains, and the other applications that belong to the same domain and organization. If the application is used only to display non-sensitive public content, with no authentication or access control functionality, then a cross-site scripting flaw may be considered low risk. However, if the same application resides on a domain that can access cookies for other more security-critical applications, then the vulnerability could be used to attack those other applications, and so may be considered high risk. Similarly, if the organization that owns the application is a likely target for phishing attacks, then the vulnerability could be leveraged to lend credibility to such attacks, by injecting Trojan functionality into the vulnerable application and exploiting users' trust in the organization in order to capture credentials for other applications that it owns. In many kinds of application, such as those providing online banking functionality, cross-site scripting should always be considered high risk.", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><h3>Remediation</h3>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "In most situations where user-controllable data is copied into application responses, cross-site scripting attacks can be prevented using two layers of defenses:<br><br>1. Input should be validated as strictly as possible on arrival, given the kind of content that it is expected to contain. For example, personal names should consist of alphabetical and a small range of typographical characters, and be relatively short; a year of birth should consist of exactly four numerals; email addresses should match a well-defined regular expression. Input which fails the validation should be rejected, not sanitized.<br>2. User input should be HTML-encoded at any point where it is copied into application responses. All HTML metacharacters, including < > \" \' and =, should be replaced with the corresponding HTML entities (&lt; &gt; etc).<br><br>In cases where the application\'s functionality allows users to author content using a restricted subset of HTML tags and attributes (for example, blog comments which allow limited formatting and linking), it is necessary to parse the supplied HTML to validate that it does not use any dangerous syntax; this is a non-trivial task.", 0, 0, None)
 						self._extender.textfield.setCaretPosition(0)
 						self._extender.selectedreq = xssreqresp[i]
 						self._extender.markHttpMessage(xssreqresp[i], "testtest")
						self._extender._requestViewer.setMessage(xssreqresp[i].getRequest(), True)
 						self._extender._responseViewer.setMessage(xssreqresp[i].getResponse(), False)
 						self._extender._currentlyDisplayedItem = xssreqresp[i]
 						self._extender._texteditor.setText(xssreqresp[i].getResponse())
 						self._extender._texteditor.setSearchExpression("testtest")
 				elif str(self.path.getParent()) == "SQL Injection":
 					if str(self.path) == parameter[i].getName():
 						self._extender.textfield.setText("")
 						confidence = self.checkConfidence(logEntry._resultsqli[i])
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<h1>"+str(self.path.getParent())+"</h1>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><table cellspacing=\"1\" cellpadding=\"0\"><tr><td>Issue:</td> <td><b>"+str(self.path.getParent())+"<b></td></tr><tr><td>Severity:</td> <td><b>High<b></td></tr><tr><td>Confidence:</td> <td>"+confidence+"</td></tr><tr><td>URL:</td> <td><b>"+url+"</b><td></tr></table>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br style=\"margin:0px\"><h3>Description</h3>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "The Parameter <b>" + self._extender._helpers.urlDecode(str(self.path)) + "</b> is Vulnerable to <b>" + str(self.path.getParent()) + "</b>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), sqli_description[i], 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries in an unsafe manner. An attacker can supply crafted input to break out of the data context in which their input appears and interfere with the structure of the surrounding query.<br>A wide range of damaging attacks can often be delivered via SQL injection, including reading or modifying critical application data, interfering with application logic, escalating privileges within the database and taking control of the database server.", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "<br><h3>Remediation</h3>", 0, 0, None)
						self._extender.kit.insertHTML(self._extender.doc, self._extender.doc.getLength(), "The most effective way to prevent SQL injection attacks is to use parameterized queries (also known as prepared statements) for all database access. This method uses two steps to incorporate potentially tainted data into SQL queries: first, the application specifies the structure of the query, leaving placeholders for each item of user input; second, the application specifies the contents of each placeholder. Because the structure of the query has already been defined in the first step, it is not possible for malformed data in the second step to interfere with the query structure. You should review the documentation for your database and application platform to determine the appropriate APIs which you can use to perform parameterized queries. It is strongly recommended that you parameterize every variable data item that is incorporated into database queries, even if it is not obviously tainted, to prevent oversights occurring and avoid vulnerabilities being introduced by changes elsewhere within the code base of the application.<br>You should be aware that some commonly employed and recommended mitigations for SQL injection vulnerabilities are not always effective:<br><br>1. One common defense is to double up any single quotation marks appearing within user input before incorporating that input into a SQL query. This defense is designed to prevent malformed data from terminating the string into which it is inserted. However, if the data being incorporated into queries is numeric, then the defense may fail, because numeric data may not be encapsulated within quotes, in which case only a space is required to break out of the data context and interfere with the query. Further, in second-order SQL injection attacks, data that has been safely escaped when initially inserted into the database is subsequently read from the database and then passed back to it again. Quotation marks that have been doubled up initially will return to their original form when the data is reused, allowing the defense to be bypassed.<br>2. Another often cited defense is to use stored procedures for database access. While stored procedures can provide security benefits, they are not guaranteed to prevent SQL injection attacks. The same kinds of vulnerabilities that arise within standard dynamic SQL queries can arise if any SQL is dynamically constructed within stored procedures. Further, even if the procedure is sound, SQL injection can arise if the procedure is invoked in an unsafe manner using user-controllable data.", 0, 0, None)
						self._extender.textfield.setCaretPosition(0)
						self._extender.selectedreq = sqlireqresp[i]
						response = sqlireqresp[i].getResponse()
						self._extender._requestViewer.setMessage(sqlireqresp[i].getRequest(), True)
 						self._extender._responseViewer.setMessage(sqlireqresp[i].getResponse(), False)
 						self._extender._currentlyDisplayedItem = sqlireqresp[i]
 						self._extender._texteditor.setText(response)
						response_str = self._extender._helpers.bytesToString(response)
						for error in self._extender.error_array:
							if error in response_str:
								self._extender._texteditor.setSearchExpression(error)
								break
							else:
								pass

	#Color of Confidence in Description
 	def checkConfidence(self, value):
 		if value == self._extender.FOUND:
 			return "<b style=\"color:red;\">Firm</b>"
 		elif value == self._extender.CHECK:
 			return "<b style=\"color:orange;\">Tentative</b>"

#
#Autoscroll enabling feature
#
class autoScrollListener(AdjustmentListener):
	def __init__(self, extender):
		self._extender = extender

	def adjustmentValueChanged(self, e):
		if self._extender.autoScroll.isSelected() is True:
			e.getAdjustable().setValue(e.getAdjustable().getMaximum())

#
#Menu Iten Added on Right Click which sends request to Trishul
#
class handleMenuItems(ActionListener):
	def __init__(self, extender, messageInfo, menuName):
		self._extender = extender
		self._menuName = menuName
		self._messageInfo = messageInfo

	def actionPerformed(self, e):
		start_new_thread(self._extender.sendRequestToTrishul,(self._messageInfo,))

#
#Function to insert request details into the table
#
class UpdateTableEDT(Runnable):
    def __init__(self,extender,action,firstRow,lastRow):
        self._extender=extender
        self._action=action
        self._firstRow=firstRow
        self._lastRow=lastRow

    def run(self):
        if self._action == "insert":
            self._extender.fireTableRowsInserted(self._firstRow, self._lastRow)
        elif self._action == "update":
            self._extender.fireTableRowsUpdated(self._firstRow, self._lastRow)
        elif self._action == "delete":
            self._extender.fireTableRowsDeleted(self._firstRow, self._lastRow)
        else:
            print("Invalid action in UpdateTableEDT")
