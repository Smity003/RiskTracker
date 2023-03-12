// Libraries
const Math = require("mathjs");
const coreLib = require("../../core");
// const phpCoreLib = require("./core.js");


// Libraries init
const core = new coreLib();
// const phpCore = new phpCoreLib();

module.exports = function() {
	// Methods
	function checkForInjections(){
		core.println("<-- Checking for Injection Vulnerabilities -->", "green", "bold");
		var num_vulnerabilities_found = 0;
		
		var files = core.getAllFilesPaths(core.config.DEFAULT_PROJECT_PATH_TO_SCAN, [], true, true, ["php"]);
		
		// Prepare OS Commands Array to Check
		var cmds = [];
		cmds.push("system(");
		cmds.push("exec(");
		cmds.push("shell_exec(");
		cmds.push("passthru(");
		cmds.push("popen(");
		cmds.push("proc_open(");
		cmds.push("proc_close(");
		cmds.push("proc_get_status(");
		cmds.push("proc_nice(");
		cmds.push("proc_terminate(");
		
		// LDAP & OS Commands Injection Check
		for(var i = 0; i < files.length; i++){
			//LDAP
			var ldap_search_array = core.findLineInFile("ldap_search(", files[i], true);
			if(ldap_search_array.length > 0){
				if(core.findLineInFile("ldap_escape(", files[i]) == 0){
					num_vulnerabilities_found = num_vulnerabilities_found + ldap_search_array.length;
					}
				else if(core.findLineInFile("LDAP_ESCAPE_FILTER", files[i]) == 0){
					num_vulnerabilities_found = num_vulnerabilities_found + ldap_search_array.length;
				}
			}
			
			//OS Commands
			for(var j = 0; j < cmds.length; j++){
				var cmd_array = core.findLineInFile(cmds[j], files[i], true);
				if(cmd_array.length > 0){
					if(core.findLineInFile("escapeshellcmd(", files[i]) == 0 || core.findLineInFile("escapeshellarg(", files[i]) == 0){
						num_vulnerabilities_found = num_vulnerabilities_found + cmd_array.length;
					}
				}
			}
		}
		
		// Results
		core.showResults(num_vulnerabilities_found, "Injection", " ", true);
		return num_vulnerabilities_found;
	}
	
	function checkForBrokenAuth(){
		core.println("<-- Checking for Broken Authentication Vulnerabilities -->", "green", "bold");
		
		var files = core.getAllFilesPaths(core.config.DEFAULT_PROJECT_PATH_TO_SCAN, [], true, true, ["php"]);
		
		var num_vulnerabilities_found = 0;
		for(var i = 0; i < files.length; i++){
			if(core.findLineInFile("<form", files[i]) > 0 && core.findLineInFile("</form>", files[i]) > 0){
				if((core.findLineInFile("g-recaptcha", files[i]) == 0 || core.findLineInFile("data-sitekey", files[i]) == 0) && (core.findLineInFile("grecaptcha", files[i]) == 0)){
					num_vulnerabilities_found++;
				}
			}
		}
		
		// Results
		core.showResults(num_vulnerabilities_found, "Broken Authentication", " ", true);
		return num_vulnerabilities_found;
	}
	
	function checkForCrossSiteRequestForgery(){
		core.println("<-- Checking for Cross-Site Request Forgery Vulnerabilities -->", "green", "bold");
		
		var files = core.getAllFilesPaths(core.config.DEFAULT_PROJECT_PATH_TO_SCAN, [], true, true, ["php"]);
		
		var num_vulnerabilities_found = 0;
		for(var i = 0; i < files.length; i++){
			if(core.findLineInFile("<form", files[i]) > 0 && core.findLineInFile("</form>", files[i]) > 0){
				if(core.findLineInFile("token", files[i]) == 0 && core.findLineInFile("csrf", files[i]) == 0){
					num_vulnerabilities_found++;
				}
			}
		}

		core.showResults(num_vulnerabilities_found, "Cross SiteRequestForgery ", " ", true);
		return num_vulnerabilities_found;
	}	

	function checkForSecurityMisconfiguration(){
		core.println("<-- Checking for Security Misconfiguration Vulnerabilities -->", "green", "bold");
	
		var num_vulnerabilities_found = 0;
		
		// Checking for Listing Directories
		var htaccessPath = core.config.DEFAULT_PROJECT_PATH_TO_SCAN + ".htaccess";
		
		if(!core.isFileExists(htaccessPath)){
			var folders = core.getAllFilesPaths(core.config.DEFAULT_PROJECT_PATH_TO_SCAN, [], false);
			
			var found = -1;
			for(var i = 0; i < folders.length; i++){
				if(core.isFileExists(folders[i] + ".htaccess")){
					found = i;
					break;
				}
			}
			
			if(found >= 0){
				htaccessPath = folders[i] + ".htaccess";
			}
			else {
				num_vulnerabilities_found++;
			}
		}
		
		if(core.isFileExists(htaccessPath)){
			if(core.findLineInFile("Options -Indexes", htaccessPath) == 0){
				num_vulnerabilities_found++;
			}
		}
		
		// Checking for error handling
		var files = core.getAllFilesPaths(core.config.DEFAULT_PROJECT_PATH_TO_SCAN, [], true, true, ["php"]);
		
		var isErrorReportingFound = false;
		for(var i = 0; i < files.length; i++){
			if(core.findLineInFile("error_reporting(0)", files[i]) > 0 || core.findLineInFile("error_reporting($", files[i]) > 0){
				isErrorReportingFound = true;
				break;
			}
		}
		
		if(!isErrorReportingFound){
			num_vulnerabilities_found++;
		}
		
		// Results
		core.showResults(num_vulnerabilities_found, "Security Misconfiguration", " ", true);
		return num_vulnerabilities_found;
	}
	
	function checkForCrossSiteScripting(){
		core.println("<-- Checking for Cross-Site Scripting Vulnerabilities -->", "green", "bold");
		
		var num_vulnerabilities_found = 0;
	
		var files = core.getAllFilesPaths(core.config.DEFAULT_PROJECT_PATH_TO_SCAN);
		
		for(var i = 0; i < files.length; i++){
			if(core.findLineInFile("$_GET[ ;", files[i]) > 0){
				if(core.findLineInFile("htmlentities( $_GET[ ;", files[i], false, true) == 0 && core.findLineInFile("htmlspecialchars( $_GET[ ;", files[i], false, true) == 0 && core.findLineInFile("->purify( $_GET[ ;", files[i], false, true) == 0 && core.findLineInFile("xss $_GET[ ;", files[i]) == 0){
					num_vulnerabilities_found = num_vulnerabilities_found + core.findLineInFile("$_GET[ ;", files[i], false, true, false, false, "File might have Cross-Site Scripting Vulnerability", "'$_GET' user input can be injected, please make sure to filter or sanitize any $_GET user input from Javascript, HTML and CSS codes input", true);
				}
			}
			
			if(core.findLineInFile("$_POST[ ;", files[i]) > 0){
				if(core.findLineInFile("htmlentities( $_POST[ ;", files[i], false, true) == 0 && core.findLineInFile("htmlspecialchars( $_POST[ ;", files[i], false, true) == 0 && core.findLineInFile("->purify( $_POST[ ;", files[i], false, true) == 0 && core.findLineInFile("xss $_POST[ ;", files[i]) == 0){
					num_vulnerabilities_found = num_vulnerabilities_found + core.findLineInFile("$_POST[ ;", files[i], false, true, false, false, "File might have Cross-Site Scripting Vulnerability", "'$_POST' user input can be injected, please make sure to filter or sanitize any $_POST user input from Javascript, HTML and CSS codes input", true);	
				}
			}
			
			if(core.findLineInFile("$_REQUEST[ ;", files[i]) > 0){
				if(core.findLineInFile("htmlentities( $_REQUEST[ ;", files[i], false, true) == 0 && core.findLineInFile("htmlspecialchars( $_REQUEST[ ;", files[i], false, true) == 0 && core.findLineInFile("->purify( $_REQUEST[ ;", files[i], false, true) == 0 && core.findLineInFile("xss $_REQUEST[ ;", files[i]) == 0){
					num_vulnerabilities_found = num_vulnerabilities_found + core.findLineInFile("$_REQUEST[ ;", files[i], false, true, false, false, "File might have Cross-Site Scripting Vulnerability", "'$_REQUEST' user input can be injected, please make sure to filter or sanitize any $_REQUEST user input from Javascript, HTML and CSS codes input", true);	
				}
			}
			
			num_vulnerabilities_found = num_vulnerabilities_found + core.findLineInFile(".innerHTML", files[i], false, true, false, false, "File might have Cross-Site Scripting Vulnerability", "'.innerHTML' function can be injected, please use '.innerText' instead", true);
			num_vulnerabilities_found = num_vulnerabilities_found + core.findLineInFile("eval(", files[i], false, true, false, false, "File might have Cross-Site Scripting Vulnerability", "'eval()' function can be injected, never use it. needing to use eval() usually indicates a problem in your code design.", true);
		}
		
		// Results
		core.showResults(num_vulnerabilities_found, "Cross-Site Scripting", "", true);
		return num_vulnerabilities_found;
	}
	
	var total_num_vulnerabilities_found = 0;
	
	console.log("");
	console.log("------------------------------");
	console.log("Scanning The file");
	console.log("------------------------------");
	console.log("");
	
	total_num_vulnerabilities_found = total_num_vulnerabilities_found + checkForInjections();
	core.showSpace();
	total_num_vulnerabilities_found = total_num_vulnerabilities_found + checkForBrokenAuth();
	core.showSpace();
	total_num_vulnerabilities_found = total_num_vulnerabilities_found + checkForCrossSiteRequestForgery();
	core.showSpace();
	total_num_vulnerabilities_found = total_num_vulnerabilities_found + checkForSecurityMisconfiguration();
	core.showSpace();
	total_num_vulnerabilities_found = total_num_vulnerabilities_found + checkForCrossSiteScripting();
	core.showSpace();
	
	core.println("Total number of possible vulnerabilities found: " + total_num_vulnerabilities_found, "yellow", "bold");
}