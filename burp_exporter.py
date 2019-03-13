import json
import time
from burp import IBurpExtender
from java.io import File
from java.io import PrintWriter

"""
From: https://support.portswigger.net/customer/portal/questions/17198859-bulk-export-of-xml-reporting-from-burp-session-file

How to use:
java -Djava.awt.headless=true -jar /opt/BurpSuitePro/burpsuite_pro.jar --project-file=/path/to/burp/save/file.burp --report /media/sf_no_scan/burp_report.json
"""

def current_timestamp():
    return int(time.time())

class BurpExtender(IBurpExtender):

    def log(self, msg):
        self._stdout.println("[+] %s" % msg)

    def error(self, msg):
        self._stdout.println("[-] %s" % msg)
        self._stderr.println("[-] %s" % msg)

    def history_to_dict(self, history_line):
        request = self._helpers.bytesToString(history_line.getRequest())
        response_bytes = history_line.getResponse()

        # the response may be null if there is a problem with the proxy or server
        if response_bytes is None:
            response = ''
        else:
            response = self._helpers.bytesToString(response_bytes)

        return {
            'request': request,
            'response': response
        }

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # obtain our output and error streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # obtain command line arguments
        args = callbacks.getCommandLineArguments()

        # check if we pass a "--report" agurment for the report filename
        close_after_dump = False
        if '--report' in args:
            filename = args[args.index('--report') + 1]
            close_after_dump = True
        else:
            filename = 'report_%s.json' % (current_timestamp())

        # ask burp the proxy history
        proxy_history = callbacks.getProxyHistory()
        history = map(lambda h: self.history_to_dict(h), proxy_history)

        # open the fimle and save the json dump
        report_fd = open(filename, 'w')
        report_fd.write(json.dumps(history))
        report_fd.close()

        if close_after_dump:
            callbacks.exitSuite(False)
